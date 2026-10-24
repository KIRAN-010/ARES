import base64
import hashlib
import math
import re
import socket
import time
from collections import Counter
import httpx
import networkx as nx
import psutil


def bounded_get(url, client_factory=httpx.Client):
    with client_factory(timeout=httpx.Timeout(5), follow_redirects=False, trust_env=False) as client:
        with client.stream("GET", url, headers={"User-Agent": "MJ-Authorized-Lab-Assessment/0.1", "Accept-Encoding": "identity"}) as response:
            if response.headers.get("content-encoding", "identity").lower() != "identity":
                raise ValueError("Compressed responses are not accepted by the bounded evidence collector")
            digest = hashlib.sha256()
            length = 0
            truncated = False
            deadline = time.monotonic() + 10
            for chunk in response.iter_raw():
                if time.monotonic() > deadline:
                    raise TimeoutError("Response exceeded evidence collection time budget")
                remaining = 65536 - length
                digest.update(chunk[:remaining])
                length += min(len(chunk), remaining)
                if len(chunk) > remaining or length == 65536:
                    truncated = True
                    break
            # Never retain cookies, authorization tokens or page contents.
            allowed = {"content-type", "content-security-policy", "x-content-type-options", "x-frame-options",
                       "strict-transport-security", "access-control-allow-origin", "server"}
            return {"url": url, "status": response.status_code,
                    "headers": {k: v[:1000] for k, v in response.headers.items() if k in allowed},
                    "body_sha256": digest.hexdigest(), "bytes_hashed": length, "truncated": truncated,
                    "redirect_not_followed": response.is_redirect}


def web_assess(target, policy):
    if target["kind"] != "web":
        raise ValueError("Web assessment requires a web target")
    evidence = bounded_get(policy.url(target))
    findings = []
    headers = evidence["headers"]
    # These are observed configuration facts, not claims of exploitable XSS or account takeover.
    for header, title in [("content-security-policy", "Content Security Policy absent"),
                          ("x-content-type-options", "MIME sniffing protection absent")]:
        if header not in headers and evidence["status"] == 200:
            findings.append({"code": "MISSING_" + header.upper().replace("-", "_"), "title": title,
                             "severity": "low", "classification": "configuration_observation",
                             "verified": True, "impact": "Defense-in-depth gap; exploitability has not been established"})
    if headers.get("access-control-allow-origin") == "*":
        findings.append({"code": "CORS_WILDCARD", "title": "Wildcard cross-origin read policy observed",
                         "severity": "info", "classification": "configuration_observation", "verified": True,
                         "impact": "May be intentional for public data; sensitive data exposure is not proven"})
    return {"evidence": evidence, "findings": findings}


def network_probe(target, policy):
    policy.check(target)
    results = []
    for port in target["ports"]:
        try:
            with socket.create_connection((target["address"], port), timeout=0.5):
                results.append({"port": port, "state": "open"})
        except (OSError, TimeoutError):
            results.append({"port": port, "state": "closed_or_filtered"})
    return {"services": results, "note": "TCP connect only; open ports are not vulnerabilities"}


def api_authz(target, policy):
    """Known-owner, two-identity read test ONLY against the synthetic bundled lab."""
    policy.check(target)
    if not policy.is_demo(target):
        raise PermissionError("Authorization validator requires the bundled synthetic lab")
    observations = []
    records = []
    with httpx.Client(timeout=5, follow_redirects=False, trust_env=False) as client:
        for actor, owner in [("bob", "bob"), ("alice", "alice"), ("alice", "bob")]:
            url = policy.url(target, path="/api/records/" + owner)
            with client.stream("GET", url, headers={"Authorization": "Bearer mj-lab-" + actor,
                                                    "Accept-Encoding": "identity"}) as response:
                raw = bytearray()
                deadline = time.monotonic() + 10
                if response.headers.get("content-encoding", "identity").lower() != "identity":
                    raise ValueError("Compressed fixture responses are not accepted")
                for chunk in response.iter_raw():
                    if time.monotonic() > deadline:
                        raise TimeoutError("Fixture response exceeded collection time budget")
                    raw.extend(chunk)
                    if len(raw) > 8192:
                        raise ValueError("Fixture API response exceeds bound")
                try:
                    import json
                    value = json.loads(raw)
                except ValueError:
                    value = {}
                if not isinstance(value, dict):
                    value = {}
                records.append(value)
                observations.append({"actor": actor, "requested_owner": owner, "status": response.status_code,
                                     "body_sha256": hashlib.sha256(raw).hexdigest(),
                                     "synthetic_fixture": value.get("fixture") == "mj-synthetic-record-v1"})
    confirmed = (all(o["status"] == 200 and o["synthetic_fixture"] for o in observations)
                 and records[0].get("owner") == "bob" and records[1].get("owner") == "alice"
                 and records[0] == records[2])
    baseline_valid = (observations[0]["status"] == 200 and observations[1]["status"] == 200
                      and observations[0]["synthetic_fixture"] and observations[1]["synthetic_fixture"])
    return {"evidence": {"checks": observations, "fixture_only": True},
            "cross_user_read_confirmed": confirmed,
            "access_control_verified": baseline_valid and observations[2]["status"] == 403,
            "findings": [{"code": "LAB_BOLA", "title": "Cross-user record read reproduced in synthetic lab",
                          "severity": "high", "classification": "confirmed_fixture_vulnerability", "verified": True,
                          "impact": "Alice retrieved Bob's synthetic record; Bob's legitimate baseline matched exactly"}] if confirmed else []}


def host_inventory(target, policy):
    policy.check(target)
    if target["kind"] != "host":
        raise ValueError("Host inventory requires an explicitly registered local host target")
    processes = []
    for process in psutil.process_iter(["pid", "name", "username"]):
        try:
            processes.append(process.info)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
        if len(processes) >= 250:
            break
    return {"processes": processes, "memory_percent": psutil.virtual_memory().percent,
            "note": "Read-only inventory, capped at 250 processes; no command lines or environment secrets"}


def analyze_events(target, store):
    events = [e for e in store.list("event", 5000) if e["target_id"] == target["id"]][:100]
    suspicious = [e for e in events if e["indicators"]]
    rule_ids = {i["rule"] for e in suspicious for i in e["indicators"]}
    correlations = []
    if {"TEMP_EXECUTABLE", "PERSISTENCE_CHANGE"}.issubset(rule_ids):
        correlations.append({"title": "Temporary executable and persistence indicators on the same target",
                             "classification": "triage_hypothesis", "confirmed_malware": False})
    return {"events_checked": len(events), "suspicious_event_ids": [e["id"] for e in suspicious],
            "correlations": correlations, "note": "Reported indicators require analyst validation"}


def attack_graph(target, store):
    graph = nx.DiGraph()
    graph.add_node(target["id"], label=target["name"], kind="asset")
    for finding in store.list("finding"):
        if finding["target_id"] != target["id"]:
            continue
        graph.add_node(finding["id"], label=finding["title"], kind="observation")
        graph.add_edge(target["id"], finding["id"], relation="observed_on", confirmed=True)
        if finding["severity"] in {"high", "critical"}:
            consequence = "hypothesis-" + finding["id"]
            graph.add_node(consequence, label="Potential impact: requires controlled validation", kind="hypothesis")
            graph.add_edge(finding["id"], consequence, relation="could_enable", confirmed=False)
    return {"nodes": [{"id": n, **data} for n, data in graph.nodes(data=True)],
            "edges": [{"source": a, "target": b, **data} for a, b, data in graph.edges(data=True)],
            "note": "Evidence relationship graph; hypothetical edges are not demonstrated attack paths"}


def analyze_sample(name, encoded):
    try:
        content = base64.b64decode(encoded, validate=True)
    except ValueError as exc:
        raise ValueError("Invalid base64 sample") from exc
    if len(content) > 1024 * 1024:
        raise ValueError("Static sample limit is 1 MiB")
    counts = Counter(content)
    entropy = -sum((n / len(content)) * math.log2(n / len(content)) for n in counts.values()) if content else 0
    indicators = []
    for marker, label in [(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE", "EICAR test marker (not malware)"),
                          (b"/etc/cron", "Persistence-related path string"),
                          (b"powershell", "PowerShell string"), (b"/bin/sh", "Shell path string")]:
        if marker.lower() in content.lower():
            indicators.append(label)
    return {"name": name, "sha256": hashlib.sha256(content).hexdigest(), "size": len(content),
            "entropy": round(entropy, 4), "format": "ELF" if content.startswith(b"\x7fELF") else ("PE-like" if content.startswith(b"MZ") else "other"),
            "printable_string_count": len(re.findall(rb"[ -~]{6,}", content)), "indicators": indicators,
            "classification": "static_triage_only", "executed": False,
            "note": "Strings and entropy do not establish maliciousness. Bytes are not saved or executed."}
