import hashlib
import shutil
import subprocess
import threading
from datetime import datetime, timezone, timedelta
from mj.lab import read_config, write_config
from mj.store import canonical
from mj.tools import bounded_get, api_authz


class Recovery:
    def __init__(self, store, policy, settings):
        self.store, self.policy, self.settings = store, policy, settings
        self.lock = threading.RLock()
        self.config = settings.data_dir / "lab-config.json"

    def vbox(self, *args):
        if not self.settings.enable_vm:
            raise PermissionError("VirtualBox adapter disabled; set MJ_ENABLE_VM=1 after lab isolation")
        executable = shutil.which("VBoxManage")
        if not executable:
            raise ValueError("VBoxManage is not installed")
        result = subprocess.run([executable, *args], capture_output=True, text=True, timeout=45, check=False)
        if result.returncode:
            raise ValueError("VirtualBox operation failed: " + result.stderr[:500])
        return result.stdout

    def vm_state(self, target):
        self.policy.check(target)
        if target["kind"] != "vm" or target.get("vm_id") not in self.settings.vm_allowlist:
            raise PermissionError("VM is not allowlisted")
        raw = self.vbox("showvminfo", target["vm_id"], "--machinereadable")
        pairs = {}
        for line in raw.splitlines():
            key, sep, value = line.partition("=")
            if sep:
                pairs[key] = value.strip('"')
        return {k: v for k, v in pairs.items() if k in {"VMState", "CurrentSnapshotUUID"}
                or k.startswith("cableconnected") or (k.startswith("nic") and k[3:].isdigit())}

    def precondition(self, action, target):
        self.policy.check(target)
        if action.startswith("lab_"):
            if not self.policy.is_demo(target):
                raise PermissionError("Configuration writes are restricted to MJ's bundled demonstration workload")
            return read_config(self.config)
        return self.vm_state(target)

    def previous(self, target_id, action):
        for record in self.store.list("recovery", 100000):
            if record["target_id"] == target_id and record["action"] == action and record["status"] == "verified":
                return record
        raise ValueError("No verified earlier operation available to reverse")

    def propose(self, target, action, reason, job_id=None):
        with self.lock:
            if any(r["target_id"] == target["id"] and r["status"] in {"pending", "executing"}
                   for r in self.store.list("recovery", 100000)):
                raise ValueError("This target already has an outstanding recovery proposal")
            before = self.precondition(action, target)
            desired = None
            if action == "lab_harden":
                if before["hardened"]:
                    raise ValueError("Demonstration workload is already hardened")
                desired = {"hardened": True}
            elif action == "lab_restore":
                desired = self.previous(target["id"], "lab_harden")["before"]
            elif action == "vm_quarantine":
                if before.get("VMState") != "running":
                    raise ValueError("Network quarantine requires a running VM")
                if not any(k.startswith("cableconnected") and v == "on" for k, v in before.items()):
                    raise ValueError("VM has no connected adapter")
            elif action == "vm_reconnect":
                desired = self.previous(target["id"], "vm_quarantine")["before"]
                if before.get("VMState") != "running":
                    raise ValueError("Reconnect requires a running VM")
            elif action == "vm_restore":
                if before.get("VMState") != "poweroff" or not target.get("snapshot_id"):
                    raise ValueError("Snapshot restore requires a powered-off VM and registered clean snapshot UUID")
            else:
                raise ValueError("Unsupported recovery action")
            return self.store.add("recovery", {
                "target_id": target["id"], "action": action, "reason": reason, "job_id": job_id,
                "status": "pending", "before": before, "desired": desired,
                "target_fingerprint": hashlib.sha256(canonical(target).encode()).hexdigest(),
                "expires": (datetime.now(timezone.utc) + timedelta(minutes=15)).isoformat(),
                "risk": "Snapshot restore discards changes since the snapshot" if action == "vm_restore"
                        else "Changes workload configuration or connectivity; review before approving",
                "verification_scope": "Configuration and service response" if action.startswith("lab_")
                                      else "VirtualBox state only; application health requires separate assessment",
                "evidence_event_ids": [e["id"] for e in self.store.list("event") if e["target_id"] == target["id"]][:100],
            })

    def _network(self, target, state, disconnect=False):
        for i in range(1, 9):
            key = f"cableconnected{i}"
            if key in state and state.get(f"nic{i}", "none") != "none":
                self.vbox("controlvm", target["vm_id"], f"setlinkstate{i}", "off" if disconnect else state[key])

    def approve(self, identifier, decision, reason):
        # Human-only API calls this. The planner's registry has no approval tool.
        with self.lock:
            record = self.store.get("recovery", identifier)
            if record["status"] != "pending":
                raise ValueError("Proposal has already been decided")
            if decision == "reject":
                return self.store.update("recovery", identifier, {"status": "rejected", "operator_reason": reason})
            if datetime.now(timezone.utc) > datetime.fromisoformat(record["expires"]):
                return self.store.update("recovery", identifier, {"status": "expired"})
            target = self.store.get("target", record["target_id"])
            if hashlib.sha256(canonical(target).encode()).hexdigest() != record["target_fingerprint"]:
                raise ValueError("Target changed since proposal")
            if self.precondition(record["action"], target) != record["before"]:
                raise ValueError("Workload changed since proposal; reject and propose again")
            self.store.update("recovery", identifier, {"status": "executing", "operator_reason": reason}, expected={"status": "pending"})
            try:
                action = record["action"]
                if action.startswith("lab_"):
                    write_config(self.config, record["desired"])
                    evidence = bounded_get(self.policy.url(target))
                    hardened = (evidence["headers"].get("x-content-type-options") == "nosniff"
                                and "content-security-policy" in evidence["headers"])
                    if evidence["status"] != 200 or hardened != record["desired"]["hardened"]:
                        raise ValueError("HTTP verification did not match desired configuration")
                    authz = api_authz(target, self.policy)
                    if record["desired"]["hardened"] and not authz["access_control_verified"]:
                        raise ValueError("Authorization regression verification failed")
                    if not record["desired"]["hardened"] and not authz["cross_user_read_confirmed"]:
                        raise ValueError("Original demonstration behavior was not restored")
                    evidence["authorization_verification"] = authz
                elif action in {"vm_quarantine", "vm_reconnect"}:
                    expected = record["before"] if action == "vm_quarantine" else record["desired"]
                    self._network(target, expected, action == "vm_quarantine")
                    evidence = self.vm_state(target)
                    for key, value in expected.items():
                        if key.startswith("cableconnected") and expected.get("nic" + key[14:], "none") != "none":
                            if evidence.get(key) != ("off" if action == "vm_quarantine" else value):
                                raise ValueError("VM network verification failed")
                else:
                    self.vbox("snapshot", target["vm_id"], "restore", target["snapshot_id"])
                    evidence = self.vm_state(target)
                    if evidence.get("CurrentSnapshotUUID") != target["snapshot_id"] or evidence.get("VMState") != "poweroff":
                        raise ValueError("Snapshot state verification failed")
                return self.store.update("recovery", identifier, {"status": "verified", "verification": evidence})
            except Exception as exc:
                compensation = "not_available; inspect VM manually" if record["action"] == "vm_restore" else "attempted"
                try:
                    if record["action"].startswith("lab_"):
                        write_config(self.config, record["before"])
                        compensation = "configuration_restored" if read_config(self.config) == record["before"] else "failed"
                    elif record["action"] in {"vm_quarantine", "vm_reconnect"}:
                        self._network(target, record["before"])
                        compensation = "restored" if self.vm_state(target) == record["before"] else "failed"
                except Exception:
                    compensation = "failed; manual intervention required"
                return self.store.update("recovery", identifier, {"status": "failed", "error": str(exc)[:600], "compensation": compensation})
