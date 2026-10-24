"""Non-LLM policy boundary. No DNS, arbitrary URLs, shell strings or redirects."""
import ipaddress
from urllib.parse import urlsplit


NETWORKS = tuple(ipaddress.ip_network(n) for n in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128"))


class Policy:
    def __init__(self, settings):
        self.settings = settings

    def check(self, target):
        if not target.get("authorized") or not target.get("active", True):
            raise PermissionError("Target is not actively authorized")
        address = ipaddress.ip_address(target["address"])
        if not any(address in n for n in NETWORKS):
            raise PermissionError("Only loopback and RFC1918 lab IP literals are accepted")
        if address.is_multicast or address.is_unspecified:
            raise PermissionError("Invalid target address")
        forbidden = {self.settings.api_port, urlsplit(self.settings.ollama_url).port or 11434}
        if set(target["ports"]) & forbidden:
            raise PermissionError("MJ control plane and Ollama ports cannot be assessed")
        if target["kind"] == "host" and not address.is_loopback:
            raise PermissionError("Host inventory is local-only")
        if target["kind"] == "vm":
            if not target.get("vm_id") or target["vm_id"] not in self.settings.vm_allowlist:
                raise PermissionError("VM UUID must be configured in MJ_VM_ALLOWLIST")
        return target

    def url(self, target, port=None, path="/"):
        self.check(target)
        port = port or target["ports"][0]
        paths = {"/", "/health"}
        if self.is_demo(target):
            paths |= {"/api/records/alice", "/api/records/bob"}
        if port not in target["ports"] or path not in paths:
            raise PermissionError("Endpoint outside bounded tool policy")
        host = target["address"]
        if ":" in host:
            host = f"[{host}]"
        return f"{target['scheme']}://{host}:{port}{path}"

    def is_demo(self, target):
        return (target["kind"] == "web" and target["address"] == "127.0.0.1"
                and target["ports"] == [self.settings.lab_port] and target["scheme"] == "http")
