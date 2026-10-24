from dataclasses import dataclass, field
from pathlib import Path
import os
import secrets
import tempfile


@dataclass
class Settings:
    data_dir: Path = field(default_factory=lambda: Path(os.getenv("MJ_DATA_DIR", "data")).resolve())
    token: str = field(default_factory=lambda: os.getenv("MJ_TOKEN", ""))
    ollama_url: str = field(default_factory=lambda: os.getenv("MJ_OLLAMA_URL", "http://127.0.0.1:11434"))
    model: str = field(default_factory=lambda: os.getenv("MJ_MODEL", "qwen2.5:3b"))
    api_port: int = field(default_factory=lambda: int(os.getenv("MJ_PORT", "8765")))
    lab_port: int = field(default_factory=lambda: int(os.getenv("MJ_LAB_PORT", "8091")))
    enable_vm: bool = field(default_factory=lambda: os.getenv("MJ_ENABLE_VM", "0") == "1")
    vm_allowlist: set[str] = field(default_factory=lambda: set(filter(None, os.getenv("MJ_VM_ALLOWLIST", "").split(","))))
    frontend: Path = field(default_factory=lambda: Path("frontend/dist").resolve())
    max_steps: int = 12

    def initialize(self):
        self.data_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        token_file = self.data_dir / "operator-token"
        if not self.token:
            if token_file.exists():
                self.token = token_file.read_text().strip()
            else:
                # Publish a complete file atomically; lab and API may start concurrently.
                fd, temporary = tempfile.mkstemp(prefix=".token-", dir=self.data_dir)
                try:
                    with os.fdopen(fd, "w") as f:
                        f.write(secrets.token_urlsafe(32))
                    try:
                        os.link(temporary, token_file)
                    except FileExistsError:
                        pass
                    self.token = token_file.read_text().strip()
                finally:
                    os.unlink(temporary)
        if len(self.token) < 24:
            raise ValueError("MJ_TOKEN must contain at least 24 characters")
        from urllib.parse import urlsplit
        url = urlsplit(self.ollama_url)
        if url.scheme != "http" or url.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("Ollama must use local HTTP on a loopback address")
        if url.username or url.password or url.query or url.fragment or url.path not in {"", "/"}:
            raise ValueError("Invalid Ollama base URL")
