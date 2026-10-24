"""A deliberately weak header configuration, NOT an exploitable malware target."""
import json
import os
import tempfile
from pathlib import Path
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import HTMLResponse


def write_config(path: Path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".lab-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as handle:
            json.dump(value, handle)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def read_config(path):
    if not path.exists():
        write_config(path, {"hardened": False})
    data = json.loads(path.read_text())
    if set(data) != {"hardened"} or not isinstance(data["hardened"], bool):
        raise ValueError("Invalid lab configuration")
    return data


def create_lab(path):
    app = FastAPI(title="MJ harmless demonstration workload")
    read_config(path)

    @app.get("/", response_class=HTMLResponse)
    def index():
        config = read_config(path)
        headers = {"X-MJ-Lab": "1"}
        if config["hardened"]:
            headers.update({"Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
                            "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"})
        return HTMLResponse("<!doctype html><title>MJ Lab</title><h1>MJ demonstration workload</h1>"
                            "<p>This page contains no sensitive data or executable samples.</p>", headers=headers)

    @app.get("/health")
    def health():
        return {"ok": True, "hardened": read_config(path)["hardened"]}

    @app.get("/api/records/{owner}")
    def record(owner: str, authorization: str = Header(default="")):
        # Publicly documented FIXTURE identities, not production credentials.
        identities = {"Bearer mj-lab-alice": "alice", "Bearer mj-lab-bob": "bob"}
        actor = identities.get(authorization)
        if not actor:
            raise HTTPException(401, "Fixture identity required")
        if owner not in {"alice", "bob"}:
            raise HTTPException(404, "Unknown fixture record")
        if read_config(path)["hardened"] and actor != owner:
            raise HTTPException(403, "Record belongs to another fixture user")
        return {"fixture": "mj-synthetic-record-v1", "owner": owner, "value": "synthetic-" + owner}

    return app
