import socket
import threading
import time
import pytest
import uvicorn
from fastapi.testclient import TestClient
from mj.api import create_app
from mj.lab import create_lab
from mj.settings import Settings


@pytest.fixture
def settings(tmp_path):
    return Settings(data_dir=tmp_path, token="test-operator-token-" + "x" * 24)


@pytest.fixture
def client(settings):
    app = create_app(settings)
    with TestClient(app) as client:
        client.headers["Authorization"] = "Bearer " + settings.token
        yield client


@pytest.fixture
def lab(settings):
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    settings.lab_port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(create_lab(settings.data_dir / "lab-config.json"), log_level="error"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    assert server.started
    yield settings.lab_port
    server.should_exit = True
    thread.join(timeout=5)
    sock.close()


def register(client, **overrides):
    body = {"name": "test lab", "kind": "web", "address": "127.0.0.1", "ports": [8091],
            "scheme": "http", "authorized": True, "authorization_note": "Owned isolated test fixture"}
    body.update(overrides)
    response = client.post("/api/targets", json=body)
    assert response.status_code == 200, response.text
    return response.json()


def wait_job(client, identifier):
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        job = client.get("/api/jobs/" + identifier).json()
        if job["status"] not in {"queued", "running"}:
            return job
        time.sleep(0.01)
    raise AssertionError("Job did not finish")
