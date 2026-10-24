import pytest
from mj.settings import Settings
from mj.schemas import TargetInput, Decision
from pydantic import ValidationError
from conftest import register


def test_token_required(client):
    client.headers.pop("Authorization")
    assert client.get("/health").status_code == 200
    for path in ("/api/status", "/api/targets", "/api/jobs", "/api/audit", "/api/openapi"):
        assert client.get(path).status_code == 401


def test_cross_origin_and_host_denied(client):
    assert client.get("/api/status", headers={"Origin": "https://attacker.example"}).status_code == 403
    assert client.get("/api/status", headers={"Host": "attacker.example"}).status_code == 400
    assert client.get("/api/status", headers={"Origin": "http://testserver"}).status_code == 200


@pytest.mark.parametrize("address", ["8.8.8.8", "169.254.169.254", "0.0.0.0", "224.0.0.1", "::ffff:127.0.0.1", "100.64.0.1", "fc00::1"])
def test_non_lab_addresses_denied(client, address):
    body = TargetInput(name="x", address=address, authorized=True, authorization_note="Owned testing lab").model_dump()
    assert client.post("/api/targets", json=body).status_code == 403


@pytest.mark.parametrize("address", ["localhost", "example.com", "127.0.0.1@evil.com", "2130706433", "http://127.0.0.1"])
def test_hostnames_and_url_tricks_denied(client, address):
    assert client.post("/api/targets", json={"name":"x", "address":address,"authorized":True,"authorization_note":"Owned test scope"}).status_code == 422


@pytest.mark.parametrize("port", [8765, 11434])
def test_control_planes_denied(client, port):
    assert client.post("/api/targets", json={"name":"x","ports":[port],"authorized":True,"authorization_note":"Owned test scope"}).status_code == 403


def test_missing_attestation(client):
    assert client.post("/api/targets", json={"name":"x","authorization_note":"Owned test scope"}).status_code == 422


def test_scope_revocation(client):
    target = register(client)
    client.post(f'/api/targets/{target["id"]}/revoke')
    response = client.post("/api/jobs", json={"target_id":target["id"],"objective":"Assess this lab","planner":"playbook"})
    assert response.status_code == 403


def test_duplicate_scope(client):
    target = register(client)
    body = {k:v for k,v in target.items() if k not in {"id", "created", "active"}}
    assert client.post("/api/targets", json=body).status_code == 409


def test_unauthorized_vm_and_remote_host(client):
    base = {"name":"x","authorized":True,"authorization_note":"Owned test scope"}
    assert client.post("/api/targets", json={**base,"kind":"vm"}).status_code == 403
    assert client.post("/api/targets", json={**base,"kind":"host","address":"192.168.1.2"}).status_code == 403


def test_request_size_cap(client):
    assert client.post("/api/samples", content=b"x" * 1500001).status_code == 413


def test_bad_sample_and_path_not_found(client):
    target = register(client)
    assert client.post("/api/samples", json={"target_id":target["id"],"name":"x","content_base64":"%%%"}).status_code == 409
    assert client.get("/api/evidence/unknown").status_code == 404


def test_planner_cannot_supply_shell_or_arguments():
    for payload in ({"tool":"shell","reason":"do it"}, {"tool":"web_assess","reason":"test","target":"8.8.8.8"},
                    {"tool":"approve","reason":"urgent"}):
        with pytest.raises(ValidationError):
            Decision.model_validate(payload)


def test_local_ollama_only(tmp_path):
    with pytest.raises(ValueError):
        Settings(data_dir=tmp_path, token="x"*32, ollama_url="http://example.com:11434").initialize()


def test_generated_token_persistence(tmp_path):
    one = Settings(data_dir=tmp_path)
    one.initialize()
    two = Settings(data_dir=tmp_path)
    two.initialize()
    assert one.token == two.token and len(one.token) >= 32
    assert (tmp_path / "operator-token").stat().st_mode & 0o777 == 0o600
