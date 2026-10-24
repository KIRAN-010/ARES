from datetime import datetime, timedelta, timezone
from mj.lab import read_config, write_config
from mj.schemas import Decision
from conftest import register, wait_job


def test_full_assess_approve_verify_restore(lab, client, settings):
    target = register(client, ports=[lab])
    job = client.post("/api/jobs", json={"target_id":target["id"],"objective":"Assess and propose hardening","planner":"playbook","allow_recovery_proposals":True}).json()
    completed = wait_job(client, job["id"])
    assert completed["status"] == "completed", completed
    assert len(completed["steps"]) == 6
    observations = client.get("/api/findings").json()
    assert len(observations) == 3
    assert sum(f["classification"] == "configuration_observation" for f in observations) == 2
    assert any(f["classification"] == "confirmed_fixture_vulnerability" for f in observations)
    proposal = client.get("/api/recovery").json()[0]
    assert proposal["status"] == "pending"
    assert read_config(settings.data_dir / "lab-config.json") == {"hardened":False}
    response = client.post('/api/recovery/'+proposal["id"]+'/decision', json={"decision":"approve","reason":"Reviewed isolated lab hardening"})
    assert response.json()["status"] == "verified", response.text
    assert "content-security-policy" in response.json()["verification"]["headers"]
    # Same approval cannot be replayed.
    assert client.post('/api/recovery/'+proposal["id"]+'/decision',json={"decision":"approve","reason":"Replay must be prevented"}).status_code == 409
    second = client.post("/api/jobs",json={"target_id":target["id"],"objective":"Verify fixed configuration","planner":"playbook"}).json()
    assert wait_job(client, second["id"])["status"] == "completed"
    assert not [f for f in client.get("/api/findings").json() if f["job_id"] == second["id"]]
    report = client.get("/api/reports/"+job["id"]).json()
    assert report["evidence"] and report["recovery"][0]["status"] == "verified"
    restore = client.post("/api/recovery", json={"target_id":target["id"],"action":"lab_restore"}).json()
    restored = client.post('/api/recovery/'+restore["id"]+'/decision',json={"decision":"approve","reason":"Restore original demo state"}).json()
    assert restored["status"] == "verified"
    assert read_config(settings.data_dir / "lab-config.json")["hardened"] is False
    assert client.get("/api/audit").json()["verification"]["valid"]


def test_verification_failure_compensates(client, settings, monkeypatch):
    target = register(client)
    proposal = client.post("/api/recovery",json={"target_id":target["id"],"action":"lab_harden"}).json()
    monkeypatch.setattr("mj.recovery.bounded_get", lambda *a: {"status":500,"headers":{}})
    result = client.post('/api/recovery/'+proposal["id"]+'/decision',json={"decision":"approve","reason":"Test verification failure"}).json()
    assert result["status"] == "failed"
    assert result["compensation"] == "configuration_restored"
    assert read_config(settings.data_dir / "lab-config.json")["hardened"] is False


def test_stale_state_blocks_action(client, settings):
    target = register(client)
    proposal = client.post("/api/recovery",json={"target_id":target["id"],"action":"lab_harden"}).json()
    write_config(settings.data_dir / "lab-config.json", {"hardened":True})
    assert client.post('/api/recovery/'+proposal["id"]+'/decision',json={"decision":"approve","reason":"Should detect stale precondition"}).status_code == 409


def test_expired_and_rejected_proposals(client):
    target = register(client)
    proposal = client.post("/api/recovery",json={"target_id":target["id"],"action":"lab_harden"}).json()
    past = (datetime.now(timezone.utc)-timedelta(seconds=1)).isoformat()
    client.app.state.store.update("recovery",proposal["id"],{"expires":past})
    assert client.post('/api/recovery/'+proposal["id"]+'/decision',json={"decision":"approve","reason":"Test expired proposal"}).json()["status"] == "expired"
    proposal = client.post("/api/recovery",json={"target_id":target["id"],"action":"lab_harden"}).json()
    assert client.post('/api/recovery/'+proposal["id"]+'/decision',json={"decision":"reject","reason":"Not needed for this test"}).json()["status"] == "rejected"


def test_revoked_target_cannot_heal(client):
    target = register(client)
    proposal = client.post("/api/recovery",json={"target_id":target["id"],"action":"lab_harden"}).json()
    client.post(f'/api/targets/{target["id"]}/revoke')
    assert client.post('/api/recovery/'+proposal["id"]+'/decision',json={"decision":"approve","reason":"Revoked scope must fail"}).status_code == 409


def test_remote_config_write_denied(client):
    target = register(client, address="192.168.56.10")
    assert client.post("/api/recovery",json={"target_id":target["id"],"action":"lab_harden"}).status_code == 403


def test_ollama_plans_are_enforced(client, monkeypatch):
    target = register(client, kind="network")
    agent = client.app.state.agent
    monkeypatch.setattr(agent.planner, "next", lambda *a: Decision(tool="host_inventory",reason="Malicious proposed action"))
    job = client.post("/api/jobs",json={"target_id":target["id"],"objective":"Inspect network scope","planner":"ollama"}).json()
    result = wait_job(client,job["id"])
    assert result["status"] == "failed"
    assert not result["steps"]


def test_ollama_failure_no_silent_fallback(client, monkeypatch):
    target = register(client)
    def unavailable(*args):
        raise ConnectionError("Ollama unavailable")
    monkeypatch.setattr(client.app.state.agent.planner, "next", unavailable)
    job = client.post("/api/jobs",json={"target_id":target["id"],"objective":"Assess this authorized lab","planner":"ollama"}).json()
    result = wait_job(client,job["id"])
    assert result["status"] == "failed" and not result["steps"]


def test_llm_uses_results_and_finishes(lab, client, monkeypatch):
    target = register(client,ports=[lab])
    calls = []
    def planner(objective, target, steps, memory, choices):
        calls.append(steps)
        return Decision(tool="web_assess" if not steps else "finish", reason="Use observations")
    monkeypatch.setattr(client.app.state.agent.planner,"next",planner)
    job = client.post("/api/jobs",json={"target_id":target["id"],"objective":"Inspect headers in scope","planner":"ollama"}).json()
    result = wait_job(client,job["id"])
    assert result["status"] == "completed"
    assert len(calls) == 2 and "MISSING_CONTENT_SECURITY_POLICY" in calls[1][0]["overview"]
