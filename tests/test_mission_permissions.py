from conftest import register, wait_job
from mj.schemas import Decision


def test_explicit_mission_tool_list(client, monkeypatch):
    target = register(client)
    monkeypatch.setattr(client.app.state.agent.planner,"next",lambda *a:Decision(tool="network_probe",reason="Extra unsolicited test"))
    job = client.post("/api/jobs",json={"target_id":target["id"],"objective":"Only inspect web headers","allowed_tools":["web_assess"]}).json()
    result = wait_job(client,job["id"])
    assert result["status"] == "failed" and not result["steps"]


def test_proposal_not_available_without_mission_permission(client,monkeypatch):
    target = register(client)
    monkeypatch.setattr(client.app.state.agent.planner,"next",lambda *a:Decision(tool="propose_healing",reason="Model overreached"))
    job = client.post("/api/jobs",json={"target_id":target["id"],"objective":"Read-only assessment please"}).json()
    assert wait_job(client,job["id"])["status"] == "failed"
    assert client.get("/api/recovery").json() == []


def test_invalid_mission_tool_rejected(client):
    target = register(client)
    assert client.post("/api/jobs",json={"target_id":target["id"],"objective":"Reject arbitrary command","allowed_tools":["shell"]}).status_code == 422
