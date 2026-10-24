import threading
from mj.schemas import Decision
from mj.agent import Agent
from conftest import register, wait_job

VM = "12345678-1234-1234-1234-123456789abc"
SNAPSHOT = "aaaaaaaa-1234-1234-1234-123456789abc"


def vm_fixture(client, settings, monkeypatch, state="running", fail_once=False):
    settings.vm_allowlist.add(VM)
    settings.enable_vm = True
    target = register(client,kind="vm",vm_id=VM,snapshot_id=SNAPSHOT)
    values = {"VMState":state,"CurrentSnapshotUUID":"bbbbbbbb-1234-1234-1234-123456789abc",
              "nic1":"hostonly","nic2":"hostonly","cableconnected1":"on","cableconnected2":"on"}
    calls = []
    def fake(*args):
        calls.append(args)
        if args[0] == "showvminfo":
            return "\n".join(f'{k}="{v}"' for k,v in values.items())
        if args[0] == "controlvm":
            if fail_once and args[2] == "setlinkstate2" and args[3] == "off":
                raise ValueError("Injected adapter failure")
            values["cableconnected" + args[2][-1]] = args[3]
        if args[0] == "snapshot":
            values["CurrentSnapshotUUID"] = args[3]
        return ""
    monkeypatch.setattr(client.app.state.recovery,"vbox",fake)
    return target, values, calls


def test_vm_quarantine_reconnect(client, settings, monkeypatch):
    target, state, calls = vm_fixture(client,settings,monkeypatch)
    proposal = client.post("/api/recovery",json={"target_id":target["id"],"action":"vm_quarantine"}).json()
    assert state["cableconnected1"] == "on" # no mutation until approval
    result = client.post('/api/recovery/'+proposal["id"]+'/decision',json={"decision":"approve","reason":"Reviewed lab containment"}).json()
    assert result["status"] == "verified", result
    assert state["cableconnected1"] == state["cableconnected2"] == "off"
    reconnect = client.post("/api/recovery",json={"target_id":target["id"],"action":"vm_reconnect"}).json()
    assert client.post('/api/recovery/'+reconnect["id"]+'/decision',json={"decision":"approve","reason":"Return isolated lab connectivity"}).json()["status"] == "verified"
    assert state["cableconnected1"] == state["cableconnected2"] == "on"
    assert all(call[1] == VM for call in calls)


def test_vm_partial_failure_compensates(client,settings,monkeypatch):
    target, state, _ = vm_fixture(client,settings,monkeypatch,fail_once=True)
    proposal = client.post("/api/recovery",json={"target_id":target["id"],"action":"vm_quarantine"}).json()
    result = client.post('/api/recovery/'+proposal["id"]+'/decision',json={"decision":"approve","reason":"Test partial failure compensation"}).json()
    assert result["status"] == "failed" and result["compensation"] == "restored"
    assert state["cableconnected1"] == state["cableconnected2"] == "on"


def test_vm_snapshot_requires_poweroff(client,settings,monkeypatch):
    target, state, _ = vm_fixture(client,settings,monkeypatch)
    assert client.post("/api/recovery",json={"target_id":target["id"],"action":"vm_restore"}).status_code == 409
    state["VMState"] = "poweroff"
    proposal = client.post("/api/recovery",json={"target_id":target["id"],"action":"vm_restore"}).json()
    result = client.post('/api/recovery/'+proposal["id"]+'/decision',json={"decision":"approve","reason":"Restore approved clean snapshot"}).json()
    assert result["status"] == "verified" and state["CurrentSnapshotUUID"] == SNAPSHOT


def test_cancel_during_inference_dispatches_nothing(client,monkeypatch):
    target = register(client)
    entered, release = threading.Event(), threading.Event()
    def planner(*args):
        entered.set()
        release.wait(3)
        return Decision(tool="web_assess",reason="Should never dispatch after cancellation")
    monkeypatch.setattr(client.app.state.agent.planner,"next",planner)
    job = client.post("/api/jobs",json={"target_id":target["id"],"objective":"Assess and test cancellation","planner":"ollama"}).json()
    assert entered.wait(3)
    assert client.post('/api/jobs/'+job["id"]+'/cancel').status_code == 200
    release.set()
    result = wait_job(client,job["id"])
    assert result["status"] == "cancelled" and not result["steps"]


def test_restart_marks_interrupted_does_not_replay(client,settings):
    store = client.app.state.store
    job = store.add("job",{"status":"running","target_id":"irrelevant"})
    recovery = store.add("recovery",{"status":"executing"})
    original = client.app.state.agent
    replacement = Agent(store,original.policy,original.recovery,settings)
    assert store.get("job",job["id"])["status"] == "interrupted"
    assert store.get("recovery",recovery["id"])["status"] == "interrupted"
    replacement.close()
