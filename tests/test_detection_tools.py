import base64
import httpx
import pytest
from mj.detection import Learner
from mj.tools import bounded_get, analyze_sample
from mj.research import fuzz, parse_fixed
from conftest import register


def test_redirect_not_followed_and_secrets_redacted():
    requests = []
    def handler(request):
        requests.append(request)
        return httpx.Response(302,headers={"Location":"http://169.254.169.254", "Set-Cookie":"secret=abc"},stream=httpx.ByteStream(b"secret body"))
    result = bounded_get("http://127.0.0.1:8091", lambda **kw: httpx.Client(transport=httpx.MockTransport(handler),**kw))
    assert len(requests) == 1 and result["redirect_not_followed"]
    assert "set-cookie" not in result["headers"] and "body" not in result


def test_response_body_bounded():
    transport = httpx.MockTransport(lambda _: httpx.Response(200,stream=httpx.ByteStream(b"x" * 100000)))
    result = bounded_get("http://127.0.0.1:8091",lambda **kw: httpx.Client(transport=transport,**kw))
    assert result["bytes_hashed"] == 65536 and result["truncated"]


def test_compressed_response_rejected():
    transport = httpx.MockTransport(lambda _: httpx.Response(200,headers={"content-encoding":"gzip"},stream=httpx.ByteStream(b"not read")))
    with pytest.raises(ValueError, match="Compressed"):
        bounded_get("http://127.0.0.1:8091",lambda **kw: httpx.Client(transport=transport,**kw))


def test_event_rules_do_not_train_and_labels_replay(client):
    target = register(client)
    event = client.post("/api/events",json={"target_id":target["id"],"kind":"auth","count":20,"failed":True}).json()
    assert event["indicators"][0]["rule"] == "AUTH_BURST"
    assert event["prediction"]["probability"] is None
    assert client.get("/api/learning").json()["labels"] == 0
    body = {"malicious":True,"reason":"Independently reproduced lab test","validated":True}
    assert client.post('/api/events/'+event["id"]+'/feedback',json=body).status_code == 200
    assert client.post('/api/events/'+event["id"]+'/feedback',json=body).status_code == 409
    assert Learner(client.app.state.store).metrics()["labels"] == 1


def test_model_warmup_and_class_balance(client):
    target = register(client)
    for i in range(32):
        malicious = i % 2 == 0
        event = client.post("/api/events",json={"target_id":target["id"],"kind":"auth","count":30 if malicious else 1,"failed":malicious}).json()
        client.post('/api/events/'+event["id"]+'/feedback',json={"malicious":malicious,"reason":"Validated isolated test fixture","validated":True})
    learner = client.app.state.learner
    prediction = learner.predict(event["features"])
    assert prediction["status"] == "experimental" and prediction["probability"] is not None
    assert learner.metrics()["class_counts"] == {"True":16,"False":16}


def test_drift_pause_blocks_feedback(client):
    target = register(client)
    event = client.post("/api/events",json={"target_id":target["id"],"kind":"process"}).json()
    client.app.state.learner.paused = True
    assert client.post('/api/events/'+event["id"]+'/feedback',json={"malicious":False,"reason":"Review validated event","validated":True}).status_code == 409


def test_static_sample_never_executes():
    content = b"MZ EICAR-STANDARD-ANTIVIRUS-TEST-FILE /bin/sh"
    result = analyze_sample("../../sample",base64.b64encode(content).decode())
    assert result["executed"] is False and result["format"] == "PE-like" and len(result["indicators"]) == 2
    assert len(result["sha256"]) == 64


def test_fuzz_reproducibility_and_fix():
    one = fuzz(42,256)
    assert one == fuzz(42,256)
    assert one["reproduced"] and one["fixed_parser_rejects"]
    with pytest.raises(ValueError):
        parse_fixed(bytes.fromhex(one["minimized_input_hex"]))
    assert parse_fixed(b"\x03abc") == b"abc"


def test_infrastructure_endpoint(client):
    target = register(client)
    response = client.post("/api/infrastructure",json={"target_id":target["id"],"manifest":{"kind":"Pod","spec":{"hostPID":True,"containers":[{"securityContext":{"privileged":True}}]}}})
    assert response.status_code == 200
    assert {"HOST_NAMESPACE","PRIVILEGED"}.issubset({f["code"] for f in response.json()["findings"]})
    assert response.json()["cluster_contacted"] is False
    assert client.post("/api/infrastructure",json={"target_id":target["id"],"manifest":{"kind":"Pod","spec":{"containers":"oops"}}}).status_code == 409


def test_artifacts_join_agent_context(client):
    from conftest import wait_job
    target = register(client,kind="network")
    sample = client.post("/api/samples",json={"target_id":target["id"],"name":"harmless.txt","content_base64":base64.b64encode(b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE").decode()})
    assert sample.status_code == 200
    client.post("/api/infrastructure",json={"target_id":target["id"],"manifest":{"kind":"Pod","spec":{}}})
    job = client.post("/api/jobs",json={"target_id":target["id"],"objective":"Review artifacts and fuzz the built-in parser","planner":"playbook"}).json()
    result = wait_job(client,job["id"])
    assert result["status"] == "completed"
    tools = {step["tool"] for step in result["steps"]}
    assert {"review_samples","review_infrastructure","fuzz_builtin_parser"}.issubset(tools)


def test_audit_tampering_detected(client):
    register(client)
    store = client.app.state.store
    assert store.verify()["valid"]
    store.db.execute("UPDATE audit SET body='{}' WHERE seq=1")
    assert not store.verify()["valid"]
