import httpx
import pytest
from pydantic import ValidationError
from mj.agent import OllamaPlanner


def test_ollama_structured_contract(settings, monkeypatch):
    requests = []
    original = httpx.Client
    def handler(request):
        import json
        body = json.loads(request.content)
        requests.append(body)
        return httpx.Response(200,json={"message":{"content":'{"tool":"finish","reason":"No applicable tools remain"}'}})
    monkeypatch.setattr("mj.agent.httpx.Client",lambda **kw: original(transport=httpx.MockTransport(handler),**kw))
    target = {"id":"1","name":"lab","kind":"web","address":"127.0.0.1","ports":[8091]}
    result = OllamaPlanner(settings).next("Assess lab",target,[],[],["finish"])
    assert result.tool.value == "finish"
    assert requests[0]["format"]["additionalProperties"] is False
    assert requests[0]["stream"] is False
    assert settings.token not in str(requests[0])


def test_ollama_malformed_response_fails(settings,monkeypatch):
    original = httpx.Client
    transport = httpx.MockTransport(lambda r: httpx.Response(200,json={"message":{"content":"run shell commands"}}))
    monkeypatch.setattr("mj.agent.httpx.Client",lambda **kw: original(transport=transport,**kw))
    target = {"id":"1","name":"lab","kind":"web","address":"127.0.0.1","ports":[8091]}
    with pytest.raises(ValidationError):
        OllamaPlanner(settings).next("Assess lab",target,[],[],["finish"])
