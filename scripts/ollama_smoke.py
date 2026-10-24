"""Real local-model integration test against a temporary synthetic HTTP lab.

Requires an already running Ollama service and the configured installed model.
Run MJ_MODEL=your-installed-model python scripts/ollama_smoke.py.
No third-party targets, approvals, model downloads or paid services are involved.
"""
import json
import socket
import tempfile
import threading
import time
from pathlib import Path
import uvicorn
from mj.agent import Agent
from mj.lab import create_lab
from mj.policy import Policy
from mj.recovery import Recovery
from mj.schemas import TargetInput
from mj.settings import Settings
from mj.store import Store


def main():
    with tempfile.TemporaryDirectory(prefix="mj-llm-smoke-") as directory:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        settings = Settings(data_dir=Path(directory), lab_port=sock.getsockname()[1])
        server = uvicorn.Server(uvicorn.Config(create_lab(settings.data_dir / "lab-config.json"), log_level="error"))
        thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
        thread.start()
        store = Store(settings.data_dir / "mj.db")
        policy = Policy(settings)
        agent = Agent(store, policy, Recovery(store, policy, settings), settings)
        try:
            deadline = time.monotonic() + 5
            while not server.started and time.monotonic() < deadline:
                time.sleep(0.05)
            if not server.started:
                raise RuntimeError("Temporary lab did not start")
            target = store.add("target", dict(TargetInput(name="Synthetic local integration lab", ports=[settings.lab_port],
                               authorized=True, authorization_note="Temporary owned model-integration fixture").model_dump(), active=True))
            started = time.monotonic()
            job = agent.submit({"target_id":target["id"], "planner":"ollama", "allow_recovery_proposals":False,
                                "allowed_tools":["web_assess","api_authz"],
                                "objective":"Use web_assess to inspect headers, then api_authz to verify the synthetic cross-user read. Then finish. Do not propose healing."})
            deadline = started + 300
            while time.monotonic() < deadline:
                job = store.get("job",job["id"])
                if job["status"] not in {"queued","running"}:
                    break
                time.sleep(0.1)
            tools = [s["tool"] for s in job["steps"]]
            result = {"model":settings.model, "status":job["status"], "tools":tools,
                      "findings":[f["code"] for f in store.list("finding")],
                      "seconds":round(time.monotonic()-started,2), "error":job.get("error")}
            print(json.dumps(result,indent=2))
            if job["status"] != "completed" or tools != ["web_assess","api_authz"]:
                raise SystemExit("Local model did not complete the requested sequence; inspect the recorded result")
        finally:
            agent.close()
            store.close()
            server.should_exit = True
            thread.join(timeout=5)
            sock.close()


if __name__ == "__main__":
    main()
