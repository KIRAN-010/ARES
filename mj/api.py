import json
import secrets
import threading
from contextlib import asynccontextmanager
import httpx
from fastapi import FastAPI, Depends, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware
from mj.agent import Agent
from mj.detection import Learner
from mj.policy import Policy
from mj.recovery import Recovery
from mj.schemas import TargetInput, JobInput, EventInput, FeedbackInput, ApprovalInput, RecoveryInput, SampleInput
from mj.settings import Settings
from mj.store import Store
from mj.tools import analyze_sample, attack_graph
from mj.schemas import FuzzInput, ManifestInput
from mj.research import fuzz
from mj.infrastructure import audit_manifest


def create_app(settings=None):
    settings = settings or Settings()
    settings.initialize()
    store = Store(settings.data_dir / "mj.db")
    policy = Policy(settings)
    learner = Learner(store)
    recovery = Recovery(store, policy, settings)
    agent = Agent(store, policy, recovery, settings)
    scope_lock = threading.RLock()

    @asynccontextmanager
    async def lifespan(app):
        yield
        agent.close()
        store.close()

    app = FastAPI(title="MJ Security Lab API", version="0.1.0", lifespan=lifespan,
                  docs_url=None, redoc_url=None, openapi_url=None)
    app.state.store, app.state.agent, app.state.recovery = store, agent, recovery
    app.state.learner, app.state.settings = learner, settings
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"])

    @app.middleware("http")
    async def limits_and_headers(request, call_next):
        if request.method in {"POST", "PUT", "PATCH"}:
            try:
                length = int(request.headers.get("content-length", "0"))
            except ValueError:
                return JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)
            if length > 1500000:
                return JSONResponse({"detail": "Request too large"}, status_code=413)
            body = bytearray()
            async for chunk in request.stream():
                body.extend(chunk)
                if len(body) > 1500000:
                    return JSONResponse({"detail": "Request too large"}, status_code=413)
            request._body = bytes(body)
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'"
        return response

    def operator(request: Request):
        auth = request.headers.get("authorization", "")
        if not secrets.compare_digest(auth, "Bearer " + settings.token):
            raise HTTPException(401, "Operator token required")
        origin = request.headers.get("origin")
        if origin and origin != str(request.base_url).rstrip("/"):
            raise HTTPException(403, "Cross-origin API access denied")

    auth = [Depends(operator)]

    @app.exception_handler(KeyError)
    async def missing(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=404)

    @app.exception_handler(ValueError)
    async def invalid(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=409)

    @app.exception_handler(PermissionError)
    async def forbidden(request, exc):
        return JSONResponse({"detail": str(exc)}, status_code=403)

    @app.get("/health")
    def health():
        return {"ok": True, "service": "mj"}

    @app.get("/api/status", dependencies=auth)
    def status():
        return {"version": "0.1.0", "model": settings.model, "vm_enabled": settings.enable_vm,
                "learning": learner.metrics(), "audit": store.verify(),
                "counts": {k: len(store.list(k, 1000000)) for k in ("target", "job", "finding", "event", "recovery")}}

    @app.get("/api/ollama", dependencies=auth)
    def ollama():
        try:
            with httpx.Client(timeout=3, trust_env=False) as client:
                response = client.get(settings.ollama_url.rstrip("/") + "/api/tags")
                response.raise_for_status()
                models = [m["name"] for m in response.json().get("models", [])]
            return {"reachable": True, "models": models, "selected": settings.model,
                    "ready": settings.model in models}
        except Exception:
            return {"reachable": False, "ready": False, "selected": settings.model,
                    "instruction": "Start Ollama and pull the configured model, or explicitly choose the deterministic playbook"}

    @app.get("/api/targets", dependencies=auth)
    def targets():
        return store.list("target")

    @app.post("/api/targets", dependencies=auth)
    def target_create(body: TargetInput):
        value = dict(body.model_dump(), active=True)
        policy.check(value)
        with scope_lock:
            if any(t["kind"] == value["kind"] and t["address"] == value["address"] and t["ports"] == value["ports"]
                   and t.get("vm_id") == value.get("vm_id") and t["active"] for t in store.list("target", 100000)):
                raise ValueError("An active target already covers this endpoint")
            return store.add("target", value)

    @app.post("/api/targets/{identifier}/revoke", dependencies=auth)
    def revoke(identifier: str):
        # Serialized with recovery approval to avoid revocation during an approved mutation.
        with recovery.lock:
            return store.update("target", identifier, {"active": False})

    @app.get("/api/jobs", dependencies=auth)
    def jobs():
        return store.list("job")

    @app.post("/api/jobs", dependencies=auth)
    def job_create(body: JobInput):
        return agent.submit(body.model_dump())

    @app.get("/api/jobs/{identifier}", dependencies=auth)
    def job_get(identifier: str):
        return store.get("job", identifier)

    @app.post("/api/jobs/{identifier}/cancel", dependencies=auth)
    def cancel(identifier: str):
        return agent.cancel(identifier)

    @app.get("/api/findings", dependencies=auth)
    def findings():
        return store.list("finding")

    @app.get("/api/evidence/{identifier}", dependencies=auth)
    def evidence(identifier: str):
        return store.get("evidence", identifier)

    @app.get("/api/targets/{identifier}/graph", dependencies=auth)
    def graph(identifier: str):
        return attack_graph(store.get("target", identifier), store)

    @app.get("/api/events", dependencies=auth)
    def events():
        return store.list("event")

    @app.post("/api/events", dependencies=auth)
    def event_create(body: EventInput):
        policy.check(store.get("target", body.target_id))
        return learner.ingest(body.model_dump())

    @app.post("/api/events/{identifier}/feedback", dependencies=auth)
    def feedback(identifier: str, body: FeedbackInput):
        return learner.feedback(identifier, body.model_dump())

    @app.get("/api/learning", dependencies=auth)
    def learning():
        return learner.metrics()

    @app.get("/api/learning/export", dependencies=auth)
    def export_labels():
        return {"schema": 1, "labels": store.list("feedback", 1000000), "metrics": learner.metrics()}

    @app.post("/api/samples", dependencies=auth)
    def sample(body: SampleInput):
        policy.check(store.get("target", body.target_id))
        return store.add("sample", dict(analyze_sample(body.name, body.content_base64), target_id=body.target_id))

    @app.get("/api/samples", dependencies=auth)
    def samples():
        return store.list("sample")

    @app.post("/api/research/fuzz", dependencies=auth)
    def fuzz_run(body: FuzzInput):
        return store.add("research", fuzz(body.seed, body.iterations))

    @app.post("/api/infrastructure", dependencies=auth)
    def infrastructure(body: ManifestInput):
        policy.check(store.get("target", body.target_id))
        try:
            result = audit_manifest(body.manifest)
        except (TypeError, AttributeError) as exc:
            raise ValueError("Malformed manifest structure") from exc
        return store.add("infrastructure", dict(result, target_id=body.target_id))

    @app.get("/api/recovery", dependencies=auth)
    def recoveries():
        return store.list("recovery")

    @app.post("/api/recovery", dependencies=auth)
    def propose(body: RecoveryInput):
        target = store.get("target", body.target_id)
        return recovery.propose(target, body.action, "Explicit operator proposal")

    @app.post("/api/recovery/{identifier}/decision", dependencies=auth)
    def approval(identifier: str, body: ApprovalInput):
        return recovery.approve(identifier, body.decision, body.reason)

    @app.get("/api/audit", dependencies=auth)
    def audit():
        return {"verification": store.verify(), "entries": store.audit()[-500:]}

    @app.get("/api/reports/{identifier}", dependencies=auth)
    def report(identifier: str):
        job = store.get("job", identifier)
        bundle = {"schema": 1, "job": job, "target": store.get("target", job["target_id"]),
                  "findings": [f for f in store.list("finding", 1000000) if f["job_id"] == identifier],
                  "evidence": [e for e in store.list("evidence", 1000000) if e["job_id"] == identifier],
                  "recovery": [r for r in store.list("recovery", 1000000) if r.get("job_id") == identifier],
                  "audit_checkpoint": store.verify()}
        return Response(json.dumps(bundle, indent=2), media_type="application/json",
                        headers={"Content-Disposition": f'attachment; filename="mj-report-{job["id"]}.json"'})

    @app.get("/api/openapi", dependencies=auth)
    def openapi():
        return app.openapi()

    if (settings.frontend / "assets").exists():
        app.mount("/assets", StaticFiles(directory=settings.frontend / "assets"), name="assets")

    @app.get("/")
    def index():
        file = settings.frontend / "index.html"
        if file.exists():
            return FileResponse(file)
        return JSONResponse({"message": "Build the dashboard: cd frontend && npm ci && npm run build", "api": "/api/status"})

    return app
