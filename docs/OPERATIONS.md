# Operator guide

## Normal session

Launch from the repository root. `mj serve`, `mj lab`, `mj doctor` and `mj token` are available after activating `.venv`. `scripts/start.sh` starts the lab in the background, starts MJ in the foreground and stops the lab when the script exits. It does not start or download Ollama automatically.

Use Scope to register the asset and its allowed ports. Only a target of kind `host` may trigger local process inventory. A network target receives bounded TCP probes and evidence correlation; target-linked uploaded artifacts can also be reviewed. A non-demo web target receives header inspection, not the synthetic API validator.

Recovery proposals are disabled by default for ordinary missions. Enable the mission checkbox if wanted; execution still requires a separate decision in Recovery. API clients can supply `allowed_tools`, an optional list of tool names, to restrict a mission further. The final allowed actions are the intersection of that list and the applicable policy-approved tools; `finish` remains available. The structured model-output schema is also narrowed to the remaining choices at each step. The one-click demonstration explicitly enables proposals.

Helpbot has two explicit modes:

- **Ollama:** local model chooses each next tool from remaining applicable actions, based on the goal and preceding results.
- **Playbook:** executes the predefined applicable assessment sequence. The objective is recorded, but does not alter this deterministic sequence.

Cancellation sets an audited flag and stops at the next tool boundary. Queue capacity is four jobs including the active job; only one assessment runs at a time. To stop all future testing of a target, revoke it. Revoked registrations remain available as historical evidence.

## Detection and validated feedback

Submit structured events through Detection or use the local collector:

```bash
source .venv/bin/activate
python scripts/collect.py YOUR_REGISTERED_HOST_TARGET_ID --seconds 60
```

The collector sends at most 500 process observations and omits command lines and environment variables. It is read-only. JSON event fields include `kind`, `count`, `failed`, `executable_write`, `persistence`, `encoded_command`, `path`, `process`, and `destination`. The rule engine does not treat a process path alone as proof of a file write.

Enter a validation reason before labeling an event. Do not mark simulated suspicious events as real malware discoveries. For a demonstration dataset, explicitly document how your synthetic ground truth was constructed. The model requires both classes before exposing probabilities, and the displayed evaluation is predict-before-learn on that stream, not a held-out benchmark.

After drift pauses updates, export labels for review. This release deliberately has no one-click resume that ignores drift. For a new experiment, stop MJ and start with a new `MJ_DATA_DIR`; retain the old directory and exported dataset. A reviewed retraining/migration workflow is a future extension.

## Research and infrastructure

Research runs seeded fuzzing of a fixed educational parser. It reports minimized input, SHA-256, reproduction status and fixed-parser rejection. The CLI native harness adds AddressSanitizer evidence. Neither accepts arbitrary executable uploads.

Infrastructure accepts Kubernetes JSON manifests. Only observations are stored; the raw manifest is not persisted. Inputs never contact a cluster, retrieve credentials or mutate cloud resources. Container defaults and external admission policies can change the significance of static findings.

## Evidence and backups

Download a per-job JSON bundle from Helpbot. It contains target authorization, objective, full tool timeline, findings, HTTP evidence, linked recovery and an audit checkpoint. Checkpoints should be copied outside the local data directory if you need to detect audit replacement/truncation.

To back up all state, stop MJ cleanly and copy the entire `data` directory to an access-controlled location. It includes the operator token; do not commit or share it. During a running backup use SQLite's backup API, not a blind copy of only `mj.db` while its write-ahead log is active.

## API examples

The token can be read from `data/operator-token` inside your own script; avoid hardcoding it or pasting it into issues. This example uses the generated token, not an `MJ_TOKEN` environment override:

```python
from pathlib import Path
import httpx

token = Path("data/operator-token").read_text().strip()
with httpx.Client(base_url="http://127.0.0.1:8765/api",
                  headers={"Authorization": "Bearer " + token}) as client:
    print(client.get("/status").json())
    print(client.get("/jobs").json())
```

| Route | Operation |
|---|---|
| `GET /api/status`, `/api/ollama` | Controller/model readiness |
| `GET/POST /api/targets` | Scope registry |
| `POST /api/targets/{id}/revoke` | Disable future operations |
| `GET/POST /api/jobs` | Missions |
| `POST /api/jobs/{id}/cancel` | Cancellation request |
| `GET /api/findings`, `/api/evidence/{id}` | Observations and proof |
| `GET /api/targets/{id}/graph` | Evidence relationships |
| `GET/POST /api/events` | Telemetry intake |
| `POST /api/events/{id}/feedback` | Validated label |
| `GET /api/learning`, `/api/learning/export` | Metrics / replayable labels |
| `GET/POST /api/samples` | Static triage |
| `POST /api/research/fuzz` | Built-in parser experiment |
| `POST /api/infrastructure` | Offline manifest review |
| `GET/POST /api/recovery` | Proposals |
| `POST /api/recovery/{id}/decision` | Human approval or rejection |
| `GET /api/audit`, `/api/reports/{id}` | Verification and reporting |
| `GET /api/openapi` | Full schema |

## Troubleshooting

| Symptom | Action |
|---|---|
| River compilation / missing Rust on Python 3.14 | Pull the latest code and rerun setup; it selects or downloads Python 3.12 and backs up the incompatible `.venv` |
| `ensurepip is not available` / apt permission denied | Pull the latest code and rerun setup; uv creates and seeds pip without sudo, apt or ensurepip, including when a failed `.venv` already exists |
| Ollama unavailable / model absent | Check `ollama list`, start its service, pull the selected model, or explicitly choose playbook |
| Model times out | Reduce model size; free RAM; use playbook for the presentation; inspect local Ollama logs |
| Assessment connection refused | Start `mj lab`; confirm target port and that the service runs on the same machine |
| Dashboard returns a build message | Run `cd frontend && npm ci && npm run build`, restart from the repository root |
| Unauthorized | Run `mj token` from the same data directory/environment as the server; unlock again |
| Proposal expired / workload changed | Reject an outstanding stale proposal if necessary; reassess and create a fresh proposal |
| Recovery verification fails | Inspect recorded failure and compensation; ensure MJ and the lab share `MJ_DATA_DIR` |
| VM not allowed / adapter disabled | Configure UUID allowlist and enable flag on the actual VirtualBox host |
| Job interrupted after restart | Inspect evidence and workload; start a new mission intentionally |
| Existing active target | Use the existing registration or revoke it before registering a replacement |

For frontend development, the supported default is build-and-serve from the same origin. The Vite proxy does not bypass API Origin checks; use a same-origin browser flow rather than disabling those checks.
