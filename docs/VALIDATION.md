# Validation record

Development validation on 24 October 2026. Results below distinguish executed tests from integrations that still need the operator's environment.

| Check | Observed result |
|---|---|
| Python automated suite | **55 passed**, approximately **86% statement coverage** |
| Ruff checks | Passed for `mj`, `tests`, `scripts` |
| Dependency consistency | `pip check` passed |
| React / TypeScript | Type checking and Vite production build passed |
| Real browser smoke | Login, live lab mission, human approval, verified remediation, research, manifest review and audit screens passed |
| Responsive layout | 1440-pixel desktop and 390-pixel mobile checked; no horizontal overflow |
| Browser exceptions | None during the smoke workflow |
| Native C harness | ASan heap-buffer-overflow reproduced; minimized input `a5`; fixed parser rejected input with exit code 2 |
| Local Ollama | Real `qwen2.5:0.5b` inference returned a valid structured decision in 5.55 seconds; a live lab mission found the synthetic flaw in 45.31 seconds but selected extra tools beyond the natural-language request |
| Lab authorization | Legitimate baselines and cross-user read reproduced before fix; 403 cross-user denial and legitimate reads verified after fix |
| Failure recovery | Deliberate verification failure restored original demo configuration |
| VirtualBox | Command/state adapter tested with a fake driver, including partial-failure compensation and snapshot preconditions; **no real VM recovery executed** |
| AFL++ | Optional documented workflow; **not executed** |
| Public / third-party targets | **None assessed** |

The Python environment was 3.12.14 on Linux; the dashboard built with Node 24.22.1. Locked numerical dependencies were selected to remain compatible with Python 3.11 as well. The CI matrix is configured for 3.11 and 3.12; this does not assert that GitHub-hosted runs have already completed.

The small-model observation motivated explicit per-mission `allowed_tools` and `allow_recovery_proposals` controls. The final test suite verifies that an overreaching model cannot dispatch excluded tools or create unpermitted proposals. The default 3B model and the final strictly restricted live-model sequence have not been benchmarked here. `scripts/ollama_smoke.py` provides that integration check for an installed local model; model quality must not be inferred from the deterministic playbook results.

One dependency emitted a Starlette test-client deprecation warning about its future HTTP client transition. It did not fail tests; it should be revisited before updating the pinned test stack.

## Security cases covered

Missing/invalid operator token; hostile Origin and Host; missing authorization assertion; public/link-local/mapped/hostname targets; control-plane port exclusion; duplicate scope; revoked scope; oversized request/response; rejected compression; redirect non-following; cookie/body exclusion from evidence; model-injected action/argument rejection; malformed model output; unavailable model without silent fallback; cancellation during inference; interrupted work after restart; approval expiry, rejection, replay and stale preconditions; verification compensation; VM adapter state reversal; cold start, class balance, validated labels, duplicate-label rejection and drift pause; audit modification detection; reproducible fuzzing; malformed manifest rejection.

## Reproduce

```bash
source .venv/bin/activate
pytest --cov=mj --cov-report=term-missing
ruff check mj tests scripts
python scripts/native_fuzz.py
cd frontend
npm ci
npm run build
```

For the optional browser smoke test, install Playwright in a temporary test environment, install its Chromium browser, and make the module available through `NODE_PATH` (or install it in `frontend` without committing the dependency changes). Then run `node scripts/browser_smoke.cjs` from the repository root. `MJ_PYTHON` can select the Python environment and `CHROMIUM_EXECUTABLE` can select an installed Chromium binary. The script starts its own temporary loopback services; ports 8765 and 8091 must be free. It removes its temporary token/database after the test and saves a synthetic dashboard screenshot.

Tests are evidence for the exercised cases, not a guarantee of production security or universal correctness. No real-world malware accuracy, production incident recovery rate or zero-false-positive claim has been established.
