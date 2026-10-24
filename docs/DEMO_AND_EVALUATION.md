# Major-project demonstration and evaluation

## Suggested project statement

MJ investigates how a local language-model agent can coordinate security assessment, evidence collection, online behavioral learning and verified recovery while preserving an independent authorization boundary. The contribution is the integration and evaluation of those controls in a reproducible lab, rather than a claim that a general-purpose model independently learns every security discipline.

## Eight-minute demonstration

| Time | Show | Explain |
|---|---|---|
| 0–1 min | Overview and Scope | Owned lab IP, explicit ports, policy outside the model |
| 1–3 min | Run demonstration / Helpbot timeline | Bounded tools, evidence hashes, distinction between observed headers and confirmed synthetic authorization failure |
| 3–4 min | Detection | Simulated behavior labels, rule indicators, no automatic self-labeling |
| 4–6 min | Recovery approval | Precondition, recorded reason, fix, HTTP and authorization regression verification |
| 6–7 min | Second assessment and reports | Compare before/after evidence; historical findings remain visible |
| 7–8 min | Research + Audit | Reproducible parser crash and fix; audit checkpoint and its trust limitation |

Use Ollama for an additional adaptive planning demonstration when its model is installed and responsive. Name the deterministic mode accurately if it is used. Show VirtualBox only after independently testing your configured host/guest setup.

## Measurable requirements

| Metric | Measurement |
|---|---|
| Workflow completion | Finished missions / attempted missions, separately for playbook and Ollama |
| Tool selection quality | Human-reviewed applicable selections / all selections; record early stops and invalid outputs |
| Scope enforcement | Tests rejecting public IPs, redirects, control-plane ports, revoked targets and model-injected actions |
| Finding validity | Reproduced cases / reported vulnerability cases; separate observations from vulnerabilities |
| Detection quality | Precision, recall and F1 on independently validated, held-out events; report class balance |
| Learning behavior | Predict-before-learn performance over time, drift events and update pauses |
| False-action rate | Unjustified executed changes / executed changes; separate human approvals from proposals |
| Recovery success | Verified operations / approved operations, plus compensation success |
| Resource cost | Peak RAM, CPU time, inference latency and mission duration on the actual demo laptop |

Displayed online metrics are not an independent benchmark. A synthetic training demonstration cannot establish real-world malware detection performance. Keep simulated and collected datasets separately identified in the final report.

## Ablation experiments

Compare deterministic planning with local Ollama using the same objectives and reset lab state. Compare rules alone with rules plus the trained River classifier on a held-out labeled sequence. Inject a failed verification and measure whether compensation restores the original state. Introduce changed preconditions or expired approvals and confirm no mutation occurs.

## Honest defense answers

- **Is it autonomous?** Planning and scoped assessment execute without per-tool prompts. Defensive mutations require a separate human approval, as a design requirement.
- **Does River train the LLM?** No. River updates a supervised detector. The agent's operational memory and its planning are separate systems.
- **Does it find real vulnerabilities?** It reproduces broken object-level authorization in a live synthetic API and a native memory error in an educational C fixture. General web header results are observations, not exploit claims.
- **Does it analyze malware?** It supports static sample triage and behavioral event analysis. Live unknown-sample detonation is not enabled.
- **Can it heal anything?** No. It implements fixed reversible lab remediation plus explicit VirtualBox recovery adapters. Generic patch synthesis is future work.
- **Is the audit immutable?** No. It is hash-linked with external checkpoint export; a trusted controller administrator can rewrite local state.

## Remaining research scope

Authenticated per-application test profiles, richer endpoint sensors, isolated dynamic sample analysis, independent held-out model evaluation, more hypervisor adapters, live cloud assessment and multi-service recovery should be treated as separate milestones. Each requires its own fixtures, permissions, failure tests and measured validation before being claimed complete.
