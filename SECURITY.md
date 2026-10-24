# Security model

MJ is intended for an explicitly authorized, isolated academic lab. The controller, local operator and OS account are trusted. Model output, target responses, collected events and uploaded bytes are not trusted instructions.

## Enforced controls

- API and lab bind to loopback. Protected API routes require a locally generated bearer token. Browser API access checks Origin and Host; there is no permissive CORS configuration.
- Target registration requires an authorization assertion and note. Only numeric loopback/RFC1918 addresses are accepted; public, link-local, multicast, mapped IPv6 and hostname forms are rejected. Private addressing alone is not ownership: the operator still has to provide genuine authorization.
- Testing is limited to up to 16 explicitly registered TCP ports and fixed paths. MJ and Ollama ports are excluded. HTTP clients ignore proxy environment variables and do not follow redirects. TLS verification is enabled.
- The LLM chooses enum tools; it cannot inject executable arguments, write arbitrary files, approve remediation or select a different target. Scope and optional per-mission tool restrictions are enforced at dispatch. Recovery proposals are disabled unless explicitly allowed for the mission. Tool outputs sent to the model are marked untrusted.
- Recovery requests expire after 15 minutes. Approval is separate from planning, single-use, scoped to captured preconditions and serialized with target revocation. Configuration writes are restricted to the bundled lab file.
- VM execution uses fixed `VBoxManage` argument lists, no shell, validated UUIDs and an operator allowlist. It is disabled by default. Restoring a snapshot requires the VM to be powered off.
- No uploaded sample executes. Static sample bytes are not retained. No active malware is included. Native research executes only the repository's deliberately vulnerable fixture.
- Events do not train the model. Authenticated operator validation is required; duplicates are rejected and drift can pause learning. No executable model deserialization is used.
- State is persisted before recovery execution. Recovery attempts, failures and compensation are audited. Interrupted operations are not replayed.

## Known limitations / non-goals

- Single local operator, no tenant isolation, no enterprise role-based access control or external signed audit sink. The bearer token confers operator privileges; protect it like a password. The dashboard keeps it in tab-scoped session storage.
- A malicious OS administrator can replace code, steal the token or rewrite the audit chain. Hash chaining detects in-chain modification but not whole-chain replacement or truncation without an externally retained checkpoint.
- Local process observation is a bounded polling collector, not a kernel-grade endpoint detection and response (EDR) sensor. Event sources are assertions by authenticated clients, not cryptographically attested sensors.
- The controller is not a malware sandbox. VirtualBox isolation must be configured by the operator; network disconnection does not remove host shared-folder/clipboard channels. Never run unknown malware on the controller.
- VM restore verifies the hypervisor's snapshot/state, not guest cleanliness, application health or data integrity. Preserve needed guest evidence before accepting data loss. Automatic forensic memory capture is not implemented.
- Real cloud remediation, arbitrary binary fuzzing, universal API auth testing, generic patch synthesis, multi-service disaster recovery and unsupervised online learning are not implemented.
- Ollama may choose incomplete sequences or produce invalid output; invalid decisions stop. The playbook is reproducible, but is not equivalent to LLM reasoning. No claims of universal detection or zero false positives are made.
- Storage/export and dashboard lists are sized for lab workloads. Run one server process per data directory. In-flight reads can finish after cancellation/revocation; subsequent dispatch is blocked.

Report issues through the repository's issue tracker with synthetic reproductions. Do not post tokens, private target data or live malware samples.
