import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Shield,
  Activity,
  Bot,
  Target,
  Fingerprint,
  RotateCcw,
  Database,
  ArrowUpRight,
  Play,
  Download,
  Lock,
  LogOut,
  CheckCircle,
  Circle,
  AlertTriangle,
  Terminal,
  FileSearch,
  Network,
} from "lucide-react";
import "./style.css";

type RecordData = { id: string; [key: string]: any };
const tabs = [
  ["Overview", Activity],
  ["Helpbot", Bot],
  ["Scope", Target],
  ["Evidence", Fingerprint],
  ["Detection", FileSearch],
  ["Research", Terminal],
  ["Infrastructure", Network],
  ["Recovery", RotateCcw],
  ["Audit", Database],
] as const;
const stamp = (s: string) => (s ? new Date(s).toLocaleString() : "—");
const short = (s: string) => s?.slice(0, 8) || "—";
const Badge = ({ children }: { children: React.ReactNode }) => (
  <span className={`badge ${String(children).toLowerCase()}`}>{children}</span>
);
const Json = ({ value }: { value: unknown }) => (
  <pre>{JSON.stringify(value, null, 2)}</pre>
);

function App() {
  const [token, setToken] = useState(sessionStorage.getItem("mj-token") || "");
  const [draftToken, setDraftToken] = useState("");
  const [connected, setConnected] = useState(false);
  const [tab, setTab] = useState("Overview");
  const [status, setStatus] = useState<any>(null);
  const [targets, setTargets] = useState<RecordData[]>([]);
  const [jobs, setJobs] = useState<RecordData[]>([]);
  const [findings, setFindings] = useState<RecordData[]>([]);
  const [events, setEvents] = useState<RecordData[]>([]);
  const [recoveries, setRecoveries] = useState<RecordData[]>([]);
  const [samples, setSamples] = useState<RecordData[]>([]);
  const [audit, setAudit] = useState<any>(null);
  const [ollama, setOllama] = useState<any>(null);
  const [selected, setSelected] = useState("");
  const [objective, setObjective] = useState(
    "Assess this authorized lab, inspect suspicious events, and propose supported defensive fixes with evidence.",
  );
  const [planner, setPlanner] = useState("ollama");
  const [allowProposals, setAllowProposals] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [busy, setBusy] = useState(false);
  const [detail, setDetail] = useState<unknown>(null);
  const [reason, setReason] = useState("");
  const [targetForm, setTargetForm] = useState({
    name: "",
    kind: "web",
    address: "127.0.0.1",
    ports: "8091",
    scheme: "http",
    authorization_note: "",
    vm_id: "",
    snapshot_id: "",
  });
  const [authorized, setAuthorized] = useState(false);
  const [eventJson, setEventJson] = useState(
    '{"kind":"auth","count":15,"failed":true,"source":"operator"}',
  );
  const [manifest, setManifest] = useState(
    JSON.stringify(
      {
        apiVersion: "v1",
        kind: "Pod",
        metadata: { name: "lab-workload" },
        spec: {
          containers: [
            {
              name: "web",
              image: "nginx:latest",
              securityContext: { privileged: true },
            },
          ],
        },
      },
      null,
      2,
    ),
  );
  const [research, setResearch] = useState<any>(null);

  async function api(path: string, method = "GET", body?: unknown) {
    const res = await fetch("/api" + path, {
      method,
      headers: {
        Authorization: "Bearer " + token,
        "Content-Type": "application/json",
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const data = await res.json();
    if (!res.ok)
      throw new Error(
        typeof data.detail === "string"
          ? data.detail
          : JSON.stringify(data.detail),
      );
    return data;
  }
  async function refresh() {
    const [s, t, j, f, e, r, sa] = await Promise.all(
      [
        "/status",
        "/targets",
        "/jobs",
        "/findings",
        "/events",
        "/recovery",
        "/samples",
      ].map((p) => api(p)),
    );
    setStatus(s);
    setTargets(t);
    setJobs(j);
    setFindings(f);
    setEvents(e);
    setRecoveries(r);
    setSamples(sa);
    setConnected(true);
    setSelected((old) => old || t.find((x: RecordData) => x.active)?.id || "");
  }
  useEffect(() => {
    if (!token) return;
    let live = true;
    refresh().catch((e) => {
      if (live) {
        setError(e.message);
        setConnected(false);
      }
    });
    api("/ollama")
      .then((v) => {
        if (live) setOllama(v);
      })
      .catch(() => {});
    const id = setInterval(
      () =>
        refresh().catch((e) => {
          if (live) setError(e.message);
        }),
      4000,
    );
    return () => {
      live = false;
      clearInterval(id);
    };
  }, [token]);
  async function act(fn: () => Promise<any>) {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await fn();
      await refresh();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function run() {
    await api("/jobs", "POST", {
      target_id: selected,
      objective,
      planner,
      allow_recovery_proposals: allowProposals,
    });
    setTab("Helpbot");
    setNotice("Job queued. Results update automatically.");
  }
  async function demo() {
    let target = targets.find(
      (t) =>
        t.active &&
        t.address === "127.0.0.1" &&
        t.ports.length === 1 &&
        t.ports[0] === 8091 &&
        t.kind === "web",
    );
    if (!target)
      target = await api("/targets", "POST", {
        name: "MJ demonstration lab",
        kind: "web",
        address: "127.0.0.1",
        ports: [8091],
        scheme: "http",
        authorized: true,
        authorization_note:
          "Operator explicitly started the bundled local MJ demonstration",
      });
    const id = target!.id;
    setSelected(id);
    for (const e of [
      { kind: "auth", count: 20, failed: true },
      { kind: "file", path: "/tmp/mj-harmless-test", executable_write: true },
      { kind: "config", persistence: true },
    ])
      await api("/events", "POST", {
        target_id: id,
        source: "lab_simulation",
        ...e,
      });
    await api("/jobs", "POST", {
      target_id: id,
      objective:
        "Assess the bundled lab, correlate simulated events, and propose a header configuration fix.",
      planner: "playbook",
      allow_recovery_proposals: true,
    });
    setTab("Helpbot");
    setNotice(
      "Demonstration started. Events are explicitly marked simulated. The lab service must be running on port 8091.",
    );
  }
  async function download(path: string, name: string) {
    const value = await api(path);
    const url = URL.createObjectURL(
      new Blob([JSON.stringify(value, null, 2)], { type: "application/json" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  }
  const active = targets.filter((t) => t.active);
  const selector = (
    <select
      aria-label="Registered target"
      value={selected}
      onChange={(e) => setSelected(e.target.value)}
    >
      <option value="">Choose an authorized target</option>
      {active.map((t) => (
        <option value={t.id} key={t.id}>
          {t.name} · {t.address}
        </option>
      ))}
    </select>
  );
  if (!connected)
    return (
      <main className="login">
        <div className="login-card">
          <div className="logo">
            <Shield size={28} /> MJ<span>LOCAL SECURITY INTELLIGENCE</span>
          </div>
          <h1>
            Your lab.
            <br />
            Your intelligence.
          </h1>
          <p>
            Connect to the local operations console with your operator token.
          </p>
          <label>
            Operator token
            <input
              type="password"
              value={draftToken}
              onChange={(e) => setDraftToken(e.target.value)}
              placeholder="Run mj token in your terminal"
              onKeyDown={(e) => {
                if (e.key === "Enter") {
                  sessionStorage.setItem("mj-token", draftToken);
                  setToken(draftToken);
                }
              }}
            />
          </label>
          <button
            onClick={() => {
              sessionStorage.setItem("mj-token", draftToken);
              setToken(draftToken);
            }}
          >
            Unlock console <ArrowUpRight size={16} />
          </button>
          {error && (
            <p className="error" role="alert">
              {error}
            </p>
          )}
          <div className="footnote">
            <Lock size={13} /> Local Ollama · No paid API required
          </div>
        </div>
      </main>
    );
  return (
    <div className="shell">
      <aside>
        <div className="logo">
          <Shield size={28} /> MJ <span>SECURITY INTELLIGENCE</span>
        </div>
        <div className="workspace">
          <span className="green-dot" /> LOCAL WORKSPACE{" "}
          <small>Authorized lab operations</small>
        </div>
        <nav>
          {tabs.map(([name, Icon]) => (
            <button
              className={tab === name ? "nav active" : "nav"}
              key={name}
              onClick={() => {
                setTab(name);
                setDetail(null);
                if (name === "Audit")
                  act(async () => setAudit(await api("/audit")));
              }}
            >
              <Icon size={18} />
              {name}
              {name === "Recovery" &&
                recoveries.some((r) => r.status === "pending") && (
                  <b>
                    {recoveries.filter((r) => r.status === "pending").length}
                  </b>
                )}
            </button>
          ))}
        </nav>
        <div className="aside-bottom">
          <div className="model">
            <Circle size={12} />
            <span>
              {status?.model}
              <small>
                {ollama?.ready ? "Ollama ready" : "Ollama not ready"}
              </small>
            </span>
          </div>
          <button
            className="nav"
            onClick={() => {
              sessionStorage.removeItem("mj-token");
              setToken("");
              setConnected(false);
              setDraftToken("");
            }}
          >
            <LogOut size={16} />
            Lock console
          </button>
        </div>
      </aside>
      <main className="content">
        <header>
          <div>
            <span className="eyebrow">MJ / OPERATIONS</span>
            <h1>{tab === "Overview" ? "Security at a glance" : tab}</h1>
          </div>
          <span className="local">
            <Lock size={13} /> LOCAL-FIRST <span className="green-dot" />
          </span>
        </header>
        {error && (
          <div className="banner error" role="alert">
            <AlertTriangle size={18} />
            {error}
            <button className="quiet" onClick={() => setError("")}>
              Dismiss
            </button>
          </div>
        )}
        {notice && (
          <div className="banner" role="status">
            {notice}
          </div>
        )}
        {tab === "Overview" && (
          <>
            <section className="hero">
              <div>
                <span className="eyebrow">
                  ONE AGENT. AN ACCOUNTABLE WORKFLOW.
                </span>
                <h2>
                  Understand. Investigate.
                  <br />
                  <em>Recover with confidence.</em>
                </h2>
                <p>
                  Coordinate scoped assessments, behavioral triage and verified
                  recovery through a single local Helpbot.
                </p>
                <div className="row">
                  <button onClick={() => setTab("Helpbot")}>
                    Open Helpbot <ArrowUpRight size={16} />
                  </button>
                  <button
                    className="secondary"
                    disabled={busy}
                    onClick={() => act(demo)}
                  >
                    <Play size={15} />
                    Run lab demonstration
                  </button>
                </div>
                <small>
                  Start <code>mj lab</code> first. Uses a deterministic playbook
                  and harmless simulated events.
                </small>
              </div>
              <div className="hero-symbol">
                <Shield size={100} strokeWidth={1} />
                <span>POLICY ENFORCED</span>
                <span className="tiny">
                  observe → propose → approve → verify
                </span>
              </div>
            </section>
            <div className="metrics">
              {[
                ["Authorized assets", active.length, "Registered scope"],
                [
                  "Observations",
                  findings.length,
                  "Historical · not exploit claims",
                ],
                [
                  "Behavioral events",
                  events.length,
                  "Operator + collector inputs",
                ],
                [
                  "Pending approvals",
                  recoveries.filter((r) => r.status === "pending").length,
                  "Human-controlled recovery",
                ],
              ].map(([label, n, note]) => (
                <div className="metric" key={label}>
                  <span>{label}</span>
                  <strong>{n}</strong>
                  <small>{note}</small>
                </div>
              ))}
            </div>
            <div className="columns">
              <section className="panel">
                <div className="section-title">
                  <h3>Recent operations</h3>
                  <button className="link" onClick={() => setTab("Helpbot")}>
                    View all ↗
                  </button>
                </div>
                {jobs.slice(0, 4).map((j) => (
                  <div className="list-item" key={j.id}>
                    <Bot size={20} />
                    <div>
                      <strong>{j.objective}</strong>
                      <small>
                        {stamp(j.created)} · {j.steps.length} tools
                      </small>
                    </div>
                    <Badge>{j.status}</Badge>
                  </div>
                ))}
                {!jobs.length && (
                  <Empty text="Your first investigation starts with an authorized target." />
                )}
              </section>
              <section className="panel">
                <h3>Control checks</h3>
                <div className="check">
                  <CheckCircle />
                  Independent scope enforcement
                </div>
                <div className="check">
                  <CheckCircle />
                  Approval required for changes
                </div>
                <div className="check">
                  <CheckCircle />
                  Evidence recorded before recovery
                </div>
                <div className="check">
                  <CheckCircle />
                  Validated labels for model updates
                </div>
                <div className="divider" />
                <small>
                  Audit chain:{" "}
                  {status?.audit.valid ? "intact" : "verification failed"} ·{" "}
                  {status?.audit.entries} entries
                </small>
              </section>
            </div>
          </>
        )}
        {tab === "Helpbot" && (
          <>
            <section className="panel compose">
              <div className="section-title">
                <h3>
                  <Bot /> Mission control
                </h3>
                <Badge>bounded autonomy</Badge>
              </div>
              <label>Authorized target{selector}</label>
              <label>
                Objective
                <textarea
                  value={objective}
                  onChange={(e) => setObjective(e.target.value)}
                  rows={3}
                />
              </label>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={allowProposals}
                  onChange={(e) => setAllowProposals(e.target.checked)}
                />
                Allow recovery proposals for this mission. Execution still
                requires separate approval.
              </label>
              <div className="row">
                <select
                  aria-label="Planner"
                  value={planner}
                  onChange={(e) => setPlanner(e.target.value)}
                >
                  <option value="ollama">
                    Local Ollama · adaptive tool selection
                  </option>
                  <option value="playbook">
                    Deterministic assessment playbook
                  </option>
                </select>
                <button
                  disabled={busy || !selected || objective.length < 8}
                  onClick={() => act(run)}
                >
                  <Play size={16} />
                  Start investigation
                </button>
              </div>
              <small>
                One worker · twelve steps maximum · no arbitrary shell ·
                approval is never delegated to the model.
              </small>
            </section>
            {jobs.map((j) => (
              <section className="panel job" key={j.id}>
                <div className="section-title">
                  <div>
                    <span className="eyebrow">
                      MISSION {short(j.id)} / {j.planner}
                    </span>
                    <h3>{j.objective}</h3>
                  </div>
                  <Badge>{j.status}</Badge>
                </div>
                <div className="timeline">
                  {j.steps.map((s: any, i: number) => (
                    <div className="step" key={i}>
                      <div className="step-no">{i + 1}</div>
                      <div>
                        <strong>{s.tool.replaceAll("_", " ")}</strong>
                        <small>{s.reason}</small>
                        <details>
                          <summary>
                            {s.status === "error"
                              ? "Tool failed — inspect error"
                              : "Inspect recorded result"}
                          </summary>
                          <Json
                            value={s.status === "error" ? s.overview : s.result}
                          />
                        </details>
                      </div>
                      <Badge>{s.status}</Badge>
                    </div>
                  ))}
                </div>
                {j.error && <p className="error">{j.error}</p>}
                <p>
                  {j.summary ||
                    "Queued or executing. The timeline updates automatically."}
                </p>
                <div className="row">
                  <button
                    className="secondary"
                    onClick={() =>
                      act(() =>
                        download(
                          "/reports/" + j.id,
                          "mj-report-" + short(j.id) + ".json",
                        ),
                      )
                    }
                  >
                    <Download size={15} />
                    Evidence report
                  </button>
                  {["queued", "running"].includes(j.status) && (
                    <button
                      className="danger"
                      onClick={() =>
                        act(() => api("/jobs/" + j.id + "/cancel", "POST"))
                      }
                    >
                      Cancel
                    </button>
                  )}
                </div>
              </section>
            ))}
            {!jobs.length && (
              <Empty text="No investigations yet. Register a target or run the bundled demonstration." />
            )}
          </>
        )}
        {tab === "Scope" && (
          <div className="columns">
            <section className="panel">
              <h3>Register a lab asset</h3>
              <p>
                IP literals only. Public IPs, metadata endpoints and MJ control
                ports are blocked.
              </p>
              <label>
                Name
                <input
                  value={targetForm.name}
                  onChange={(e) =>
                    setTargetForm({ ...targetForm, name: e.target.value })
                  }
                />
              </label>
              <div className="row">
                <label>
                  Kind
                  <select
                    value={targetForm.kind}
                    onChange={(e) =>
                      setTargetForm({ ...targetForm, kind: e.target.value })
                    }
                  >
                    {["web", "network", "host", "vm"].map((t) => (
                      <option key={t}>{t}</option>
                    ))}
                  </select>
                </label>
                <label>
                  IP address
                  <input
                    value={targetForm.address}
                    onChange={(e) =>
                      setTargetForm({ ...targetForm, address: e.target.value })
                    }
                  />
                </label>
              </div>
              <div className="row">
                <label>
                  Ports (comma-separated)
                  <input
                    value={targetForm.ports}
                    onChange={(e) =>
                      setTargetForm({ ...targetForm, ports: e.target.value })
                    }
                  />
                </label>
                <label>
                  Scheme
                  <select
                    value={targetForm.scheme}
                    onChange={(e) =>
                      setTargetForm({ ...targetForm, scheme: e.target.value })
                    }
                  >
                    <option>http</option>
                    <option>https</option>
                  </select>
                </label>
              </div>
              {targetForm.kind === "vm" && (
                <>
                  <label>
                    Allowlisted VM UUID
                    <input
                      value={targetForm.vm_id}
                      onChange={(e) =>
                        setTargetForm({ ...targetForm, vm_id: e.target.value })
                      }
                    />
                  </label>
                  <label>
                    Clean snapshot UUID
                    <input
                      value={targetForm.snapshot_id}
                      onChange={(e) =>
                        setTargetForm({
                          ...targetForm,
                          snapshot_id: e.target.value,
                        })
                      }
                    />
                  </label>
                </>
              )}
              <label>
                Authorization record
                <textarea
                  value={targetForm.authorization_note}
                  onChange={(e) =>
                    setTargetForm({
                      ...targetForm,
                      authorization_note: e.target.value,
                    })
                  }
                  placeholder="Who owns this lab, and what testing is permitted?"
                />
              </label>
              <label className="checkbox">
                <input
                  type="checkbox"
                  checked={authorized}
                  onChange={(e) => setAuthorized(e.target.checked)}
                />
                I own or have explicit permission to test this lab asset.
              </label>
              <button
                disabled={busy || !authorized}
                onClick={() =>
                  act(async () => {
                    await api("/targets", "POST", {
                      ...targetForm,
                      ports: targetForm.ports.split(",").map(Number),
                      vm_id: targetForm.vm_id || null,
                      snapshot_id: targetForm.snapshot_id || null,
                      authorized: true,
                    });
                    setNotice("Target registered.");
                    setAuthorized(false);
                  })
                }
              >
                Register asset
              </button>
            </section>
            <section className="panel">
              <h3>Scope registry</h3>
              {targets.map((t) => (
                <article className="asset" key={t.id}>
                  <div className="section-title">
                    <h3>{t.name}</h3>
                    <Badge>{t.active ? "active" : "revoked"}</Badge>
                  </div>
                  <code>
                    {t.address} : {t.ports.join(", ")}
                  </code>
                  <p>{t.authorization_note}</p>
                  <small>
                    {t.kind} · {short(t.id)}
                  </small>
                  <div className="row">
                    <button
                      className="secondary"
                      onClick={() =>
                        act(async () =>
                          setDetail(await api("/targets/" + t.id + "/graph")),
                        )
                      }
                    >
                      <Network size={14} />
                      Evidence graph
                    </button>
                    {t.active && (
                      <button
                        className="danger"
                        onClick={() =>
                          act(() => api("/targets/" + t.id + "/revoke", "POST"))
                        }
                      >
                        Revoke
                      </button>
                    )}
                  </div>
                </article>
              ))}
              {!targets.length && (
                <Empty text="No assets registered. Testing requires explicit scope." />
              )}
            </section>
          </div>
        )}
        {tab === "Evidence" && (
          <section className="panel">
            <div className="section-title">
              <h3>Evidence-backed observations</h3>
              <Badge>historical records</Badge>
            </div>
            <p>
              Missing headers are configuration observations. MJ does not infer
              an exploitable vulnerability from them. Older findings remain in
              the audit record after recovery.
            </p>
            {findings.map((f) => (
              <article className="finding" key={f.id}>
                <div className="section-title">
                  <h3>{f.title}</h3>
                  <Badge>{f.severity}</Badge>
                </div>
                <p>{f.impact}</p>
                <small>
                  {f.classification} · {stamp(f.created)} · job{" "}
                  {short(f.job_id)}
                </small>
                <button
                  className="secondary"
                  onClick={() =>
                    act(async () =>
                      setDetail(await api("/evidence/" + f.evidence_id)),
                    )
                  }
                >
                  Inspect proof <ArrowUpRight size={14} />
                </button>
              </article>
            ))}
            {!findings.length && (
              <Empty text="No observations yet. Run an assessment to collect evidence." />
            )}
          </section>
        )}
        {tab === "Detection" && (
          <>
            <div className="metrics">
              {[
                ["Validated labels", status?.learning.labels],
                [
                  "Prequential accuracy",
                  Number(status?.learning.accuracy || 0).toFixed(3),
                ],
                ["F1 score", Number(status?.learning.f1 || 0).toFixed(3)],
                ["Drift alerts", status?.learning.drift_events],
              ].map(([k, v]) => (
                <div className="metric" key={k}>
                  <span>{k}</span>
                  <strong>{v}</strong>
                  <small>Operator-labeled stream only</small>
                </div>
              ))}
            </div>
            <div className="columns">
              <section className="panel">
                <h3>Behavioral event intake</h3>
                <label>Target{selector}</label>
                <label>
                  Structured event
                  <textarea
                    rows={5}
                    value={eventJson}
                    onChange={(e) => setEventJson(e.target.value)}
                  />
                </label>
                <button
                  disabled={busy || !selected}
                  onClick={() =>
                    act(() =>
                      api("/events", "POST", {
                        ...JSON.parse(eventJson),
                        target_id: selected,
                      }),
                    )
                  }
                >
                  Record event
                </button>
                <p>
                  Indicators are triage signals, not malware verdicts. The model
                  stays in cold start until 30 labels, including at least five
                  of each class.
                </p>
                <label>
                  Validation reason
                  <input
                    value={reason}
                    onChange={(e) => setReason(e.target.value)}
                    placeholder="Explain how you independently validated this event"
                  />
                </label>
                <button
                  className="secondary"
                  onClick={() =>
                    act(() =>
                      download("/learning/export", "mj-validated-labels.json"),
                    )
                  }
                >
                  <Download size={15} />
                  Export labeled dataset
                </button>
              </section>
              <section className="panel">
                <h3>Static sample triage</h3>
                <p>
                  Up to 1 MiB. Calculates hashes, entropy and string indicators.
                  Sample bytes are neither saved nor executed.
                </p>
                <input
                  aria-label="Sample file"
                  type="file"
                  disabled={busy || !selected}
                  onChange={(e) => {
                    const file = e.target.files?.[0];
                    if (file)
                      act(async () => {
                        if (file.size > 1048576)
                          throw new Error("Maximum file size is 1 MiB");
                        const bytes = new Uint8Array(await file.arrayBuffer());
                        let binary = "";
                        for (const byte of bytes)
                          binary += String.fromCharCode(byte);
                        await api("/samples", "POST", {
                          target_id: selected,
                          name: file.name,
                          content_base64: btoa(binary),
                        });
                      });
                  }}
                />
                {samples.map((s) => (
                  <details key={s.id}>
                    <summary>
                      {s.name} · {s.size} bytes · {s.indicators.length}{" "}
                      indicators
                    </summary>
                    <Json value={s} />
                  </details>
                ))}
              </section>
            </div>
            <section className="panel">
              <h3>Event stream</h3>
              {events.map((e) => (
                <article className="event" key={e.id}>
                  <div className="section-title">
                    <strong>
                      {e.kind} ·{" "}
                      {e.process ||
                        e.path ||
                        e.destination ||
                        "reported activity"}
                    </strong>
                    <Badge>{e.source}</Badge>
                  </div>
                  <small>
                    {stamp(e.created)} · {e.prediction.status} ·{" "}
                    {e.indicators.length} rule hits
                  </small>
                  {e.indicators.map((i: any) => (
                    <p key={i.rule}>
                      <Badge>{i.severity}</Badge> {i.reason}
                    </p>
                  ))}
                  <div className="row">
                    <button
                      className="secondary"
                      disabled={busy || reason.length < 12}
                      onClick={() =>
                        act(() =>
                          api("/events/" + e.id + "/feedback", "POST", {
                            malicious: false,
                            reason,
                            validated: true,
                          }),
                        )
                      }
                    >
                      Validate benign
                    </button>
                    <button
                      className="danger"
                      disabled={busy || reason.length < 12}
                      onClick={() =>
                        act(() =>
                          api("/events/" + e.id + "/feedback", "POST", {
                            malicious: true,
                            reason,
                            validated: true,
                          }),
                        )
                      }
                    >
                      Validate malicious
                    </button>
                    <button className="link" onClick={() => setDetail(e)}>
                      Details
                    </button>
                  </div>
                </article>
              ))}
              {!events.length && <Empty text="No events collected yet." />}
            </section>
          </>
        )}
        {tab === "Recovery" && (
          <>
            <section className="panel">
              <div className="section-title">
                <h3>Operator decision desk</h3>
                <Badge>approval required</Badge>
              </div>
              <p>
                Proposals expire after 15 minutes and execute only if the
                workload matches the recorded precondition. Snapshot restore
                discards post-snapshot changes; VM verification checks
                infrastructure state only.
              </p>
              <label>
                Decision reason
                <input
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="Record why you approve or reject this action"
                />
              </label>
              <div className="row">
                {selector}
                <select
                  aria-label="Recovery action"
                  defaultValue=""
                  onChange={(e) => {
                    if (e.target.value) {
                      const action = e.target.value;
                      act(() =>
                        api("/recovery", "POST", {
                          target_id: selected,
                          action,
                        }),
                      );
                      e.target.value = "";
                    }
                  }}
                  disabled={!selected || busy}
                >
                  <option value="">Propose a recovery action…</option>
                  {[
                    "lab_harden",
                    "lab_restore",
                    "vm_quarantine",
                    "vm_reconnect",
                    "vm_restore",
                  ].map((a) => (
                    <option key={a}>{a}</option>
                  ))}
                </select>
              </div>
            </section>
            {recoveries.map((r) => (
              <section className="panel" key={r.id}>
                <div className="section-title">
                  <h3>{r.action.replaceAll("_", " ")}</h3>
                  <Badge>{r.status}</Badge>
                </div>
                <p>{r.reason}</p>
                <p className="warning">{r.risk}</p>
                <small>
                  Target {short(r.target_id)} · expires {stamp(r.expires)}
                </small>
                <details>
                  <summary>Review preconditions and verification</summary>
                  <Json value={r} />
                </details>
                {r.status === "pending" && (
                  <div className="row">
                    <button
                      disabled={busy || reason.length < 8}
                      onClick={() =>
                        act(() =>
                          api("/recovery/" + r.id + "/decision", "POST", {
                            decision: "approve",
                            reason,
                          }),
                        )
                      }
                    >
                      Approve & execute
                    </button>
                    <button
                      className="danger"
                      disabled={busy || reason.length < 8}
                      onClick={() =>
                        act(() =>
                          api("/recovery/" + r.id + "/decision", "POST", {
                            decision: "reject",
                            reason,
                          }),
                        )
                      }
                    >
                      Reject
                    </button>
                  </div>
                )}
                {r.error && <p className="error">{r.error}</p>}
              </section>
            ))}
            {!recoveries.length && (
              <Empty text="No recovery proposals. Assessment tools can propose supported actions." />
            )}
          </>
        )}
        {tab === "Audit" && (
          <section className="panel">
            <div className="section-title">
              <h3>Hash-linked audit trail</h3>
              <button
                className="secondary"
                onClick={() => act(async () => setAudit(await api("/audit")))}
              >
                Verify & refresh
              </button>
            </div>
            <p>
              Detects edits within the recorded chain. A database administrator
              can rewrite the chain; externally preserve checkpoint hashes for
              stronger assurance.
            </p>
            {audit && (
              <>
                <Json value={audit.verification} />
                <div className="audit-list">
                  {[...audit.entries].reverse().map((a: any) => (
                    <details key={a.seq}>
                      <summary>
                        #{a.seq} · {a.event} <small>{stamp(a.created)}</small>
                      </summary>
                      <Json value={{ ...a, body: JSON.parse(a.body) }} />
                    </details>
                  ))}
                </div>
              </>
            )}
          </section>
        )}
        {tab === "Research" && (
          <section className="panel">
            <h3>Reproducible fuzzing laboratory</h3>
            <p>
              Mutate inputs to the built-in length-prefixed parser, reproduce
              its unchecked-length exception, minimize the failing case, and
              verify that a fixed parser rejects it safely. This demonstration
              never executes uploaded code.
            </p>
            <button
              disabled={busy}
              onClick={() =>
                act(async () =>
                  setResearch(
                    await api("/research/fuzz", "POST", {
                      seed: 42,
                      iterations: 256,
                    }),
                  ),
                )
              }
            >
              <Play size={15} />
              Run 256 deterministic mutations
            </button>
            {research && <Json value={research} />}
            <div className="divider" />
            <h3>Native sanitizer harness</h3>
            <p>
              The repository also includes a controlled C parser,
              AddressSanitizer validation and an AFL++ workflow. Run the
              documented harness locally in your disposable research VM.
            </p>
            <code>python scripts/native_fuzz.py</code>
          </section>
        )}
        {tab === "Infrastructure" && (
          <section className="panel">
            <h3>Kubernetes configuration review</h3>
            <p>
              Paste a JSON Pod, Deployment, DaemonSet, StatefulSet or Job
              manifest. Reviews privilege, host namespaces, host mounts,
              service-account token mounting, root filesystem and image pinning.
              No cluster credentials or live writes.
            </p>
            <label>Authorized target{selector}</label>
            <label>
              Manifest JSON
              <textarea
                rows={16}
                value={manifest}
                onChange={(e) => setManifest(e.target.value)}
              />
            </label>
            <button
              disabled={busy}
              onClick={() =>
                act(async () =>
                  setDetail(
                    await api("/infrastructure", "POST", {
                      target_id: selected,
                      manifest: JSON.parse(manifest),
                    }),
                  ),
                )
              }
            >
              Assess configuration <ArrowUpRight size={15} />
            </button>
          </section>
        )}
        {detail !== null && (
          <div
            className="modal"
            role="dialog"
            aria-modal="true"
            aria-label="Evidence details"
          >
            <section className="panel">
              <div className="section-title">
                <h3>Recorded detail</h3>
                <button className="secondary" onClick={() => setDetail(null)}>
                  Close
                </button>
              </div>
              <Json value={detail} />
            </section>
          </div>
        )}
        <footer>
          <span>
            <Shield size={13} /> MJ · Authorized lab edition
          </span>
          <span>Evidence first. Changes by approval.</span>
        </footer>
      </main>
    </div>
  );
}
function Empty({ text }: { text: string }) {
  return (
    <div className="empty">
      <Terminal size={26} />
      <p>{text}</p>
    </div>
  );
}
createRoot(document.getElementById("root")!).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
);
