import React, { useEffect, useMemo, useState } from "react";
import {
  Activity, AlertTriangle, BrainCircuit, CheckCircle2, CircleStop, Clock3,
  Cpu, GitBranch, HardDrive, History, MemoryStick, Pause, Play, RefreshCw,
  Search, Shield, Sparkles, TerminalSquare, X, Zap
} from "lucide-react";

const API = "http://127.0.0.1:5000/api";

function formatMB(mb = 0) {
  return mb >= 1024 ? `${(mb / 1024).toFixed(1)} GB` : `${mb.toFixed(0)} MB`;
}

function StatusPill({ status }) {
  const cls = { running: "running", sleeping: "sleeping", stopped: "stopped", zombie: "zombie" }[status] || "";
  return <span className={`pill ${cls}`}>{status}</span>;
}

function Stat({ icon, label, value, sub }) {
  return <div className="stat-card"><div className="stat-icon">{icon}</div><div><span className="stat-label">{label}</span><strong>{value}</strong><small>{sub}</small></div></div>;
}

function Sparkline({ points = [], unit = "%" }) {
  const values = points.map(p => p.value);
  if (!values.length) return <div className="spark-empty">Collecting telemetry…</div>;
  const max = Math.max(100, ...values, 1), min = Math.min(0, ...values), w = 420, h = 110;
  const coords = values.map((v, i) => `${(i / Math.max(1, values.length - 1)) * w},${h - ((v - min) / Math.max(1, max - min)) * h}`).join(" ");
  return <><svg viewBox={`0 0 ${w} ${h}`} className="spark" preserveAspectRatio="none"><polyline points={coords} fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" /></svg><div className="spark-value">{values.at(-1).toFixed(1)}{unit}</div></>;
}

function Tree({ node }) {
  if (!node) return <div className="muted">No process-tree data available.</div>;
  return <div className="tree-node"><div className="tree-line"><GitBranch size={13}/><b>{node.name}</b><span>PID {node.pid}</span></div>{node.children?.map(c => <div className="tree-child" key={`${c.pid}-${c.identity}`}><Tree node={c}/></div>)}</div>;
}

function App() {
  const [system, setSystem] = useState(null);
  const [processes, setProcesses] = useState([]);
  const [history, setHistory] = useState({ cpu: [], memory: [], processes: [] });
  const [alerts, setAlerts] = useState([]);
  const [lifecycle, setLifecycle] = useState([]);
  const [selected, setSelected] = useState(null);
  const [tree, setTree] = useState(null);
  const [baseline, setBaseline] = useState(null);
  const [tab, setTab] = useState("overview");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("all");
  const [diagnosis, setDiagnosis] = useState(null);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [backend, setBackend] = useState(false);

  async function get(path) {
    const r = await fetch(API + path);
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.error || "Request failed");
    return data;
  }

  async function refresh() {
    try {
      const [s, p, h, a, l] = await Promise.all([get("/system"), get("/processes"), get("/history"), get("/alerts"), get("/lifecycle")]);
      setSystem(s); setProcesses(p.processes); setHistory(h); setAlerts(a.alerts); setLifecycle(l.events); setBackend(true); setMessage("");
      if (selected) {
        const fresh = await get(`/processes/${selected.pid}`).catch(() => null);
        if (fresh) setSelected(fresh); else setSelected(null);
        if (fresh) setBaseline(await get(`/processes/${fresh.pid}/baseline`).catch(() => null));
      }
    } catch {
      setBackend(false); setMessage("Backend unavailable. Run the Flask server on port 5000.");
    }
  }

  useEffect(() => { refresh(); const id = setInterval(refresh, 2500); return () => clearInterval(id); }, []);

  async function openProcess(p) {
    try {
      const [detail, t, b] = await Promise.all([get(`/processes/${p.pid}`), get(`/processes/${p.pid}/tree`), get(`/processes/${p.pid}/baseline`)]);
      setSelected(detail); setTree(t); setBaseline(b); setTab("processes");
    } catch { setMessage("That process is no longer available."); }
  }

  async function control(action) {
    if (!selected) return;
    if (!window.confirm(`${action[0].toUpperCase() + action.slice(1)} ${selected.name} (PID ${selected.pid})?`)) return;
    setBusy(true);
    try {
      const r = await fetch(`${API}/processes/${selected.pid}/${action}`, { method: "POST" });
      const data = await r.json();
      setMessage(data.ok ? `${action} requested for ${data.name || selected.name} (PID ${selected.pid}).` : data.error);
      await refresh();
      if (action === "terminate") setSelected(null);
    } catch { setMessage("Control request failed."); }
    finally { setBusy(false); }
  }

  async function diagnose() {
    setBusy(true);
    try { setDiagnosis(await get("/diagnose")); setTab("diagnose"); }
    catch { setMessage("Could not run diagnosis."); }
    finally { setBusy(false); }
  }

  async function demoStart() {
    setBusy(true);
    try { const d = await fetch(`${API}/demo/cpu/start`, { method: "POST" }).then(r => r.json()); setMessage(`CPU demo started as PID ${d.pid}. Watch Guardian Alerts for detection.`); }
    finally { setBusy(false); }
  }

  async function demoStop() {
    await fetch(`${API}/demo/cpu/stop`, { method: "POST" });
    setMessage("CPU demo stopped.");
    refresh();
  }

  const filtered = useMemo(() => processes.filter(p => {
    const q = `${p.name} ${p.pid} ${p.username}`.toLowerCase();
    return q.includes(query.toLowerCase()) && (filter === "all" || p.status === filter);
  }), [processes, query, filter]);

  const attention = alerts.filter(a => a.severity === "critical").length ? "ATTENTION NEEDED" : alerts.length ? "MONITORING" : "NOMINAL";

  return <div className="app">
    <header className="topbar">
      <div className="brand"><div className="brand-icon"><Shield size={24}/></div><div><b>Process Guardian</b><span>Cross-platform process behavior intelligence</span></div></div>
      <div className="top-actions"><span className={`status-dot ${backend ? "on" : "off"}`}></span>{backend ? `ONLINE · ${system?.os || "OS"}` : "OFFLINE"}<button className="icon-btn" onClick={refresh}><RefreshCw size={16}/></button></div>
    </header>

    <main>
      <section className="hero">
        <div><div className="eyebrow">OPERATING SYSTEM PROJECT · BEHAVIOR LAYER</div><h1>Don't just watch processes.<br/><em>Understand their behavior.</em></h1><p>Process Guardian turns real OS telemetry into baselines, anomaly alerts, lifecycle events and explainable system diagnostics.</p><div className="hero-actions"><button className="primary" onClick={diagnose} disabled={!backend || busy}><Sparkles size={16}/> Diagnose System</button><button className="secondary" onClick={demoStart} disabled={!backend || busy}><Zap size={16}/> Run CPU Demo</button><button className="secondary" onClick={demoStop} disabled={!backend || busy}><CircleStop size={16}/> Stop Demo</button></div></div>
        <div className="guardian-card"><Shield size={34}/><div><span>GUARDIAN STATUS</span><b>{attention}</b><small>{alerts.length} recorded alert{alerts.length === 1 ? "" : "s"}</small></div></div>
      </section>

      {message && <div className="notice"><AlertTriangle size={16}/><span>{message}</span><button onClick={() => setMessage("")}><X size={15}/></button></div>}

      <section className="stats">
        <Stat icon={<Cpu/>} label="CPU" value={`${system?.cpu ?? 0}%`} sub="system utilization"/>
        <Stat icon={<MemoryStick/>} label="Memory" value={`${system?.memory ?? 0}%`} sub={system ? `${formatMB(system.memory_used_mb)} / ${formatMB(system.memory_total_mb)}` : "waiting"}/>
        <Stat icon={<Activity/>} label="Processes" value={system?.processes ?? "—"} sub="live process table"/>
        <Stat icon={<HardDrive/>} label="Disk" value={`${system?.disk ?? 0}%`} sub="root volume"/>
      </section>

      <nav className="tabs">
        <button className={tab === "overview" ? "active" : ""} onClick={() => setTab("overview")}><Shield size={15}/> Overview</button>
        <button className={tab === "processes" ? "active" : ""} onClick={() => setTab("processes")}><Activity size={15}/> Processes</button>
        <button className={tab === "alerts" ? "active" : ""} onClick={() => setTab("alerts")}><AlertTriangle size={15}/> Alerts <i>{alerts.length}</i></button>
        <button className={tab === "incidents" ? "active" : ""} onClick={() => setTab("incidents")}><History size={15}/> Lifecycle</button>
        <button className={tab === "diagnose" ? "active" : ""} onClick={() => setTab("diagnose")}><BrainCircuit size={15}/> Diagnosis</button>
      </nav>

      {tab === "overview" && <>
        <section className="overview-grid">
          <div className="panel"><div className="panel-head"><div><span className="eyebrow">LIVE TELEMETRY</span><h2>System behavior</h2></div><span className="live"><span/> LIVE</span></div><div className="charts-grid"><div className="chart"><span>CPU history</span><b>{system?.cpu ?? 0}%</b><Sparkline points={history.cpu}/></div><div className="chart"><span>Memory history</span><b>{system?.memory ?? 0}%</b><Sparkline points={history.memory}/></div></div></div>
          <div className="panel guardian-panel"><div className="panel-head"><div><span className="eyebrow">GUARDIAN ENGINE</span><h2>What changed?</h2></div><BrainCircuit size={22}/></div>{alerts.slice(0,4).map((a,i)=><div className={`mini-alert ${a.severity}`} key={i}><AlertTriangle size={15}/><div><b>{a.title}</b><small>{a.detail}</small></div><time>{a.time}</time></div>)}{!alerts.length && <div className="empty"><CheckCircle2 size={30}/><b>No anomalies detected</b><span>Guardian is building process baselines.</span></div>}</div>
        </section>
        <section className="panel process-preview"><div className="panel-head"><div><span className="eyebrow">TOP RESOURCE CONTRIBUTORS</span><h2>Processes worth investigating</h2></div><button className="link-btn" onClick={() => setTab("processes")}>View all →</button></div><div className="top-list">{processes.slice(0,6).map(p => <button key={p.identity} onClick={() => openProcess(p)}><span className="proc-icon"><TerminalSquare size={15}/></span><div><b>{p.name}</b><small>PID {p.pid} · {p.threads} threads</small></div><strong className={p.cpu >= 80 ? "hot" : ""}>{p.cpu}%</strong><span>{formatMB(p.memory_mb)}</span></button>)}</div></section>
      </>}

      {tab === "processes" && <section className="panel process-panel"><div className="panel-head"><div><span className="eyebrow">REAL OS PROCESS TABLE</span><h2>Every process has an identity</h2></div><span className="muted">PID is assigned by the operating system</span></div><div className="toolbar"><div className="search"><Search size={16}/><input value={query} onChange={e => setQuery(e.target.value)} placeholder="Search name, PID or user…"/></div><select value={filter} onChange={e => setFilter(e.target.value)}><option value="all">All states</option><option value="running">Running</option><option value="sleeping">Sleeping</option><option value="stopped">Stopped</option></select></div><div className="table-wrap"><table><thead><tr><th>PROCESS</th><th>PID</th><th>CPU</th><th>MEMORY</th><th>THREADS</th><th>STATE</th></tr></thead><tbody>{filtered.slice(0,120).map(p => <tr key={p.identity} onClick={() => openProcess(p)} className={selected?.pid === p.pid ? "selected" : ""}><td><b>{p.name}</b><small>{p.username}</small></td><td className="mono">{p.pid}</td><td className={p.cpu >= 80 ? "hot" : ""}>{p.cpu}%</td><td>{formatMB(p.memory_mb)}</td><td>{p.threads}</td><td><StatusPill status={p.status}/></td></tr>)}</tbody></table></div></section>}

      {tab === "alerts" && <section className="panel"><div className="panel-head"><div><span className="eyebrow">EXPLAINABLE ALERTS</span><h2>Why Guardian flagged something</h2></div></div><div className="alert-list">{alerts.length ? alerts.map((a,i)=><div className={`big-alert ${a.severity}`} key={i}><div className="alert-badge"><AlertTriangle size={17}/></div><div><b>{a.title}</b><p>{a.detail}</p><small>{a.category} · {a.time}{a.pid ? ` · PID ${a.pid}` : ""}</small></div></div>) : <div className="empty"><CheckCircle2 size={32}/><b>No alerts yet</b><span>Try the CPU demo to see the Guardian engine react to a real process.</span></div>}</div></section>}

      {tab === "incidents" && <section className="panel"><div className="panel-head"><div><span className="eyebrow">PROCESS LIFECYCLE</span><h2>What started, changed or ended?</h2></div><Clock3 size={20}/></div><div className="timeline">{lifecycle.map((e,i)=><div className="timeline-item" key={`${e.timestamp}-${i}`}><span className={`timeline-dot ${e.type}`}></span><div><b>{e.name} · PID {e.pid}</b><p>{e.detail}</p><small>{e.time} · {e.type}</small></div></div>)}{!lifecycle.length && <div className="empty"><History size={30}/><b>Collecting lifecycle events…</b></div>}</div></section>}

      {tab === "diagnose" && <section className="panel diagnosis"><div className="panel-head"><div><span className="eyebrow">SYSTEM DIAGNOSTIC</span><h2>Why might the system feel slow?</h2></div><button className="primary small" onClick={diagnose} disabled={busy}><Sparkles size={15}/> Run again</button></div>{diagnosis ? <><div className="diagnosis-summary"><BrainCircuit size={25}/><div><b>{diagnosis.summary}</b><small>Generated at {diagnosis.generated_at}</small></div></div><div className="reason-list">{diagnosis.reasons.length ? diagnosis.reasons.map((r,i)=><div key={i}><Zap size={14}/>{r}</div>) : <div className="success"><CheckCircle2 size={15}/> No strong resource-pressure signal in this sample.</div>}</div><div className="diagnosis-cols"><div><h3>Top CPU contributors</h3>{diagnosis.top_cpu.map(p => <button key={p.identity} onClick={() => openProcess(p)}><b>{p.name}</b><span>{p.cpu}%</span></button>)}</div><div><h3>Top memory contributors</h3>{diagnosis.top_memory.map(p => <button key={p.identity} onClick={() => openProcess(p)}><b>{p.name}</b><span>{formatMB(p.memory_mb)}</span></button>)}</div></div></> : <div className="empty"><BrainCircuit size={36}/><b>Run a diagnosis</b><span>Guardian will combine current CPU, memory and process data into an explainable snapshot.</span><button className="primary small" onClick={diagnose}>Diagnose System</button></div>}</section>}

      {selected && <aside className="drawer"><div className="drawer-head"><div><span className="eyebrow">PROCESS INSPECTOR</span><h2>{selected.name}</h2><small className="mono">PID {selected.pid}</small></div><button className="icon-btn" onClick={() => setSelected(null)}><X/></button></div><div className="detail-grid"><div><span>CPU</span><b>{selected.cpu}%</b></div><div><span>MEMORY</span><b>{formatMB(selected.memory_mb)}</b></div><div><span>THREADS</span><b>{selected.threads}</b></div><div><span>STATUS</span><b>{selected.status}</b></div><div><span>PARENT PID</span><b>{selected.parent_pid}</b></div><div><span>USER</span><b>{selected.username}</b></div></div><div className="baseline"><div><span>BEHAVIOR BASELINE</span><b>{baseline?.ready ? "READY" : "LEARNING"}</b></div>{baseline?.ready ? <p>Avg CPU {baseline.cpu_avg}% · Avg RAM {formatMB(baseline.memory_avg_mb)} · Peak CPU {baseline.cpu_peak}%</p> : <p>Collecting samples so Guardian can compare this process with its own recent behavior.</p>}</div><div className="control-title">PROCESS CONTROL</div><div className="controls"><button disabled={busy} onClick={() => control("suspend")}><Pause size={15}/> Suspend</button><button disabled={busy} onClick={() => control("resume")}><Play size={15}/> Resume</button><button disabled={busy} className="danger" onClick={() => control("terminate")}><CircleStop size={15}/> Terminate</button></div><div className="control-title">PROCESS TREE</div><Tree node={tree}/><div className="path"><Clock3 size={13}/> Started {selected.start_time?.replace("T", " ")}</div></aside>}

      <footer>Process Guardian · Cross-platform OS project · Heuristics indicate resource/behavior anomalies, not malware verdicts.</footer>
    </main>
  </div>;
}

export default App;
