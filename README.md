# Process Guardian

**Cross-platform process behavior monitoring, anomaly detection, lifecycle analysis and guarded process control.**

The project is intentionally different from a basic process viewer: it continuously samples real OS process data through `psutil`, builds lightweight per-process baselines, detects configurable behavior/resource deviations, records lifecycle events, and provides an explainable system diagnosis.

## Architecture

React + Vite → Flask REST API → Python `psutil` → macOS / Windows / Linux process APIs

## Features

- Real-time process table with PID, CPU, memory, threads, state, user and parent PID
- Process inspector with executable/cmdline information where OS permissions allow
- Suspend / resume / terminate with protected Guardian backend PIDs
- Interactive parent/child process tree
- Per-process behavior baseline: average/peak CPU, memory and threads
- Heuristic anomaly detection: sustained CPU, high memory, CPU+memory critical usage, CPU/memory baseline deviation, thread spikes and process-count spikes
- Explainable Guardian alerts (heuristics are **not** malware classifications)
- Process lifecycle timeline: starts, exits and user control actions
- "Diagnose System" mode that identifies current CPU/memory contributors
- Safe CPU demo process so the anomaly engine can be demonstrated live
- CPU, memory and process-count history
- Cross-platform backend design for macOS, Windows and Linux

## Run on macOS / Linux

### Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Backend: `http://127.0.0.1:5000`

### Frontend

Open a **second terminal**:

```bash
cd frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal.

## Windows

Backend environment activation is:

```powershell
.venv\Scripts\activate
```

Then run `python app.py`. Frontend commands are the same.

## Demo

1. Start both backend and frontend.
2. Click **Run CPU Demo** in Process Guardian.
3. A real Python child process is created by the backend.
4. Watch the process table and Guardian Alerts.
5. After the sustained CPU threshold is met, a high-CPU alert can appear.
6. Click **Stop Demo** to terminate the demo process.
7. Open **Lifecycle** to see the process start and end events.
8. Open a process and wait for the **Behavior Baseline** to become ready.

## Important permissions note

Operating systems protect critical processes. Some process details or controls may return `AccessDenied`, and that is expected. Do not terminate system-critical processes.

## Viva positioning

> Activity Monitor / task managers primarily expose current process and resource information. Process Guardian adds a behavior-analysis layer: it learns recent process baselines, detects configurable deviations, records lifecycle events, explains alerts, and diagnoses current system resource pressure.

This project does **not** claim to be an antivirus or malware detector. Its alerts identify observable resource/behavior anomalies for investigation.
