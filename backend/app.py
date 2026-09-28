from flask import Flask, jsonify
from flask_cors import CORS

from process_monitor import ProcessMonitor
from guardian import Guardian

app = Flask(__name__)
CORS(app)
monitor = ProcessMonitor()
guardian = Guardian(monitor)


def collect():
    processes = monitor.list_processes()
    guardian.scan(processes)
    system = monitor.system_snapshot()
    return processes, system


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "service": "Process Guardian", "platform": system_platform()})


def system_platform():
    import platform
    return platform.system()


@app.get("/api/system")
def system():
    _, snapshot = collect()
    return jsonify(snapshot)


@app.get("/api/processes")
def processes():
    p, _ = collect()
    return jsonify({"processes": p})


@app.get("/api/processes/<int:pid>")
def process_detail(pid):
    data = monitor.process_detail(pid)
    if data is None:
        return jsonify({"error": "Process not found or access was denied."}), 404
    return jsonify(data)


@app.get("/api/processes/<int:pid>/tree")
def process_tree(pid):
    data = monitor.process_tree(pid)
    if data is None:
        return jsonify({"error": "Process not found or access was denied."}), 404
    return jsonify(data)


@app.get("/api/processes/<int:pid>/baseline")
def process_baseline(pid):
    return jsonify(guardian.baseline(pid))


@app.get("/api/history")
def history():
    return jsonify(monitor.history())


@app.get("/api/alerts")
def alerts():
    return jsonify({"alerts": guardian.alerts()})


@app.get("/api/lifecycle")
def lifecycle():
    return jsonify({"events": monitor.lifecycle()})


@app.get("/api/diagnose")
def diagnose():
    p, s = collect()
    return jsonify(guardian.diagnose(p, s))


@app.get("/api/rules")
def rules():
    return jsonify(guardian.rules)


@app.post("/api/processes/<int:pid>/<action>")
def control_process(pid, action):
    if action not in {"suspend", "resume", "terminate"}:
        return jsonify({"error": "Unsupported action"}), 400
    result = monitor.control(pid, action)
    return jsonify(result), (200 if result["ok"] else 403)


@app.post("/api/demo/cpu/start")
def demo_cpu_start():
    return jsonify(monitor.start_cpu_demo())


@app.post("/api/demo/cpu/stop")
def demo_cpu_stop():
    return jsonify(monitor.stop_demo())


if __name__ == "__main__":
    print("Process Guardian API listening on http://127.0.0.1:5000")
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
