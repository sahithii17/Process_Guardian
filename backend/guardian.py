import time
from collections import defaultdict, deque


class Guardian:
    """Behavior-focused heuristic engine. Alerts are not malware classifications."""

    def __init__(self, monitor):
        self.monitor = monitor
        self.alert_log = deque(maxlen=150)
        self.cpu_since = {}
        self.samples = defaultdict(lambda: deque(maxlen=12))
        self.last_process_count = None
        self.last_spike_time = 0.0
        self.rules = {
            "high_cpu": 80,
            "high_cpu_seconds": 10,
            "high_memory_mb": 1024,
            "critical_cpu": 90,
            "critical_memory_mb": 1024,
            "spawn_spike": 8,
        }

    def _add(self, severity, title, pid=None, detail="", category="behavior"):
        now = time.time()
        key = (pid, title)
        for item in self.alert_log:
            if item["key"] == key and now - item["timestamp_epoch"] < 15:
                return
        self.alert_log.appendleft({
            "key": key,
            "timestamp_epoch": now,
            "time": time.strftime("%H:%M:%S"),
            "severity": severity,
            "title": title,
            "pid": pid,
            "detail": detail,
            "category": category,
        })

    def scan(self, processes):
        now = time.time()
        current_count = len(processes)
        if self.last_process_count is not None:
            delta = current_count - self.last_process_count
            if delta >= self.rules["spawn_spike"] and now - self.last_spike_time > 15:
                self._add("warning", "Process creation spike", detail=f"{delta} net new processes appeared between samples.", category="lifecycle")
                self.last_spike_time = now
        self.last_process_count = current_count

        current_keys = set()
        for p in processes:
            key = p["identity"]
            current_keys.add(key)
            cpu = p["cpu"]
            mem = p["memory_mb"]
            samples = self.samples[key]
            samples.append({"cpu": cpu, "memory": mem, "threads": p["threads"], "time": now, "pid": p["pid"], "name": p["name"]})

            if cpu >= self.rules["high_cpu"]:
                self.cpu_since.setdefault(key, now)
                duration = now - self.cpu_since[key]
                if duration >= self.rules["high_cpu_seconds"]:
                    self._add("warning", "Sustained high CPU", p["pid"], f"{p['name']} stayed above {self.rules['high_cpu']}% CPU for about {int(duration)}s.")
            else:
                self.cpu_since.pop(key, None)

            if mem >= self.rules["high_memory_mb"]:
                self._add("warning", "High memory usage", p["pid"], f"{p['name']} is using {mem:.0f} MB of RAM.")

            if cpu >= self.rules["critical_cpu"] and mem >= self.rules["critical_memory_mb"]:
                self._add("critical", "Critical resource usage", p["pid"], f"{p['name']} is using {cpu}% CPU and {mem:.0f} MB RAM.")

            if len(samples) >= 4:
                baseline = list(samples)[:-1]
                avg_cpu = sum(x["cpu"] for x in baseline) / len(baseline)
                avg_mem = sum(x["memory"] for x in baseline) / len(baseline)
                if avg_cpu >= 1 and cpu > max(70, avg_cpu * 3):
                    self._add("warning", "CPU behavior deviation", p["pid"], f"Current CPU {cpu}% is far above this process's recent baseline of {avg_cpu:.1f}%.", category="baseline")
                if avg_mem >= 20 and mem > max(300, avg_mem * 2.5):
                    self._add("warning", "Memory behavior deviation", p["pid"], f"Current memory {mem:.0f} MB is far above its recent baseline of {avg_mem:.0f} MB.", category="baseline")
                if len(baseline) >= 3:
                    previous_threads = baseline[-1]["threads"]
                    if p["threads"] >= max(50, previous_threads + 40):
                        self._add("warning", "Thread-count spike", p["pid"], f"Thread count rose from {previous_threads} to {p['threads']}.", category="behavior")

        for key in list(self.samples):
            if key not in current_keys:
                self.samples.pop(key, None)
                self.cpu_since.pop(key, None)

    def alerts(self):
        return list(self.alert_log)

    def baseline(self, pid):
        matches = []
        for key, samples in self.samples.items():
            if samples and samples[-1]["pid"] == pid:
                matches = list(samples)
                break
        if len(matches) < 2:
            return {"ready": False, "message": "Collecting more samples for this process...", "samples": len(matches)}
        return {
            "ready": len(matches) >= 4,
            "samples": len(matches),
            "cpu_avg": round(sum(x["cpu"] for x in matches) / len(matches), 1),
            "memory_avg_mb": round(sum(x["memory"] for x in matches) / len(matches), 1),
            "threads_avg": round(sum(x["threads"] for x in matches) / len(matches), 1),
            "cpu_peak": round(max(x["cpu"] for x in matches), 1),
            "memory_peak_mb": round(max(x["memory"] for x in matches), 1),
        }

    def diagnose(self, processes, system):
        top_cpu = sorted(processes, key=lambda x: x["cpu"], reverse=True)[:5]
        top_mem = sorted(processes, key=lambda x: x["memory_mb"], reverse=True)[:5]
        reasons = []
        if system["cpu"] >= 80:
            reasons.append(f"System CPU is high at {system['cpu']}%.")
        if system["memory"] >= 80:
            reasons.append(f"System memory utilization is high at {system['memory']}%.")
        for p in top_cpu[:3]:
            if p["cpu"] >= 50:
                reasons.append(f"{p['name']} (PID {p['pid']}) is using {p['cpu']}% CPU.")
        for p in top_mem[:3]:
            if p["memory_mb"] >= 500:
                reasons.append(f"{p['name']} (PID {p['pid']}) is using {p['memory_mb']:.0f} MB RAM.")

        if not reasons:
            summary = "No strong resource-pressure signal was detected in the current sample."
        else:
            summary = "The current slowdown indicators are driven mainly by the processes listed below."
        return {"summary": summary, "reasons": reasons, "top_cpu": top_cpu, "top_memory": top_mem, "generated_at": time.strftime("%H:%M:%S")}
