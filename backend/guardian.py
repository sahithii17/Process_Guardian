import time
from collections import defaultdict, deque


class Guardian:

    def __init__(self, monitor):

        self.monitor = monitor

        self.alert_log = deque(maxlen=200)

        self.cpu_high_since = {}

        self.samples = defaultdict(
            lambda: deque(maxlen=60)
        )

        self.process_counts = deque(maxlen=30)

        self.rules = {
            "high_cpu": 80,
            "high_cpu_seconds": 10,
            "high_memory_mb": 1024,
            "critical_cpu": 90,
            "critical_memory_mb": 1024,
            "spawn_spike": 8,
            "thread_spike": 100,
            "behavior_deviation": 2.0,
        }

    # ---------------------------------------------------------
    # Alerts
    # ---------------------------------------------------------

    def add_alert(
        self,
        severity,
        title,
        message,
        pid=None,
        process=None,
    ):

        alert = {
            "id": f"{time.time_ns()}",
            "timestamp": time.time(),
            "severity": severity,
            "title": title,
            "message": message,
            "pid": pid,
            "process": process,
        }

        self.alert_log.appendleft(alert)

    def scan(self, processes):

        now = time.time()

        self.process_counts.append(len(processes))

        for process in processes:

            pid = process["pid"]
            name = process["name"]

            cpu = float(process.get("cpu", 0))
            memory = float(process.get("memory_mb", 0))
            threads = int(process.get("threads", 0))

            sample = self.samples[pid]

            sample.append({
                "cpu": cpu,
                "memory_mb": memory,
                "threads": threads,
                "timestamp": now,
            })

            # Sustained CPU
            if cpu >= self.rules["high_cpu"]:

                if pid not in self.cpu_high_since:
                    self.cpu_high_since[pid] = now

                duration = now - self.cpu_high_since[pid]

                if duration >= self.rules["high_cpu_seconds"]:

                    self.add_alert(
                        "warning",
                        "Sustained high CPU",
                        (
                            f"{name} has remained above "
                            f"{self.rules['high_cpu']}% CPU."
                        ),
                        pid,
                        name,
                    )

            else:
                self.cpu_high_since.pop(pid, None)

            # High memory
            if memory >= self.rules["high_memory_mb"]:

                self.add_alert(
                    "warning",
                    "High memory usage",
                    (
                        f"{name} is using "
                        f"{memory:.0f} MB of memory."
                    ),
                    pid,
                    name,
                )

            # Critical
            if (
                cpu >= self.rules["critical_cpu"]
                and
                memory >= self.rules["critical_memory_mb"]
            ):

                self.add_alert(
                    "critical",
                    "Critical resource usage",
                    (
                        f"{name} is using "
                        f"{cpu:.0f}% CPU and "
                        f"{memory:.0f} MB memory."
                    ),
                    pid,
                    name,
                )

            # Thread spike
            if threads >= self.rules["thread_spike"]:

                self.add_alert(
                    "info",
                    "Large thread count",
                    (
                        f"{name} currently has "
                        f"{threads} threads."
                    ),
                    pid,
                    name,
                )

    # ---------------------------------------------------------
    # Alerts API
    # ---------------------------------------------------------

    def alerts(self):
        return list(self.alert_log)

    # ---------------------------------------------------------
    # Baseline
    # ---------------------------------------------------------

    def baseline(self, pid):

        samples = list(self.samples.get(pid, []))

        if not samples:

            return {
                "pid": pid,
                "samples": 0,
                "avg_cpu": 0,
                "peak_cpu": 0,
                "avg_memory_mb": 0,
                "peak_memory_mb": 0,
                "avg_threads": 0,
                "peak_threads": 0,
            }

        cpu_values = [
            item["cpu"]
            for item in samples
        ]

        memory_values = [
            item["memory_mb"]
            for item in samples
        ]

        thread_values = [
            item["threads"]
            for item in samples
        ]

        return {
            "pid": pid,
            "samples": len(samples),

            "avg_cpu": round(
                sum(cpu_values) / len(cpu_values),
                2,
            ),

            "peak_cpu": round(
                max(cpu_values),
                2,
            ),

            "avg_memory_mb": round(
                sum(memory_values) / len(memory_values),
                2,
            ),

            "peak_memory_mb": round(
                max(memory_values),
                2,
            ),

            "avg_threads": round(
                sum(thread_values) / len(thread_values),
                2,
            ),

            "peak_threads": max(thread_values),
        }

    # ---------------------------------------------------------
    # Diagnosis
    # ---------------------------------------------------------

    def diagnose(self, processes, system):

        reasons = []
        recommendations = []

        cpu = float(system.get("cpu", 0))
        memory = float(system.get("memory", 0))

        # System CPU
        if cpu >= 80:

            top_cpu = sorted(
                processes,
                key=lambda p: p.get("cpu", 0),
                reverse=True,
            )[:5]

            reasons.append({
                "type": "cpu",
                "severity": "warning",
                "title": "High system CPU usage",
                "message": (
                    f"Overall CPU utilization is "
                    f"{cpu:.1f}%."
                ),
                "processes": [
                    {
                        "pid": p["pid"],
                        "name": p["name"],
                        "cpu": p["cpu"],
                    }
                    for p in top_cpu
                ],
            })

            recommendations.append(
                "Inspect the highest CPU processes in the Processes tab."
            )

        # System memory
        if memory >= 80:

            top_memory = sorted(
                processes,
                key=lambda p: p.get("memory_mb", 0),
                reverse=True,
            )[:5]

            reasons.append({
                "type": "memory",
                "severity": "warning",
                "title": "High system memory usage",
                "message": (
                    f"Overall memory utilization is "
                    f"{memory:.1f}%."
                ),
                "processes": [
                    {
                        "pid": p["pid"],
                        "name": p["name"],
                        "memory_mb": p["memory_mb"],
                    }
                    for p in top_memory
                ],
            })

            recommendations.append(
                "Inspect processes with the largest memory footprint."
            )

        # Top CPU contributor
        if processes:

            top = max(
                processes,
                key=lambda p: p.get("cpu", 0),
            )

            if top.get("cpu", 0) >= 50:

                reasons.append({
                    "type": "process",
                    "severity": "info",
                    "title": "Main CPU contributor",
                    "message": (
                        f"{top['name']} (PID {top['pid']}) "
                        f"is currently using "
                        f"{top['cpu']:.1f}% CPU."
                    ),
                    "pid": top["pid"],
                })

        if not reasons:

            reasons.append({
                "type": "healthy",
                "severity": "normal",
                "title": "No major resource pressure detected",
                "message": (
                    "Current CPU and memory utilization "
                    "are within the configured thresholds."
                ),
            })

        return {
            "timestamp": time.time(),
            "summary": (
                "System appears healthy."
                if len(reasons) == 1
                and reasons[0]["type"] == "healthy"
                else "Potential resource pressure detected."
            ),
            "reasons": reasons,
            "recommendations": recommendations,
            "system": system,
        }