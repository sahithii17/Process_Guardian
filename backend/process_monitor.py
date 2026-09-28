import os
import platform
import subprocess
import sys
import time
from collections import deque
from datetime import datetime

import psutil


class ProcessMonitor:
    def __init__(self):
        self.started_at = time.time()
        self.cpu_history = deque(maxlen=120)
        self.memory_history = deque(maxlen=120)
        self.process_history = deque(maxlen=120)
        self.process_seen = {}
        self.lifecycle_events = deque(maxlen=200)
        self.demo_pids = set()

        for p in psutil.process_iter():
            try:
                p.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

    def _priority(self, p):
        try:
            return str(p.nice())
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.Error):
            return "N/A"

    def _identity(self, p):
        try:
            return f"{p.pid}:{p.create_time():.3f}"
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return str(p.pid)

    def _process(self, p):
        try:
            with p.oneshot():
                cpu = p.cpu_percent(None)
                mem = p.memory_info().rss / (1024 * 1024)
                status = p.status()
                parent = p.ppid()
                threads = p.num_threads()
                name = p.name()
                create_time = p.create_time()
                priority = self._priority(p)
                username = ""
                try:
                    username = p.username()
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    username = "Permission denied"

            return {
                "pid": p.pid,
                "name": name,
                "cpu": round(cpu, 1),
                "memory_mb": round(mem, 1),
                "status": status,
                "parent_pid": parent,
                "threads": threads,
                "priority": priority,
                "username": username,
                "start_time": datetime.fromtimestamp(create_time).isoformat(timespec="seconds"),
                "identity": self._identity(p),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

    def list_processes(self):
        result = []
        current = {}
        for p in psutil.process_iter():
            item = self._process(p)
            if item:
                result.append(item)
                current[item["identity"]] = item

        previous = set(self.process_seen)
        now = time.time()
        for identity, item in current.items():
            if identity not in self.process_seen:
                self.lifecycle_events.appendleft({
                    "timestamp": now,
                    "time": time.strftime("%H:%M:%S"),
                    "type": "started",
                    "pid": item["pid"],
                    "name": item["name"],
                    "detail": f"{item['name']} (PID {item['pid']}) entered the process table."
                })
        for identity in previous - set(current):
            old = self.process_seen[identity]
            self.lifecycle_events.appendleft({
                "timestamp": now,
                "time": time.strftime("%H:%M:%S"),
                "type": "ended",
                "pid": old["pid"],
                "name": old["name"],
                "detail": f"{old['name']} (PID {old['pid']}) left the process table."
            })

        self.process_seen = current
        return sorted(result, key=lambda x: x["cpu"], reverse=True)

    def system_snapshot(self):
        cpu = psutil.cpu_percent(interval=0.15)
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage(os.path.abspath(os.sep))
        processes = len(psutil.pids())
        now = time.time()

        sample = {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "cpu": round(cpu, 1),
            "memory": round(vm.percent, 1),
            "memory_used_mb": round(vm.used / (1024 * 1024), 1),
            "memory_total_mb": round(vm.total / (1024 * 1024), 1),
            "disk": round(disk.percent, 1),
            "processes": processes,
            "uptime_seconds": round(now - self.started_at, 1),
            "os": platform.system(),
            "os_version": platform.version(),
            "machine": platform.machine(),
        }
        self.cpu_history.append({"time": sample["timestamp"], "value": sample["cpu"]})
        self.memory_history.append({"time": sample["timestamp"], "value": sample["memory"]})
        self.process_history.append({"time": sample["timestamp"], "value": processes})
        return sample

    def history(self):
        return {
            "cpu": list(self.cpu_history),
            "memory": list(self.memory_history),
            "processes": list(self.process_history),
        }

    def lifecycle(self):
        return list(self.lifecycle_events)[:50]

    def process_detail(self, pid):
        try:
            p = psutil.Process(pid)
            item = self._process(p)
            if not item:
                return None
            try:
                item["exe"] = p.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                item["exe"] = "Permission denied"
            try:
                item["cmdline"] = p.cmdline()
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                item["cmdline"] = []
            try:
                item["open_files"] = len(p.open_files())
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.Error):
                item["open_files"] = None
            return item
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    def process_tree(self, pid):
        try:
            root = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

        def node(p, depth=0):
            item = self._process(p)
            if not item:
                return None
            children = []
            try:
                for child in p.children(recursive=False):
                    child_node = node(child, depth + 1)
                    if child_node:
                        children.append(child_node)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            item["depth"] = depth
            item["children"] = children
            return item

        return node(root)

    def control(self, pid, action):
        protected = {os.getpid()}
        if hasattr(os, "getppid"):
            protected.add(os.getppid())
        if pid == 1:
            protected.add(1)

        if pid in protected:
            return {"ok": False, "error": "This PID is protected by Process Guardian."}

        try:
            p = psutil.Process(pid)
            name = p.name()
            if action == "suspend":
                p.suspend()
            elif action == "resume":
                p.resume()
            elif action == "terminate":
                p.terminate()
            else:
                return {"ok": False, "error": "Unknown action"}
            self.lifecycle_events.appendleft({
                "timestamp": time.time(),
                "time": time.strftime("%H:%M:%S"),
                "type": action,
                "pid": pid,
                "name": name,
                "detail": f"User requested {action} for {name} (PID {pid})."
            })
            return {"ok": True, "pid": pid, "name": name, "action": action}
        except psutil.AccessDenied:
            return {"ok": False, "error": "Permission denied by the operating system."}
        except psutil.NoSuchProcess:
            return {"ok": False, "error": "Process no longer exists."}
        except psutil.Error as exc:
            return {"ok": False, "error": str(exc)}

    def start_cpu_demo(self):
        # Harmless demo process used to prove that Guardian reacts to real OS behavior.
        code = "import time\nwhile True: pass"
        proc = subprocess.Popen([sys.executable, "-c", code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.demo_pids.add(proc.pid)
        return {"ok": True, "pid": proc.pid, "name": "Python CPU Demo"}

    def stop_demo(self, pid=None):
        targets = [pid] if pid else list(self.demo_pids)
        stopped = []
        for target in targets:
            if target not in self.demo_pids and pid is not None:
                continue
            result = self.control(target, "terminate")
            if result.get("ok"):
                stopped.append(target)
                self.demo_pids.discard(target)
        return {"ok": True, "stopped": stopped}
