import os
import platform
import subprocess
import sys
import time
from collections import deque

import psutil


class ProcessMonitor:

    def __init__(self, lifecycle_store):
        self.lifecycle_store = lifecycle_store

        self.history_data = deque(maxlen=120)

        self.process_seen = set()
        self.process_info_cache = {}

        self.expected_ended = set()
        self.demo_pids = set()

        self.started = False

        self.protected_pids = {
            os.getpid(),
            os.getppid(),
        }

        if hasattr(psutil, "pid_exists") and psutil.pid_exists(1):
            self.protected_pids.add(1)

    # ---------------------------------------------------------
    # Helpers
    # ---------------------------------------------------------

    def _safe(self, function, default=None):
        try:
            return function()
        except Exception:
            return default

    def _event(self, event_type, pid, name=None, **extra):
        event = {
            "type": event_type,
            "pid": int(pid),
            "name": name or "Unknown",
            **extra,
        }

        return self.lifecycle_store.add(event)

    def _process(self, process):
        pid = process.pid

        name = self._safe(process.name, "Unknown")
        username = self._safe(process.username, "Unknown")

        # IMPORTANT:
        # cpu_percent must be passed as a callable.
        cpu = self._safe(
            lambda: process.cpu_percent(interval=None),
            0.0
        )

        memory_mb = self._safe(
            lambda: process.memory_info().rss / (1024 * 1024),
            0.0
        )

        threads = self._safe(
            process.num_threads,
            0
        )

        status = self._safe(
            process.status,
            "unknown"
        )

        parent_pid = self._safe(
            process.ppid,
            0
        )

        create_time = self._safe(
            process.create_time,
            None
        )

        self.process_info_cache[pid] = {
            "pid": pid,
            "name": name,
            "username": username,
            "cpu": round(float(cpu or 0), 2),
            "memory_mb": round(float(memory_mb or 0), 2),
            "threads": int(threads or 0),
            "status": status,
            "parent_pid": parent_pid,
            "create_time": create_time,
        }

        return self.process_info_cache[pid]

    # ---------------------------------------------------------
    # Processes
    # ---------------------------------------------------------

    def list_processes(self):

        current_pids = set()

        processes = []

        for process in psutil.process_iter():

            try:
                current_pids.add(process.pid)

                data = self._process(process)

                if process.pid not in self.process_seen:
                    if self.started:
                        self._event(
                            "started",
                            process.pid,
                            data["name"],
                            parent_pid=data["parent_pid"],
                        )

                    self.process_seen.add(process.pid)

                processes.append(data)

            except (
                psutil.NoSuchProcess,
                psutil.AccessDenied,
                psutil.ZombieProcess,
            ):
                continue

        # Detect ended processes
        ended = self.process_seen - current_pids

        for pid in ended:

            if pid in self.expected_ended:
                self.expected_ended.discard(pid)
                continue

            old = self.process_info_cache.get(pid, {})

            self._event(
                "ended",
                pid,
                old.get("name", "Unknown"),
            )

        self.process_seen.intersection_update(current_pids)

        self.started = True

        processes.sort(
            key=lambda item: item.get("cpu", 0),
            reverse=True,
        )

        return processes

    # ---------------------------------------------------------
    # System
    # ---------------------------------------------------------

    def system_snapshot(self):

        cpu = self._safe(
            lambda: psutil.cpu_percent(interval=0.1),
            0.0,
        )

        memory = self._safe(
            psutil.virtual_memory,
            None,
        )

        disk = self._safe(
            lambda: psutil.disk_usage(os.path.abspath(os.sep)),
            None,
        )

        process_count = len(
            self._safe(
                psutil.pids,
                [],
            )
        )

        snapshot = {
            "cpu": round(float(cpu or 0), 2),
            "memory": round(
                float(memory.percent if memory else 0),
                2,
            ),
            "memory_used_mb": round(
                float(memory.used / (1024 * 1024) if memory else 0),
                2,
            ),
            "memory_total_mb": round(
                float(memory.total / (1024 * 1024) if memory else 0),
                2,
            ),
            "disk": round(
                float(disk.percent if disk else 0),
                2,
            ),
            "disk_used_gb": round(
                float(disk.used / (1024 ** 3) if disk else 0),
                2,
            ),
            "disk_total_gb": round(
                float(disk.total / (1024 ** 3) if disk else 0),
                2,
            ),
            "processes": process_count,
            "os": platform.system(),
            "os_version": platform.version(),
            "machine": platform.machine(),
        }

        self.history_data.append({
            "timestamp": time.time(),
            "cpu": snapshot["cpu"],
            "memory": snapshot["memory"],
            "processes": process_count,
        })

        return snapshot

    def history(self):
        return list(self.history_data)

    # ---------------------------------------------------------
    # Process details
    # ---------------------------------------------------------

    def process_detail(self, pid):

        try:
            process = psutil.Process(pid)

            data = self._process(process)

            data["exe"] = self._safe(
                process.exe,
                "",
            )

            data["cmdline"] = self._safe(
                process.cmdline,
                [],
            )

            data["cwd"] = self._safe(
                process.cwd,
                "",
            )

            data["parent_name"] = self._safe(
                lambda: process.parent().name()
                if process.parent()
                else "",
                "",
            )

            return data

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess,
        ):
            return None

    # ---------------------------------------------------------
    # Process tree
    # ---------------------------------------------------------

    def process_tree(self, pid):
        """Return a live parent/child tree using the current OS process table."""
        try:
            root = psutil.Process(pid)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return None

        # Build PID -> children from the live process table. This is more reliable
        # than asking only the selected process for its direct children.
        children_by_parent = {}
        process_by_pid = {}
        for candidate in psutil.process_iter(["pid", "ppid"]):
            try:
                cpid = candidate.pid
                ppid = candidate.ppid()
                process_by_pid[cpid] = candidate
                children_by_parent.setdefault(ppid, []).append(candidate)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue

        result = []
        visited = set()

        def walk(process, depth=0, parent_pid=None):
            if process.pid in visited:
                return
            visited.add(process.pid)
            try:
                info = self._process(process)
                direct_children = children_by_parent.get(process.pid, [])
                result.append({
                    "pid": process.pid,
                    "name": info["name"],
                    "status": info["status"],
                    "cpu": info["cpu"],
                    "memory_mb": info["memory_mb"],
                    "threads": info["threads"],
                    "parent_pid": parent_pid,
                    "depth": depth,
                    "child_count": len(direct_children),
                })

                direct_children.sort(key=lambda child: child.pid)
                for child in direct_children:
                    walk(child, depth + 1, process.pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        walk(root)
        return {"root_pid": pid, "processes": result, "count": len(result)}

    def termination_check(self, pid):
        """Explain termination risk using the selected process's current state."""
        try:
            process = psutil.Process(pid)
            info = self._process(process)

            # Build the live process relationship map once. This lets us count
            # descendants even when process.children() is incomplete.
            children_by_parent = {}
            for candidate in psutil.process_iter(["pid", "ppid"]):
                try:
                    children_by_parent.setdefault(candidate.ppid(), []).append(candidate)
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    continue

            direct_children = children_by_parent.get(pid, [])
            descendants = []
            queue = list(direct_children)
            visited = set()
            while queue:
                child = queue.pop(0)
                if child.pid in visited:
                    continue
                visited.add(child.pid)
                descendants.append(child)
                queue.extend(children_by_parent.get(child.pid, []))

            parent = self._safe(process.parent, None)
            name = str(info.get("name", "Unknown"))
            name_lower = name.lower()
            status = str(info.get("status", "unknown")).lower()
            cpu = float(info.get("cpu", 0) or 0)
            memory = float(info.get("memory_mb", 0) or 0)

            reasons = []
            cautions = []
            positives = []

            critical_names = {
                "launchd", "kernel_task", "windowserver", "loginwindow",
                "systemd", "init", "system", "smss.exe", "csrss.exe",
                "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe",
            }
            critical = pid in self.protected_pids or name_lower in critical_names

            if critical:
                reasons.append(f"{name} is identified as a protected or critical operating-system process.")
                cautions.append("Terminating it may disrupt essential system services or the operating system.")
            else:
                positives.append("This process is not identified as a protected critical system process.")

            if cpu >= 90:
                reasons.append(f"CPU usage is very high at {cpu:.1f}%.")
            elif cpu >= 80:
                cautions.append(f"CPU usage is elevated at {cpu:.1f}%.")
            else:
                positives.append(f"CPU usage is currently {cpu:.1f}%, below the high-CPU threshold.")

            if memory >= 1024:
                reasons.append(f"Memory usage is high at {memory:.0f} MB.")
            elif memory >= 512:
                cautions.append(f"Memory usage is moderately high at {memory:.0f} MB.")
            else:
                positives.append(f"Memory usage is {memory:.0f} MB, below the 512 MB caution threshold.")

            if direct_children:
                child_names = []
                for child in direct_children[:5]:
                    child_name = self._safe(child.name, "Unknown")
                    child_names.append(f"{child_name} (PID {child.pid})")

                cautions.append(
                    f"It currently has {len(direct_children)} direct child "
                    f"process{'es' if len(direct_children) != 1 else ''}."
                )
                cautions.append(
                    "Direct children: " + ", ".join(child_names)
                    + ("..." if len(direct_children) > 5 else "")
                )

                if len(descendants) > len(direct_children):
                    cautions.append(
                        f"The complete process tree contains {len(descendants)} "
                        f"descendant process{'es' if len(descendants) != 1 else ''}."
                    )
            else:
                positives.append(
                    "No direct child processes are currently attached to this process."
                )

            if parent and parent.pid != 1:
                parent_name = self._safe(parent.name, "Unknown")
                positives.append(
                    f"Parent process: {parent_name} (PID {parent.pid})."
                )
            else:
                positives.append("No non-system parent process was identified.")

            # Do not warn merely because a process is sleeping. Sleeping is a
            # normal state for many healthy applications and system processes.
            if status in {"zombie", "dead"}:
                cautions.append(f"The process currently reports a {status} state.")
            elif status == "stopped":
                cautions.append("The process is currently stopped.")
            else:
                positives.append(f"Current process state: {status}.")

            if critical:
                level = "critical"
                recommendation = "Do not terminate unless you have a specific system-recovery reason."
            elif cpu >= 90 or memory >= 1024:
                level = "warning"
                recommendation = "Use caution: the process is currently consuming significant system resources."
            elif direct_children or status in {"stopped", "zombie", "dead"}:
                level = "warning"
                recommendation = "Use caution: review the process tree and parent relationship before terminating."
            else:
                level = "safe"
                recommendation = "Termination appears low-risk based on the information currently available."

            return {
                "ok": True,
                "pid": pid,
                "name": name,
                "level": level,
                "recommendation": recommendation,
                "reasons": reasons,
                "cautions": cautions,
                "positives": positives,
                "child_count": len(direct_children),
                "descendant_count": len(descendants),
                "parent_pid": parent.pid if parent else None,
                "parent_name": self._safe(parent.name, "Unknown") if parent else None,
                "process": info,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            return {"ok": False, "error": "Process no longer exists or access was denied."}

    # ---------------------------------------------------------
    # Lifecycle
    # ---------------------------------------------------------

    def lifecycle(self):
        return self.lifecycle_store.list()

    # ---------------------------------------------------------
    # Process control
    # ---------------------------------------------------------

    def control(self, pid, action):

        if pid in self.protected_pids:
            return {
                "ok": False,
                "error": "This is a protected Process Guardian/system process.",
            }

        try:
            process = psutil.Process(pid)

            name = self._safe(process.name, "Unknown")

            if action == "suspend":

                process.suspend()

                self._event(
                    "suspended",
                    pid,
                    name,
                )

                return {
                    "ok": True,
                    "message": f"Process {pid} suspended.",
                }

            if action == "resume":

                process.resume()

                self._event(
                    "resumed",
                    pid,
                    name,
                )

                return {
                    "ok": True,
                    "message": f"Process {pid} resumed.",
                }

            if action == "terminate":

                self.expected_ended.add(pid)

                process.terminate()

                try:
                    process.wait(timeout=3)
                except Exception:
                    pass

                self._event(
                    "terminated",
                    pid,
                    name,
                )

                return {
                    "ok": True,
                    "message": f"Process {pid} terminated.",
                }

            return {
                "ok": False,
                "error": "Unsupported action.",
            }

        except psutil.NoSuchProcess:
            return {
                "ok": False,
                "error": "Process no longer exists.",
            }

        except psutil.AccessDenied:
            return {
                "ok": False,
                "error": "Permission denied by the operating system.",
            }

        except Exception as exc:
            return {
                "ok": False,
                "error": str(exc),
            }

    # ---------------------------------------------------------
    # CPU demo
    # ---------------------------------------------------------

    def start_cpu_demo(self):

        try:

            command = [
                sys.executable,
                "-c",
                "while True: pass",
            ]

            process = subprocess.Popen(command)

            self.demo_pids.add(process.pid)

            self._event(
                "demo_started",
                process.pid,
                "Process Guardian CPU Demo",
            )

            return {
                "ok": True,
                "pid": process.pid,
                "message": "CPU demo started.",
            }

        except Exception as exc:

            return {
                "ok": False,
                "error": str(exc),
            }

    def stop_demo(self):

        stopped = []

        for pid in list(self.demo_pids):

            try:

                process = psutil.Process(pid)

                self.expected_ended.add(pid)

                process.terminate()

                try:
                    process.wait(timeout=3)
                except Exception:
                    pass

                stopped.append(pid)

                self._event(
                    "demo_stopped",
                    pid,
                    "Process Guardian CPU Demo",
                )

            except Exception:
                pass

            self.demo_pids.discard(pid)

        return {
            "ok": True,
            "stopped": stopped,
        }