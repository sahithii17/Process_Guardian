import json
import threading
from datetime import datetime, timezone
from pathlib import Path


class LifecycleStore:

    def __init__(self, path, max_events=1000):
        self.path = Path(path)
        self.max_events = max_events
        self.lock = threading.Lock()

        self.path.parent.mkdir(parents=True, exist_ok=True)

        if not self.path.exists():
            self._write([])

    def _read(self):
        try:
            with self.path.open("r", encoding="utf-8") as file:
                data = json.load(file)

            if isinstance(data, list):
                return data

        except Exception:
            pass

        return []

    def _write(self, events):
        temp = self.path.with_suffix(".tmp")

        with temp.open("w", encoding="utf-8") as file:
            json.dump(events, file, indent=2)

        temp.replace(self.path)

    def add(self, event):
        with self.lock:
            events = self._read()

            item = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                **event,
            }

            events.append(item)

            if len(events) > self.max_events:
                events = events[-self.max_events:]

            self._write(events)

            return item

    def list(self, limit=200):
        with self.lock:
            events = self._read()

        return list(reversed(events[-limit:]))

    def count(self):
        with self.lock:
            return len(self._read())

    def clear(self):
        with self.lock:
            self._write([])