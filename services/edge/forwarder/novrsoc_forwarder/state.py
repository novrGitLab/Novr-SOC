"""Durable forwarder state: checkpoint, single-instance lock and dead letters (all under FORWARDER_STATE_DIR).

cursor.json (checkpoint v2, compatible with the legacy format):
  {"version": 2, "last_forwarded_timestamp": "<ISO>", "search_after": [<timestamp ms>, "<alert id>"], "saved_at": "<ISO>"}
It records the position of the last alert in a page the API ACKNOWLEDGED. Writes are atomic and durable
(temporary file, fsync, rename, directory fsync on POSIX), so a crash leaves either the old or the new checkpoint.
dead-letters.jsonl: alert ids that can never be valid, with a reason. Never the alert content.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from typing import Optional

from .logs import log


class Checkpoint:
    def __init__(self, ts: datetime, sort: Optional[list] = None):
        self.ts, self.sort = ts, sort


class LockError(Exception):
    pass


class State:
    def __init__(self, directory: str):
        self.dir = directory
        os.makedirs(directory, mode=0o700, exist_ok=True)
        self.cursor = os.path.join(directory, "cursor.json")
        self.dead = os.path.join(directory, "dead-letters.jsonl")
        self._lock_fh = None

    # ---- single instance ------------------------------------------------------------------------
    def lock(self) -> None:
        fh = open(os.path.join(self.dir, "forwarder.lock"), "a+")
        try:
            try:
                import fcntl
                fcntl.flock(fh.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except ImportError:  # Windows (development only)
                import msvcrt
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
        except OSError:
            fh.close()
            raise LockError("another forwarder instance holds the state directory lock") from None
        self._lock_fh = fh

    def unlock(self) -> None:
        if self._lock_fh is not None:
            self._lock_fh.close()
            self._lock_fh = None

    # ---- checkpoint -----------------------------------------------------------------------------
    def load(self) -> Optional[Checkpoint]:
        try:
            with open(self.cursor, encoding="utf-8") as f:
                data = json.load(f)
        except FileNotFoundError:
            return None
        except (OSError, ValueError):
            log("error", "cursor_unreadable", path=self.cursor)
            raise
        from .core import parse_ts, valid_sort  # local import: core imports this module
        if not isinstance(data, dict):
            raise ValueError("cursor file is not an object")
        sort = valid_sort(data.get("search_after"))
        ts = (datetime.fromtimestamp(sort[0] / 1000, tz=timezone.utc) if sort
              else parse_ts(str(data.get("last_forwarded_timestamp") or "")))
        if ts is None:
            raise ValueError("cursor file has no usable position")
        return Checkpoint(ts, sort)

    def save(self, cp: Checkpoint) -> None:
        body = {"version": 2, "last_forwarded_timestamp": cp.ts.isoformat(),
                "saved_at": datetime.now(timezone.utc).isoformat()}
        if cp.sort:
            body["search_after"] = cp.sort
        tmp = f"{self.cursor}.tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(body, f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.cursor)
        if hasattr(os, "O_DIRECTORY"):
            fd = os.open(self.dir, os.O_DIRECTORY)
            try:
                os.fsync(fd)
            finally:
                os.close(fd)

    # ---- dead letters ---------------------------------------------------------------------------
    def dead_letter(self, alert_id: str, reason: str, batch_id: Optional[str]) -> None:
        line = json.dumps({"at": datetime.now(timezone.utc).isoformat(), "alert_id": str(alert_id)[:200],
                           "reason": reason, "batch_id": batch_id})
        with open(self.dead, "a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            os.fsync(f.fileno())
        log("warning", "dead_letter", alert_id=str(alert_id)[:200], reason=reason)
