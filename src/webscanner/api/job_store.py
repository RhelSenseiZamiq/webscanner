"""Generic async job tracker for streaming scan progress over Server-Sent Events.

Jobs run in a worker thread (via run_in_executor) and call back into the event
loop thread-safely via loop.call_soon_threadsafe so every SSE subscriber
receives real-time progress and log lines.
"""

from __future__ import annotations

import asyncio
import uuid
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


@dataclass
class JobRecord:
    """Tracks a running background scan job with thread-safe SSE fan-out.

    Worker threads call job.progress() / job.log() / job.complete() / job.error().
    SSE consumers call job.subscribe() to get a queue pre-filled with buffered
    events (so late-joiners still see the full history).
    """

    job_id: str
    _loop: asyncio.AbstractEventLoop
    _subscribers: list[asyncio.Queue[dict[str, Any]]] = field(
        default_factory=list, repr=False
    )
    # Buffer stores every event so late subscribers get the full history
    _buffer: list[dict[str, Any]] = field(default_factory=list, repr=False)
    _done: bool = False

    # ------------------------------------------------------------------
    # Thread-safe emit methods (safe to call from worker threads)
    # ------------------------------------------------------------------

    def _broadcast(self, event: dict[str, Any]) -> None:
        """Append to buffer and fan-out to all live subscribers (thread-safe)."""
        self._buffer.append(event)
        if event.get("type") in ("completed", "error"):
            self._done = True
        for q in list(self._subscribers):
            # call_soon_threadsafe is the correct way to push into an asyncio
            # queue from a non-event-loop thread.
            self._loop.call_soon_threadsafe(q.put_nowait, event)

    def log(self, message: str) -> None:
        """Emit a plain log line (no progress-bar update)."""
        self._broadcast({"type": "log", "message": message})

    def progress(self, pct: int, message: str) -> None:
        """Emit a progress update (updates bar + appends to log)."""
        self._broadcast({"type": "progress", "pct": max(0, min(100, pct)), "message": message})

    def complete(self, result: Any) -> None:
        """Emit final completion payload. SSE stream will close after this."""
        self._broadcast({"type": "completed", "result": result})

    def error(self, message: str) -> None:
        """Emit a terminal error. SSE stream will close after this."""
        self._broadcast({"type": "error", "message": message})

    def make_progress_cb(self) -> Callable[[int, str], None]:
        """Return a progress callback safe to invoke from worker threads."""
        def cb(pct: int, message: str) -> None:
            self.progress(pct, message)
        return cb

    # ------------------------------------------------------------------
    # SSE subscription
    # ------------------------------------------------------------------

    def subscribe(self) -> asyncio.Queue[dict[str, Any]]:
        """Create a subscriber queue pre-filled with all buffered events."""
        q: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
        # Replay history so late-connecting clients see everything
        for event in self._buffer:
            q.put_nowait(event)
        self._subscribers.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue[dict[str, Any]]) -> None:
        if q in self._subscribers:
            self._subscribers.remove(q)


class JobStore:
    """In-memory store for running and recently completed scan jobs."""

    MAX_JOBS = 50

    def __init__(self) -> None:
        self._jobs: OrderedDict[str, JobRecord] = OrderedDict()

    def create(self, loop: asyncio.AbstractEventLoop) -> JobRecord:
        job_id = str(uuid.uuid4())
        record = JobRecord(job_id=job_id, _loop=loop)
        self._jobs[job_id] = record
        if len(self._jobs) > self.MAX_JOBS:
            self._jobs.popitem(last=False)
        return record

    def get(self, job_id: str) -> JobRecord | None:
        return self._jobs.get(job_id)
