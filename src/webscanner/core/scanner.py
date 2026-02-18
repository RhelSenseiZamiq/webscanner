"""Scanner protocol that all scan modules must implement."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from webscanner.core.types import ModuleResult, ScanTarget


@runtime_checkable
class Scanner(Protocol):
    """Protocol that all scan modules must satisfy."""

    async def scan(self, target: ScanTarget) -> ModuleResult:
        """Execute the scan and return an immutable result."""
        ...

    @property
    def module_name(self) -> str:
        """Identify which module this scanner implements."""
        ...

    @property
    def is_active_probe(self) -> bool:
        """Whether this scanner sends active exploit payloads."""
        ...
