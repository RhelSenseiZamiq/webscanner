"""REST and GraphQL API endpoint discovery scanner."""

from __future__ import annotations

import asyncio
import json
import time
from dataclasses import dataclass

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import Finding, ModuleResult, ScanModule, ScanTarget, Severity

API_PATHS: tuple[str, ...] = (
    "/api", "/api/v1", "/api/v2", "/api/v3",
    "/rest", "/v1", "/v2",
    "/swagger.json", "/swagger/v1/swagger.json",
    "/openapi.json", "/openapi.yaml",
    "/api-docs", "/docs", "/redoc",
    "/graphql", "/graphiql",
    "/.well-known/openapi",
)

GRAPHQL_INTROSPECTION_QUERY = '{"query": "{ __schema { types { name } } }"}'


@dataclass(frozen=True)
class EndpointDiscoveryScanner:
    """Discovers REST and GraphQL API endpoints."""

    http_client: ScopedHttpClient
    concurrency: int = 5

    @property
    def module_name(self) -> str:
        return "endpoint_discovery"

    @property
    def is_active_probe(self) -> bool:
        return True

    async def scan(self, target: ScanTarget) -> ModuleResult:
        start = time.monotonic()
        findings: list[Finding] = []
        semaphore = asyncio.Semaphore(self.concurrency)

        async def check_path(path: str) -> Finding | None:
            url = f"{target.base_url.rstrip('/')}{path}"
            async with semaphore:
                try:
                    response = await self.http_client.get(url)
                    if response.status in (200, 301, 302):
                        return Finding(
                            module=ScanModule.API_SECURITY,
                            check_name="api_endpoint_found",
                            severity=Severity.INFO,
                            title=f"API endpoint: {path} (HTTP {response.status})",
                            description=f"API endpoint discovered at {path}.",
                            url=url,
                            evidence=f"HTTP {response.status}",
                            remediation="Ensure API endpoints are properly authenticated and documented.",
                        )
                except Exception:
                    pass
            return None

        tasks = [check_path(path) for path in API_PATHS]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Finding):
                findings.append(result)

        graphql_findings = await self._check_graphql_introspection(target, semaphore)
        findings.extend(graphql_findings)

        openapi_findings = await self._check_openapi_spec(target, semaphore)
        findings.extend(openapi_findings)

        return ModuleResult(
            module=ScanModule.API_SECURITY,
            findings=tuple(findings),
            duration_seconds=time.monotonic() - start,
            urls_scanned=len(API_PATHS),
        )

    async def _check_graphql_introspection(
        self, target: ScanTarget, semaphore: asyncio.Semaphore
    ) -> list[Finding]:
        findings: list[Finding] = []
        graphql_url = f"{target.base_url.rstrip('/')}/graphql"

        async with semaphore:
            try:
                response = await self.http_client.post(
                    graphql_url,
                    data=GRAPHQL_INTROSPECTION_QUERY,
                    headers={"Content-Type": "application/json"},
                )
                if response.status == 200:
                    body = await response.text()
                    if "__schema" in body:
                        findings.append(
                            Finding(
                                module=ScanModule.API_SECURITY,
                                check_name="graphql_introspection",
                                severity=Severity.MEDIUM,
                                title="GraphQL introspection enabled",
                                description="GraphQL introspection query succeeds, exposing the full schema.",
                                url=graphql_url,
                                evidence="Introspection query returned __schema",
                                remediation="Disable GraphQL introspection in production.",
                                cwe_id="CWE-200",
                            )
                        )
            except Exception:
                pass

        return findings

    async def _check_openapi_spec(
        self, target: ScanTarget, semaphore: asyncio.Semaphore
    ) -> list[Finding]:
        findings: list[Finding] = []
        spec_paths = ("/swagger.json", "/openapi.json")

        for path in spec_paths:
            url = f"{target.base_url.rstrip('/')}{path}"
            async with semaphore:
                try:
                    response = await self.http_client.get(url)
                    if response.status == 200:
                        body = await response.text()
                        try:
                            spec = json.loads(body)
                            if "paths" in spec or "openapi" in spec or "swagger" in spec:
                                endpoint_count = len(spec.get("paths", {}))
                                findings.append(
                                    Finding(
                                        module=ScanModule.API_SECURITY,
                                        check_name="openapi_spec_exposed",
                                        severity=Severity.LOW,
                                        title=f"OpenAPI spec exposed at {path}",
                                        description=f"API specification with {endpoint_count} endpoints publicly accessible.",
                                        url=url,
                                        evidence=f"Found {endpoint_count} paths in spec",
                                        remediation="Restrict access to API documentation in production if not intended.",
                                    )
                                )
                        except json.JSONDecodeError:
                            pass
                except Exception:
                    pass

        return findings
