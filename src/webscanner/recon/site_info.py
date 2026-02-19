"""Site information gatherer — collects a full technical profile of a target website."""

from __future__ import annotations

import asyncio
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from webscanner.core.http_client import ScopedHttpClient
from webscanner.core.types import ScanTarget

logger = logging.getLogger("webscanner.recon.site_info")

# Known CDN/hosting signatures detected from response headers
_CDN_SIGNATURES: tuple[tuple[str, str], ...] = (
    ("cf-ray", "Cloudflare"),
    ("x-amz-cf-id", "Amazon CloudFront"),
    ("x-cache", "Fastly"),
    ("x-served-by", "Fastly"),
    ("x-azure-ref", "Azure CDN"),
    ("x-akamai-transformed", "Akamai"),
    ("x-sucuri-id", "Sucuri"),
    ("x-varnish", "Varnish"),
    ("x-powered-by-plesk", "Plesk"),
)


@dataclass(frozen=True)
class SiteInfo:
    """Immutable technical profile of a scanned website."""

    # HTTP basics
    final_url: str
    status_code: int
    response_time_ms: float
    redirect_chain: tuple[str, ...]

    # Server & hosting
    server: str | None
    powered_by: str | None
    ip_address: str | None
    cdn: str | None

    # Page metadata
    title: str | None
    description: str | None
    favicon_url: str | None
    language: str | None
    og_title: str | None
    og_description: str | None

    # Technology stack (populated from fingerprint module findings)
    technologies: tuple[str, ...]

    # SSL certificate
    ssl_issuer: str | None
    ssl_subject: str | None
    ssl_expiry: str | None          # ISO date string
    ssl_days_remaining: int | None
    ssl_sans: tuple[str, ...]

    # DNS records
    dns_a: tuple[str, ...]
    dns_mx: tuple[str, ...]
    dns_ns: tuple[str, ...]
    dns_txt: tuple[str, ...]

    # Crawl files
    has_robots_txt: bool
    robots_txt_preview: str | None   # first 500 chars
    has_sitemap: bool

    # Full HTTP response headers
    response_headers: dict[str, str] = field(default_factory=dict)


class SiteInfoGatherer:
    """Collects a comprehensive technical profile of a target site."""

    def __init__(self, http_client: ScopedHttpClient) -> None:
        self._http = http_client

    async def gather(self, target: ScanTarget) -> SiteInfo:
        """Collect all site information. Best-effort — individual failures are caught."""
        base_url = target.base_url

        # Run HTTP fetch, SSL, DNS, and file checks concurrently
        (
            http_result,
            ssl_result,
            dns_result,
            files_result,
        ) = await asyncio.gather(
            self._fetch_page(base_url),
            self._resolve_ssl(base_url),
            self._resolve_dns(base_url),
            self._check_files(base_url),
            return_exceptions=True,
        )

        # Unpack HTTP result (status, headers, body, redirect_chain, response_time_ms)
        if isinstance(http_result, Exception):
            logger.debug("Site info HTTP fetch failed: %s", http_result)
            http_result = (0, {}, "", (), 0.0)

        status_code, raw_headers, body, redirect_chain, response_time_ms = http_result

        # Parse metadata from HTML body
        metadata = _parse_metadata(body, base_url)

        # Server / CDN
        server = raw_headers.get("server") or raw_headers.get("Server")
        powered_by = raw_headers.get("x-powered-by") or raw_headers.get("X-Powered-By")
        cdn = _detect_cdn(raw_headers)

        # Normalise headers to lowercase keys, string values
        response_headers = {k.lower(): str(v) for k, v in raw_headers.items()}

        # Unpack SSL
        if isinstance(ssl_result, Exception):
            logger.debug("Site info SSL resolution failed: %s", ssl_result)
            ssl_result = (None, None, None, None, ())
        ssl_issuer, ssl_subject, ssl_expiry, ssl_days_remaining, ssl_sans = ssl_result

        # Unpack DNS
        if isinstance(dns_result, Exception):
            logger.debug("Site info DNS resolution failed: %s", dns_result)
            dns_result = ((), (), (), ())
        dns_a, dns_mx, dns_ns, dns_txt = dns_result

        # Unpack file checks
        if isinstance(files_result, Exception):
            logger.debug("Site info file checks failed: %s", files_result)
            files_result = (False, None, False)
        has_robots_txt, robots_txt_preview, has_sitemap = files_result

        # IP address (first A record or resolved from hostname)
        ip_address: str | None = dns_a[0] if dns_a else None
        if not ip_address:
            try:
                hostname = urlparse(base_url).hostname or ""
                ip_address = socket.gethostbyname(hostname)
            except Exception:
                pass

        return SiteInfo(
            final_url=redirect_chain[-1] if redirect_chain else base_url,
            status_code=status_code,
            response_time_ms=round(response_time_ms, 1),
            redirect_chain=redirect_chain,
            server=_clean(server),
            powered_by=_clean(powered_by),
            ip_address=ip_address,
            cdn=cdn,
            title=metadata.get("title"),
            description=metadata.get("description"),
            favicon_url=metadata.get("favicon_url"),
            language=metadata.get("language"),
            og_title=metadata.get("og_title"),
            og_description=metadata.get("og_description"),
            technologies=(),   # filled by orchestrator from fingerprint results
            ssl_issuer=ssl_issuer,
            ssl_subject=ssl_subject,
            ssl_expiry=ssl_expiry,
            ssl_days_remaining=ssl_days_remaining,
            ssl_sans=ssl_sans,
            dns_a=dns_a,
            dns_mx=dns_mx,
            dns_ns=dns_ns,
            dns_txt=dns_txt,
            has_robots_txt=has_robots_txt,
            robots_txt_preview=robots_txt_preview,
            has_sitemap=has_sitemap,
            response_headers=response_headers,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    async def _fetch_page(
        self, url: str
    ) -> tuple[int, dict[str, str], str, tuple[str, ...], float]:
        """Fetch the main page and return (status, headers, body, redirect_chain, ms)."""
        start = time.monotonic()
        redirect_chain: list[str] = []
        status = 0
        headers: dict[str, str] = {}
        body = ""

        try:
            async with self._http.get(url) as resp:
                elapsed_ms = (time.monotonic() - start) * 1000
                status = resp.status
                headers = dict(resp.headers)
                # Collect redirect history
                for r in resp.history:
                    redirect_chain.append(str(r.url))
                redirect_chain.append(str(resp.url))
                # Read up to 512 KB of body for metadata parsing
                raw = await resp.read()
                body = raw[:524288].decode("utf-8", errors="replace")
        except Exception as exc:
            elapsed_ms = (time.monotonic() - start) * 1000
            logger.debug("Page fetch error for %s: %s", url, exc)

        return status, headers, body, tuple(redirect_chain), elapsed_ms

    async def _resolve_ssl(
        self, url: str
    ) -> tuple[str | None, str | None, str | None, int | None, tuple[str, ...]]:
        """Resolve SSL certificate details. Returns (issuer, subject, expiry_iso, days, sans)."""
        parsed = urlparse(url)
        if parsed.scheme != "https":
            return None, None, None, None, ()

        hostname = parsed.hostname or ""
        port = parsed.port or 443

        def _get_cert() -> tuple[str | None, str | None, str | None, int | None, tuple[str, ...]]:
            try:
                context = ssl.create_default_context()
                with socket.create_connection((hostname, port), timeout=10) as sock:
                    with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()

                if not cert:
                    return None, None, None, None, ()

                # Subject
                subject_dict = dict(x[0] for x in cert.get("subject", ()))
                subject = subject_dict.get("commonName")

                # Issuer
                issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
                issuer = issuer_dict.get("organizationName") or issuer_dict.get("commonName")

                # Expiry
                not_after_str = cert.get("notAfter", "")
                expiry_dt: datetime | None = None
                if not_after_str:
                    try:
                        expiry_dt = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(
                            tzinfo=timezone.utc
                        )
                    except ValueError:
                        pass

                expiry_iso = expiry_dt.isoformat() if expiry_dt else None
                days_remaining: int | None = None
                if expiry_dt:
                    delta = expiry_dt - datetime.now(timezone.utc)
                    days_remaining = max(0, delta.days)

                # SANs
                sans: list[str] = []
                for san_type, san_value in cert.get("subjectAltName", ()):
                    if san_type == "DNS":
                        sans.append(san_value)

                return issuer, subject, expiry_iso, days_remaining, tuple(sans)

            except Exception as exc:
                logger.debug("SSL cert resolution failed for %s: %s", hostname, exc)
                return None, None, None, None, ()

        return await asyncio.get_event_loop().run_in_executor(None, _get_cert)

    async def _resolve_dns(
        self, url: str
    ) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
        """Resolve DNS records. Returns (A, MX, NS, TXT)."""
        hostname = urlparse(url).hostname or ""
        if not hostname:
            return (), (), (), ()

        def _lookup() -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
            a_records: list[str] = []
            mx_records: list[str] = []
            ns_records: list[str] = []
            txt_records: list[str] = []

            # A records via standard socket
            try:
                info = socket.getaddrinfo(hostname, None, socket.AF_INET)
                seen: set[str] = set()
                for entry in info:
                    ip = entry[4][0]
                    if ip not in seen:
                        seen.add(ip)
                        a_records.append(ip)
            except Exception:
                pass

            # MX / NS / TXT via dnspython (soft dependency)
            try:
                import dns.resolver  # type: ignore[import]
                resolver = dns.resolver.Resolver()
                resolver.lifetime = 5.0

                for rtype, target_list in (("MX", mx_records), ("NS", ns_records), ("TXT", txt_records)):
                    try:
                        answers = resolver.resolve(hostname, rtype)
                        for rdata in answers:
                            target_list.append(str(rdata).rstrip("."))
                    except Exception:
                        pass
            except ImportError:
                pass  # dnspython not installed — A records only

            return tuple(a_records), tuple(mx_records), tuple(ns_records), tuple(txt_records)

        return await asyncio.get_event_loop().run_in_executor(None, _lookup)

    async def _check_files(self, base_url: str) -> tuple[bool, str | None, bool]:
        """Check for robots.txt and sitemap.xml. Returns (has_robots, preview, has_sitemap)."""
        robots_url = urljoin(base_url, "/robots.txt")
        sitemap_url = urljoin(base_url, "/sitemap.xml")

        has_robots = False
        robots_preview: str | None = None
        has_sitemap = False

        async def _check(url: str) -> tuple[bool, str | None]:
            try:
                async with self._http.get(url) as resp:
                    if resp.status == 200:
                        raw = await resp.read()
                        text = raw[:500].decode("utf-8", errors="replace")
                        return True, text
            except Exception:
                pass
            return False, None

        robots_result, sitemap_result = await asyncio.gather(
            _check(robots_url), _check(sitemap_url), return_exceptions=True
        )

        if not isinstance(robots_result, Exception) and robots_result[0]:
            has_robots, robots_preview = robots_result

        if not isinstance(sitemap_result, Exception) and sitemap_result[0]:
            has_sitemap = True

        return has_robots, robots_preview, has_sitemap


# ---------------------------------------------------------------------------
# Module-level helpers (pure functions)
# ---------------------------------------------------------------------------

def _parse_metadata(html: str, base_url: str) -> dict[str, str | None]:
    """Extract page metadata from HTML body."""
    result: dict[str, str | None] = {
        "title": None, "description": None, "favicon_url": None,
        "language": None, "og_title": None, "og_description": None,
    }
    if not html:
        return result

    try:
        soup = BeautifulSoup(html, "html.parser")

        # Title
        tag = soup.find("title")
        if tag and tag.string:
            result["title"] = tag.string.strip()[:200]

        # Language
        html_tag = soup.find("html")
        if html_tag and html_tag.get("lang"):  # type: ignore[union-attr]
            result["language"] = str(html_tag["lang"])[:20]  # type: ignore[index]

        # Meta tags
        for meta in soup.find_all("meta"):
            name = (meta.get("name") or meta.get("property") or "").lower()
            content = meta.get("content", "")
            if not content:
                continue
            if name == "description":
                result["description"] = str(content)[:300]
            elif name == "og:title":
                result["og_title"] = str(content)[:200]
            elif name == "og:description":
                result["og_description"] = str(content)[:300]

        # Favicon
        for rel in ("shortcut icon", "icon", "apple-touch-icon"):
            link = soup.find("link", rel=lambda r: r and rel in " ".join(r).lower())  # type: ignore[arg-type]
            if link and link.get("href"):  # type: ignore[union-attr]
                href = str(link["href"])  # type: ignore[index]
                if href.startswith("http"):
                    result["favicon_url"] = href
                else:
                    result["favicon_url"] = urljoin(base_url, href)
                break

    except Exception as exc:
        logger.debug("Metadata parsing error: %s", exc)

    return result


def _detect_cdn(headers: dict[str, str]) -> str | None:
    """Detect CDN/reverse proxy from response headers."""
    lowered = {k.lower(): v for k, v in headers.items()}
    for header_key, cdn_name in _CDN_SIGNATURES:
        if header_key in lowered:
            return cdn_name
    return None


def _clean(value: str | None) -> str | None:
    """Strip and return None for empty strings."""
    if not value:
        return None
    stripped = value.strip()
    return stripped if stripped else None


def with_technologies(info: SiteInfo, technologies: tuple[str, ...]) -> SiteInfo:
    """Return a new SiteInfo with the technologies field replaced (immutable update)."""
    return SiteInfo(
        final_url=info.final_url,
        status_code=info.status_code,
        response_time_ms=info.response_time_ms,
        redirect_chain=info.redirect_chain,
        server=info.server,
        powered_by=info.powered_by,
        ip_address=info.ip_address,
        cdn=info.cdn,
        title=info.title,
        description=info.description,
        favicon_url=info.favicon_url,
        language=info.language,
        og_title=info.og_title,
        og_description=info.og_description,
        technologies=technologies,
        ssl_issuer=info.ssl_issuer,
        ssl_subject=info.ssl_subject,
        ssl_expiry=info.ssl_expiry,
        ssl_days_remaining=info.ssl_days_remaining,
        ssl_sans=info.ssl_sans,
        dns_a=info.dns_a,
        dns_mx=info.dns_mx,
        dns_ns=info.dns_ns,
        dns_txt=info.dns_txt,
        has_robots_txt=info.has_robots_txt,
        robots_txt_preview=info.robots_txt_preview,
        has_sitemap=info.has_sitemap,
        response_headers=info.response_headers,
    )
