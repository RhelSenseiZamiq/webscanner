"""WPA/WPA2 password strength auditor.

Tests the strength of your own WiFi network password by running a
dictionary attack against a captured WPA handshake file (.cap or .hc22000).

How to capture your own handshake (Linux + wireless card that supports monitor mode):
    sudo airmon-ng start wlan0
    sudo airodump-ng -c <channel> --bssid <your-AP-mac> -w capture wlan0mon
    # Wait for a client to connect, or reconnect your own device
    sudo airmon-ng stop wlan0mon

Then audit it:
    webscanner wifi-audit --capture capture-01.cap --wordlist wordlists/rockyou.txt

This module does NOT perform deauthentication, packet injection, or
any active wireless attacks. It only reads .cap/.hc22000 files you provide.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger("webscanner.wifi.wpa_audit")

_WORDLISTS_DIR = Path(__file__).parent.parent.parent.parent.parent / "wordlists"
_DEFAULT_WORDLIST = _WORDLISTS_DIR / "wifi-passwords.txt"
_BUILTIN_FALLBACK = _WORDLISTS_DIR / "common_passwords.txt"


@dataclass(frozen=True)
class WPAAuditResult:
    """Immutable result of a WPA password audit."""

    capture_file: str
    wordlist_used: str
    password_found: bool
    password: str | None         # None if not found
    tool_used: str               # "aircrack-ng" or "hashcat"
    keys_tested: int
    duration_seconds: float
    error: str | None = None


def audit_capture(
    capture_file: Path,
    wordlist: Path | None = None,
    bssid: str | None = None,
) -> WPAAuditResult:
    """Run a dictionary attack against a .cap or .hc22000 file.

    Args:
        capture_file: Path to the .cap (pcap) or .hc22000 (hashcat format) file.
        wordlist: Path to the password wordlist. Defaults to the wifi-passwords wordlist.
        bssid: Optional BSSID (MAC) to target a specific AP in a multi-AP capture.

    Returns:
        WPAAuditResult with the outcome.
    """
    if not capture_file.exists():
        return WPAAuditResult(
            capture_file=str(capture_file),
            wordlist_used="",
            password_found=False,
            password=None,
            tool_used="none",
            keys_tested=0,
            duration_seconds=0.0,
            error=f"Capture file not found: {capture_file}",
        )

    effective_wordlist = _resolve_wordlist(wordlist)
    if not effective_wordlist.exists():
        return WPAAuditResult(
            capture_file=str(capture_file),
            wordlist_used=str(effective_wordlist),
            password_found=False,
            password=None,
            tool_used="none",
            keys_tested=0,
            duration_seconds=0.0,
            error=(
                f"Wordlist not found: {effective_wordlist}. "
                "Run: python wordlists/download_wordlists.py"
            ),
        )

    # Choose tool based on file type and availability
    is_hc22000 = capture_file.suffix.lower() in (".hc22000", ".22000")

    if not is_hc22000 and shutil.which("aircrack-ng"):
        return _run_aircrack(capture_file, effective_wordlist, bssid)
    elif shutil.which("hashcat"):
        return _run_hashcat(capture_file, effective_wordlist, is_hc22000)
    else:
        return WPAAuditResult(
            capture_file=str(capture_file),
            wordlist_used=str(effective_wordlist),
            password_found=False,
            password=None,
            tool_used="none",
            keys_tested=0,
            duration_seconds=0.0,
            error=(
                "No cracking tool found. Install one of:\n"
                "  macOS:  brew install aircrack-ng\n"
                "  Linux:  sudo apt install aircrack-ng  (or hashcat)\n"
                "  Docker: docker-compose -f docker-compose.cracker.yml run cracker"
            ),
        )


def _resolve_wordlist(wordlist: Path | None) -> Path:
    if wordlist:
        return wordlist
    if _DEFAULT_WORDLIST.exists():
        return _DEFAULT_WORDLIST
    return _BUILTIN_FALLBACK


# ---------------------------------------------------------------------------
# aircrack-ng backend
# ---------------------------------------------------------------------------

def _run_aircrack(
    capture: Path, wordlist: Path, bssid: str | None
) -> WPAAuditResult:
    started = time.monotonic()
    cmd = ["aircrack-ng", "-w", str(wordlist)]
    if bssid:
        cmd += ["-b", bssid]
    cmd.append(str(capture))

    logger.info("Running: %s", " ".join(cmd))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        output = proc.stdout + proc.stderr
        duration = time.monotonic() - started

        password = _extract_aircrack_password(output)
        keys_tested = _extract_aircrack_keys(output)

        return WPAAuditResult(
            capture_file=str(capture),
            wordlist_used=str(wordlist),
            password_found=password is not None,
            password=password,
            tool_used="aircrack-ng",
            keys_tested=keys_tested,
            duration_seconds=duration,
        )

    except subprocess.TimeoutExpired:
        return WPAAuditResult(
            capture_file=str(capture),
            wordlist_used=str(wordlist),
            password_found=False,
            password=None,
            tool_used="aircrack-ng",
            keys_tested=0,
            duration_seconds=time.monotonic() - started,
            error="Timed out after 1 hour",
        )
    except Exception as e:
        return WPAAuditResult(
            capture_file=str(capture),
            wordlist_used=str(wordlist),
            password_found=False,
            password=None,
            tool_used="aircrack-ng",
            keys_tested=0,
            duration_seconds=time.monotonic() - started,
            error=str(e),
        )


def _extract_aircrack_password(output: str) -> str | None:
    """Parse aircrack-ng output for a found KEY."""
    for line in output.splitlines():
        if "KEY FOUND!" in line:
            # Line format: KEY FOUND! [ thepassword ]
            start = line.find("[")
            end = line.find("]")
            if start != -1 and end != -1:
                return line[start + 1:end].strip()
    return None


def _extract_aircrack_keys(output: str) -> int:
    """Parse the number of keys tested from aircrack-ng output."""
    import re
    for line in output.splitlines():
        m = re.search(r"(\d[\d,]+)\s+keys tested", line)
        if m:
            return int(m.group(1).replace(",", ""))
    return 0


# ---------------------------------------------------------------------------
# hashcat backend (for .hc22000 or when aircrack-ng is absent)
# ---------------------------------------------------------------------------

def _run_hashcat(
    capture: Path, wordlist: Path, is_hc22000: bool
) -> WPAAuditResult:
    started = time.monotonic()
    # Mode 22000 = WPA-PBKDF2-PMKID+EAPOL  (new format)
    # Mode 2500  = WPA-EAPOL-PBKDF2         (legacy .hccapx)
    hash_mode = "22000" if is_hc22000 else "2500"
    potfile = capture.with_suffix(".pot")

    cmd = [
        "hashcat",
        f"-m{hash_mode}",
        str(capture),
        str(wordlist),
        "--potfile-path", str(potfile),
        "--status",
        "--status-timer=10",
        "-O",               # optimized kernels
        "--quiet",
    ]

    logger.info("Running: %s", " ".join(cmd))

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
        output = proc.stdout + proc.stderr
        duration = time.monotonic() - started

        password = _extract_hashcat_password(potfile)
        return WPAAuditResult(
            capture_file=str(capture),
            wordlist_used=str(wordlist),
            password_found=password is not None,
            password=password,
            tool_used="hashcat",
            keys_tested=_extract_hashcat_keys(output),
            duration_seconds=duration,
        )

    except subprocess.TimeoutExpired:
        return WPAAuditResult(
            capture_file=str(capture),
            wordlist_used=str(wordlist),
            password_found=False, password=None,
            tool_used="hashcat", keys_tested=0,
            duration_seconds=time.monotonic() - started,
            error="Timed out after 1 hour",
        )
    except Exception as e:
        return WPAAuditResult(
            capture_file=str(capture),
            wordlist_used=str(wordlist),
            password_found=False, password=None,
            tool_used="hashcat", keys_tested=0,
            duration_seconds=time.monotonic() - started,
            error=str(e),
        )


def _extract_hashcat_password(potfile: Path) -> str | None:
    """Read the hashcat potfile for a cracked password."""
    if not potfile.exists():
        return None
    with open(potfile) as f:
        for line in f:
            line = line.strip()
            if ":" in line:
                # potfile format: hash:password
                parts = line.split(":")
                if len(parts) >= 2:
                    return parts[-1]
    return None


def _extract_hashcat_keys(output: str) -> int:
    import re
    for line in output.splitlines():
        m = re.search(r"Progress\.+:\s*(\d+)/", line)
        if m:
            return int(m.group(1))
    return 0
