"""Passive WiFi network scanner.

Uses native OS tools to discover nearby wireless networks without
sending any packets — reads what the OS already knows from beacon frames.

Supported platforms:
  - macOS  → airport -s -x  (XML output)
  - Linux  → nmcli -f ... dev wifi list  or  iwlist scan
  - Windows → netsh wlan show networks mode=bssid  (basic)
"""

from __future__ import annotations

import json
import logging
import os
import platform
import plistlib
import re
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass, field

logger = logging.getLogger("webscanner.wifi.scanner")

_AIRPORT_PATH = (
    "/System/Library/PrivateFrameworks/Apple80211.framework"
    "/Versions/Current/Resources/airport"
)


@dataclass(frozen=True)
class WiFiNetwork:
    """Immutable snapshot of a discovered wireless network."""

    ssid: str
    bssid: str
    signal_dbm: int
    channel: int
    security: str          # e.g. "WPA2 Personal", "WEP", "Open", "WPA3"
    wps_enabled: bool = False
    band: str = "2.4GHz"   # "2.4GHz" or "5GHz"
    vendor: str = ""       # OUI lookup result if available


@dataclass
class WiFiScanResult:
    """Mutable container — filled as scan progresses, then frozen."""

    networks: list[WiFiNetwork] = field(default_factory=list)
    scan_duration_seconds: float = 0.0
    platform: str = ""
    error: str | None = None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def get_preferred_networks(interface: str = "en0") -> list[str]:
    """Return SSIDs of all saved/preferred WiFi networks (no Location Services needed).

    Uses `networksetup -listpreferredwirelessnetworks` on macOS, which always
    returns real network names regardless of Location Services status.

    Returns an empty list on non-macOS platforms or on any error.
    """
    if platform.system() != "Darwin":
        return []
    try:
        proc = subprocess.run(
            ["networksetup", "-listpreferredwirelessnetworks", interface],
            capture_output=True, text=True, timeout=5,
        )
        # Output:
        #   Preferred networks on en0:
        #           NetworkName1
        #           NetworkName2
        lines = proc.stdout.splitlines()
        return [line.strip() for line in lines[1:] if line.strip()]
    except Exception:
        return []


def scan_networks(
    on_progress: Callable[[int, str], None] | None = None,
) -> WiFiScanResult:
    """Perform a passive WiFi scan using OS-native tools.

    Args:
        on_progress: Optional callback(pct, message) called at each step.

    Returns a WiFiScanResult. On error, result.error is set and
    result.networks is empty.
    """
    def emit(pct: int, msg: str) -> None:
        if on_progress:
            on_progress(pct, msg)

    result = WiFiScanResult(platform=platform.system())
    started = time.monotonic()

    emit(0, "Starting passive WiFi scan…")

    try:
        system = platform.system()
        emit(15, f"Detected platform: {system} — querying wireless interface…")
        if system == "Darwin":
            result.networks = _scan_macos(emit)
        elif system == "Linux":
            result.networks = _scan_linux()
        elif system == "Windows":
            result.networks = _scan_windows()
        else:
            result.error = f"Unsupported platform: {system}"
        emit(80, f"Raw scan returned {len(result.networks)} network(s)")

        # Emit network type breakdown
        if result.networks:
            open_n  = sum(1 for n in result.networks if not n.security or n.security.upper() in ("OPEN", "NONE", "--", "ESS", ""))
            wep_n   = sum(1 for n in result.networks if "WEP" in n.security.upper())
            wpa3_n  = sum(1 for n in result.networks if "WPA3" in n.security.upper())
            wpa2_n  = sum(1 for n in result.networks if "WPA2" in n.security.upper())
            wps_n   = sum(1 for n in result.networks if n.wps_enabled)
            emit(82, (
                f"Breakdown: {open_n} open, {wep_n} WEP, "
                f"{wpa2_n} WPA2, {wpa3_n} WPA3, {wps_n} WPS-enabled"
            ))
    except FileNotFoundError as e:
        result.error = f"Required tool not found: {e}. Install the needed package."
        emit(80, f"Error: {result.error}")
    except PermissionError:
        result.error = (
            "Permission denied. WiFi scanning may require root/admin privileges. "
            "Try: sudo python -m webscanner wifi"
        )
        emit(80, f"Error: {result.error}")
    except Exception as e:
        logger.exception("WiFi scan failed")
        result.error = str(e)
        emit(80, f"Error: {result.error}")
    finally:
        result.scan_duration_seconds = time.monotonic() - started

    network_word = "network" if len(result.networks) == 1 else "networks"
    emit(90, f"Parsing complete — {len(result.networks)} {network_word} found")

    logger.info(
        "WiFi scan complete: %d networks found in %.1fs",
        len(result.networks), result.scan_duration_seconds,
    )
    return result


# ---------------------------------------------------------------------------
# macOS via system_profiler (macOS 14+) with airport fallback (macOS 13-)
# ---------------------------------------------------------------------------

# Internal key → human-readable security label
_SECURITY_MODE_MAP: dict[str, str] = {
    "spairport_security_mode_none": "Open",
    "spairport_security_mode_wep": "WEP",
    "spairport_security_mode_wpa_personal": "WPA Personal",
    "spairport_security_mode_wpa2_personal": "WPA2 Personal",
    "spairport_security_mode_wpa2_personal_mixed": "WPA/WPA2 Personal",
    "spairport_security_mode_wpa3_personal": "WPA3 Personal",
    "spairport_security_mode_wpa3_personal_transition": "WPA2/WPA3 Personal",
    "spairport_security_mode_wpa2_enterprise": "WPA2 Enterprise",
    "spairport_security_mode_wpa3_enterprise": "WPA3 Enterprise",
    "spairport_security_mode_wpa3_enterprise_transition": "WPA2/WPA3 Enterprise",
}


def _scan_macos(
    emit: Callable[[int, str], None] | None = None,
) -> list[WiFiNetwork]:
    """macOS WiFi scan — CoreWLAN primary (real SSIDs), system_profiler fallback."""
    _emit = emit or (lambda _p, _m: None)
    try:
        from webscanner.wifi.swift_helper import scan_via_corewlan, LOCATION_SERVICES_HINT
        raw_networks, ssids_visible = scan_via_corewlan(on_progress=_emit)
        if not ssids_visible:
            logger.warning(LOCATION_SERVICES_HINT)
        return [
            WiFiNetwork(
                ssid=n["ssid"],              # type: ignore[arg-type]
                bssid=n["bssid"],            # type: ignore[arg-type]
                signal_dbm=n["signal_dbm"],  # type: ignore[arg-type]
                channel=n["channel"],        # type: ignore[arg-type]
                security=n["security"],      # type: ignore[arg-type]
                band=n["band"],              # type: ignore[arg-type]
            )
            for n in raw_networks
        ]
    except Exception as exc:
        _emit(40, f"CoreWLAN unavailable ({exc}) — falling back to system_profiler…")
        logger.debug("CoreWLAN scan failed (%s), falling back to system_profiler", exc)
        return _scan_macos_system_profiler()


def _scan_macos_system_profiler() -> list[WiFiNetwork]:
    """Primary macOS backend: system_profiler SPAirPortDataType -json.

    Works on macOS 14 (Sonoma) and later where the airport binary was removed.
    Note: SSIDs appear as '<redacted>' on macOS Ventura+ due to OS privacy policy.
    """
    proc = subprocess.run(
        ["system_profiler", "SPAirPortDataType", "-json"],
        capture_output=True,
        text=True,
        timeout=20,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"system_profiler failed: {proc.stderr.strip()}")

    data: dict = json.loads(proc.stdout)
    interfaces: list[dict] = (
        data.get("SPAirPortDataType", [{}])[0]
        .get("spairport_airport_interfaces", [])
    )
    if not interfaces:
        return []

    iface = interfaces[0]
    networks: list[WiFiNetwork] = []

    # Currently connected network (if any)
    current = iface.get("spairport_current_network_information")
    if isinstance(current, dict):
        net = _parse_sp_network(current)
        if net:
            networks.append(net)

    # All other visible networks
    for entry in iface.get("spairport_airport_other_local_wireless_networks", []):
        if isinstance(entry, dict):
            net = _parse_sp_network(entry)
            if net:
                networks.append(net)

    return networks


def _parse_sp_network(entry: dict) -> WiFiNetwork | None:
    """Build a WiFiNetwork from one system_profiler network dict."""
    ssid = entry.get("_name") or "<redacted>"

    raw_mode = entry.get("spairport_security_mode", "")
    security = _SECURITY_MODE_MAP.get(raw_mode, "Open" if not raw_mode else raw_mode)

    channel, band = _parse_sp_channel(entry.get("spairport_network_channel", ""))
    signal_dbm = _parse_sp_signal(entry.get("spairport_signal_noise", ""))

    return WiFiNetwork(
        ssid=ssid,
        bssid="",          # system_profiler does not expose BSSID
        signal_dbm=signal_dbm,
        channel=channel,
        security=security,
        band=band,
    )


def _parse_sp_channel(channel_str: str) -> tuple[int, str]:
    """Parse '44 (5GHz, 80MHz)' → (44, '5GHz')."""
    if not channel_str:
        return 0, "2.4GHz"
    m = re.match(r"(\d+)", channel_str)
    channel = int(m.group(1)) if m else 0
    if "5GHz" in channel_str or "5 GHz" in channel_str:
        band = "5GHz"
    elif "6GHz" in channel_str or "6 GHz" in channel_str:
        band = "6GHz"
    else:
        band = "5GHz" if channel > 14 else "2.4GHz"
    return channel, band


def _parse_sp_signal(signal_str: str) -> int:
    """Parse '-61 dBm / -89 dBm' → -61 (signal; noise discarded)."""
    if not signal_str:
        return -100
    m = re.search(r"(-?\d+)\s*dBm", signal_str)
    return int(m.group(1)) if m else -100


def _scan_macos_airport() -> list[WiFiNetwork]:
    """Legacy fallback: airport binary (macOS 13 and earlier)."""
    # Try XML output first
    try:
        proc = subprocess.run(
            [_AIRPORT_PATH, "-s", "-x"],
            capture_output=True,
            timeout=15,
        )
        if proc.returncode == 0 and proc.stdout:
            plist = plistlib.loads(proc.stdout)
            return [_parse_airport_entry(entry) for entry in plist]
    except Exception:
        pass

    # Plain-text fallback
    proc = subprocess.run(
        [_AIRPORT_PATH, "-s"],
        capture_output=True,
        text=True,
        timeout=15,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"airport failed: {proc.stderr}")

    networks: list[WiFiNetwork] = []
    for line in proc.stdout.splitlines()[1:]:  # skip header
        parts = line.split()
        if len(parts) < 6:
            continue
        try:
            ssid = parts[0]
            bssid = parts[1]
            rssi = int(parts[2])
            channel = int(parts[3].split(",")[0])
            security = " ".join(parts[6:]) or "Open"
            band = "5GHz" if channel > 14 else "2.4GHz"
            networks.append(WiFiNetwork(
                ssid=ssid, bssid=bssid, signal_dbm=rssi,
                channel=channel, security=security, band=band,
            ))
        except (ValueError, IndexError):
            continue

    return networks


def _parse_airport_entry(entry: dict) -> WiFiNetwork:
    """Parse one plist entry from legacy airport -s -x output."""
    ssid = entry.get("SSID_STR", "<hidden>")
    bssid = entry.get("BSSID", "")
    rssi = int(entry.get("RSSI", -100))
    channel_info = entry.get("CHANNEL", 0)
    channel = int(channel_info) if isinstance(channel_info, int) else 0
    band = "5GHz" if channel > 14 else "2.4GHz"

    wpa_mode = entry.get("appleWirelessNetworkModes", "")
    auth_list = entry.get("RSN_IE", {})
    caps = entry.get("CAPABILITIES", 0)

    if "WPA3" in str(wpa_mode):
        security = "WPA3 Personal"
    elif "WPA2" in str(wpa_mode) or auth_list:
        security = "WPA2 Personal"
    elif "WPA" in str(wpa_mode):
        security = "WPA Personal"
    elif caps and (caps & 0x10):
        security = "WEP"
    else:
        security = "Open"

    return WiFiNetwork(
        ssid=ssid, bssid=bssid, signal_dbm=rssi,
        channel=channel, security=security, band=band,
    )


# ---------------------------------------------------------------------------
# Linux via nmcli / iwlist
# ---------------------------------------------------------------------------

def _scan_linux() -> list[WiFiNetwork]:
    """Use nmcli to list nearby networks on Linux."""
    try:
        return _scan_linux_nmcli()
    except FileNotFoundError:
        return _scan_linux_iwlist()


def _scan_linux_nmcli() -> list[WiFiNetwork]:
    proc = subprocess.run(
        [
            "nmcli", "--terse", "--fields",
            "SSID,BSSID,SIGNAL,CHAN,SECURITY,WPS",
            "dev", "wifi", "list",
        ],
        capture_output=True, text=True, timeout=15,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"nmcli failed: {proc.stderr}")

    networks: list[WiFiNetwork] = []
    for line in proc.stdout.splitlines():
        parts = line.split(":")
        if len(parts) < 5:
            continue
        try:
            ssid = parts[0] or "<hidden>"
            bssid = parts[1].replace("\\:", ":")
            signal = int(parts[2]) if parts[2] else 0
            # nmcli signal is 0-100; convert to approximate dBm
            signal_dbm = signal // 2 - 100
            channel = int(parts[3]) if parts[3] else 0
            security = parts[4] or "Open"
            wps = len(parts) > 5 and parts[5].upper() == "YES"
            band = "5GHz" if channel > 14 else "2.4GHz"
            networks.append(WiFiNetwork(
                ssid=ssid, bssid=bssid, signal_dbm=signal_dbm,
                channel=channel, security=security, wps_enabled=wps, band=band,
            ))
        except (ValueError, IndexError):
            continue

    return networks


def _scan_linux_iwlist() -> list[WiFiNetwork]:
    """Fallback: use iwlist scan (requires root)."""
    proc = subprocess.run(
        ["iwlist", "scan"],
        capture_output=True, text=True, timeout=20,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"iwlist failed: {proc.stderr}")

    networks: list[WiFiNetwork] = []
    current: dict[str, str] = {}

    for line in proc.stdout.splitlines():
        line = line.strip()
        if "Cell" in line and "Address:" in line:
            if current:
                networks.append(_build_from_iwlist(current))
            current = {"bssid": line.split("Address:")[-1].strip()}
        elif "ESSID:" in line:
            current["ssid"] = line.split('"')[1] if '"' in line else ""
        elif "Signal level=" in line:
            m = re.search(r"Signal level=(-?\d+)", line)
            if m:
                current["signal"] = m.group(1)
        elif "Channel:" in line:
            current["channel"] = line.split(":")[-1].strip()
        elif "Encryption key:" in line:
            current["enc"] = line.split(":")[-1].strip()
        elif "IE: IEEE 802.11i/WPA2" in line:
            current["security"] = "WPA2"
        elif "IE: WPA" in line and "security" not in current:
            current["security"] = "WPA"

    if current:
        networks.append(_build_from_iwlist(current))

    return networks


def _build_from_iwlist(d: dict[str, str]) -> WiFiNetwork:
    channel = int(d.get("channel", 0) or 0)
    security = d.get("security", "WEP" if d.get("enc") == "on" else "Open")
    return WiFiNetwork(
        ssid=d.get("ssid", "<hidden>"),
        bssid=d.get("bssid", ""),
        signal_dbm=int(d.get("signal", -100) or -100),
        channel=channel,
        security=security,
        band="5GHz" if channel > 14 else "2.4GHz",
    )


# ---------------------------------------------------------------------------
# Windows via netsh
# ---------------------------------------------------------------------------

def _scan_windows() -> list[WiFiNetwork]:
    proc = subprocess.run(
        ["netsh", "wlan", "show", "networks", "mode=bssid"],
        capture_output=True, text=True, timeout=15,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"netsh failed: {proc.stderr}")

    networks: list[WiFiNetwork] = []
    current: dict[str, str] = {}

    for line in proc.stdout.splitlines():
        line = line.strip()
        if line.startswith("SSID") and "BSSID" not in line:
            if current.get("bssid"):
                networks.append(_build_from_netsh(current))
            current = {"ssid": line.split(":", 1)[-1].strip()}
        elif "BSSID" in line:
            current["bssid"] = line.split(":", 1)[-1].strip()
        elif "Signal" in line:
            current["signal"] = line.split(":", 1)[-1].strip().rstrip("%")
        elif "Authentication" in line:
            current["security"] = line.split(":", 1)[-1].strip()
        elif "Channel" in line:
            current["channel"] = line.split(":", 1)[-1].strip()

    if current.get("bssid"):
        networks.append(_build_from_netsh(current))

    return networks


def _build_from_netsh(d: dict[str, str]) -> WiFiNetwork:
    channel = int(d.get("channel", 0) or 0)
    signal_pct = int(d.get("signal", 50) or 50)
    signal_dbm = signal_pct // 2 - 100
    return WiFiNetwork(
        ssid=d.get("ssid", "<hidden>"),
        bssid=d.get("bssid", ""),
        signal_dbm=signal_dbm,
        channel=channel,
        security=d.get("security", "Unknown"),
        band="5GHz" if channel > 14 else "2.4GHz",
    )
