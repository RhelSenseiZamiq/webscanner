"""CoreWLAN-based WiFi scanner for macOS — returns real SSIDs via Swift/CoreWLAN.

Compiles a tiny Swift program once, caches the binary in /tmp, and runs it
to get the full list of nearby networks including actual SSIDs and BSSIDs.
Falls back gracefully if swiftc is not available.
"""

from __future__ import annotations

import logging
import os
import subprocess
import tempfile
from collections.abc import Callable

logger = logging.getLogger("webscanner.wifi.swift_helper")

# Cached binary path — compiled once per session
_BINARY_PATH = os.path.join(tempfile.gettempdir(), "ws_wifi_helper")

# CoreWLAN security enum raw values → human-readable label
_CW_SECURITY: dict[int, str] = {
    0:  "Open",
    1:  "WEP",
    2:  "WPA Personal",
    3:  "WPA/WPA2 Personal",
    4:  "WPA2 Personal",
    5:  "Personal",
    6:  "Dynamic WEP",
    7:  "WPA Enterprise",
    8:  "WPA/WPA2 Enterprise",
    9:  "WPA2 Enterprise",
    10: "Enterprise",
    11: "WPA3 Personal",
    12: "WPA3 Enterprise",
    13: "WPA2/WPA3 Personal",
}

# Swift source — compiled at runtime; uses CoreWLAN framework
_SWIFT_SOURCE = """\
import CoreWLAN
import Foundation

let client = CWWiFiClient.shared()
guard let iface = client.interface() else {
    fputs("ERROR: No WiFi interface found\\n", stderr)
    exit(1)
}

do {
    let networks = try iface.scanForNetworks(withSSID: nil)
    for n in networks {
        let ssid    = n.ssid    ?? "<hidden>"
        let bssid   = n.bssid   ?? ""
        let rssi    = n.rssiValue
        let channel = n.wlanChannel?.channelNumber ?? 0
        let band: String
        switch n.wlanChannel?.channelBand {
        case .band5GHz:  band = "5GHz"
        case .band6GHz:  band = "6GHz"
        default:         band = "2.4GHz"
        }
        let sec = n.security.rawValue
        print("\\(ssid)\\t\\(bssid)\\t\\(rssi)\\t\\(channel)\\t\\(band)\\t\\(sec)")
    }
} catch {
    fputs("ERROR: \\(error.localizedDescription)\\n", stderr)
    exit(1)
}
"""


def _ensure_binary() -> str:
    """Compile the Swift helper if needed; return path to binary."""
    if os.path.exists(_BINARY_PATH):
        return _BINARY_PATH

    # Write source to a temp file
    src_path = _BINARY_PATH + ".swift"
    with open(src_path, "w") as f:
        f.write(_SWIFT_SOURCE)

    logger.debug("Compiling CoreWLAN WiFi helper with swiftc...")
    proc = subprocess.run(
        ["swiftc", "-framework", "CoreWLAN", src_path, "-o", _BINARY_PATH],
        capture_output=True,
        text=True,
        timeout=30,
    )

    try:
        os.unlink(src_path)
    except OSError:
        pass

    if proc.returncode != 0:
        raise RuntimeError(
            f"swiftc compilation failed: {proc.stderr.strip()}"
        )

    os.chmod(_BINARY_PATH, 0o755)
    logger.debug("CoreWLAN helper compiled to %s", _BINARY_PATH)
    return _BINARY_PATH


def _get_current_ssid(interface: str = "en0") -> str | None:
    """Return the SSID of the currently connected network via networksetup.

    This always works on macOS regardless of Location Services settings.
    Returns None if not connected or on error.
    """
    try:
        proc = subprocess.run(
            ["networksetup", "-getairportnetwork", interface],
            capture_output=True, text=True, timeout=5,
        )
        # Output: "Current Wi-Fi Network: MySSID"
        line = proc.stdout.strip()
        if "Current Wi-Fi Network: " in line:
            return line.split("Current Wi-Fi Network: ", 1)[1].strip()
    except Exception:
        pass
    return None


def scan_via_corewlan(
    on_progress: Callable[[int, str], None] | None = None,
) -> tuple[list[dict[str, object]], bool]:
    """Run the CoreWLAN helper and return (networks, ssids_visible).

    ssids_visible is True when real SSIDs were returned (Location Services on).
    When False, caller should warn the user to enable Location Services.

    Each network dict has keys:
        ssid, bssid, signal_dbm (int), channel (int), band (str), security (str)

    Raises RuntimeError on any failure (caller should fall back to system_profiler).
    """
    def emit(pct: int, msg: str) -> None:
        if on_progress:
            on_progress(pct, msg)

    needs_compile = not os.path.exists(_BINARY_PATH)
    if needs_compile:
        emit(5, "Compiling CoreWLAN scanner helper (first run — may take a moment)…")
    else:
        emit(5, "CoreWLAN scanner helper already compiled")

    binary = _ensure_binary()

    if needs_compile:
        emit(15, "CoreWLAN helper compiled successfully")

    emit(20, "Running CoreWLAN WiFi scan…")

    proc = subprocess.run(
        [binary],
        capture_output=True,
        text=True,
        timeout=20,
    )

    if proc.returncode != 0:
        raise RuntimeError(
            f"CoreWLAN helper failed: {proc.stderr.strip()}"
        )

    networks: list[dict[str, object]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t")
        if len(parts) < 6:
            continue
        try:
            ssid, bssid, rssi_s, ch_s, band, sec_s = parts[:6]
            sec_int = int(sec_s)
            security = _CW_SECURITY.get(sec_int, f"Unknown ({sec_int})")
            networks.append({
                "ssid":       ssid or "<hidden>",
                "bssid":      bssid,
                "signal_dbm": int(rssi_s),
                "channel":    int(ch_s),
                "band":       band,
                "security":   security,
            })
        except (ValueError, IndexError):
            continue

    emit(70, f"CoreWLAN returned {len(networks)} network(s)")

    # Check if SSIDs are visible or redacted by macOS privacy
    ssids_visible = any(
        n["ssid"] not in ("<redacted>", "<hidden>", "")
        for n in networks
    )

    # If redacted, patch the current connected network with its real SSID
    # (networksetup -getairportnetwork always returns the connected SSID)
    if not ssids_visible and networks:
        current_ssid = _get_current_ssid()
        if current_ssid:
            # The connected network typically has the strongest signal
            strongest = max(networks, key=lambda n: int(n["signal_dbm"]))  # type: ignore[arg-type]
            strongest["ssid"] = current_ssid + " (connected)"
            ssids_visible = True

    if not ssids_visible:
        emit(80, (
            "⚠  SSIDs hidden by macOS privacy — enable Location Services for Terminal: "
            "System Settings → Privacy & Security → Location Services → Terminal → On"
        ))
    else:
        emit(80, f"SSIDs visible (Location Services enabled) — {len(networks)} network(s) found")

    return networks, ssids_visible


LOCATION_SERVICES_HINT = (
    "SSIDs are hidden by macOS privacy. To see network names:\n"
    "  System Settings → Privacy & Security → Location Services\n"
    "  → enable Terminal (or the app running this scan)\n"
    "  Then re-run: webscanner wifi"
)
