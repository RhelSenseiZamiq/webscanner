"""WiFi security analyzer.

Takes the raw scan results and produces security findings — flagging
open networks, WEP encryption, WPS vulnerabilities, evil twin APs,
hidden SSIDs, deauth attack surface, and WPA downgrade risks.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from webscanner.wifi.scanner import WiFiNetwork, WiFiScanResult

logger = logging.getLogger("webscanner.wifi.analyzer")


@dataclass(frozen=True)
class WiFiFinding:
    """An immutable WiFi security finding."""

    network_ssid: str
    bssid: str
    severity: str        # "critical" | "high" | "medium" | "low" | "info"
    title: str
    description: str
    evidence: str
    remediation: str


@dataclass(frozen=True)
class WiFiAnalysisResult:
    """Immutable result of analyzing a WiFi scan."""

    findings: tuple[WiFiFinding, ...]
    networks_analyzed: int
    open_count: int
    wep_count: int
    wps_count: int
    wpa2_count: int
    wpa3_count: int


def analyze(scan_result: WiFiScanResult) -> WiFiAnalysisResult:
    """Analyze scanned WiFi networks and produce security findings."""
    findings: list[WiFiFinding] = []
    open_count = wep_count = wps_count = wpa2_count = wpa3_count = 0

    for network in scan_result.networks:
        sec = network.security.upper()

        if "WPA3" in sec:
            wpa3_count += 1
        elif "WPA2" in sec:
            wpa2_count += 1

        # Open network — no encryption at all
        if _is_open(network):
            open_count += 1
            findings.append(WiFiFinding(
                network_ssid=network.ssid,
                bssid=network.bssid,
                severity="high",
                title="Open WiFi Network (No Encryption)",
                description=(
                    f"The network '{network.ssid}' uses no wireless encryption. "
                    "All traffic between clients and the access point is transmitted "
                    "in plaintext. Any device within radio range can capture and read "
                    "all unencrypted traffic using freely available tools."
                ),
                evidence=f"Security: '{network.security}' | BSSID: {network.bssid} | Signal: {network.signal_dbm} dBm",
                remediation=(
                    "Enable WPA3-Personal or, at minimum, WPA2-AES on the access point. "
                    "Disable WEP and TKIP cipher modes. "
                    "If offering guest WiFi, isolate it from internal networks using VLAN segmentation."
                ),
            ))

        # WEP — broken encryption, crackable in minutes
        elif _is_wep(network):
            wep_count += 1
            findings.append(WiFiFinding(
                network_ssid=network.ssid,
                bssid=network.bssid,
                severity="critical",
                title="WEP Encryption — Critically Weak",
                description=(
                    f"The network '{network.ssid}' uses WEP (Wired Equivalent Privacy), "
                    "which was officially deprecated in 2004 and can be cracked in under "
                    "60 seconds using tools like aircrack-ng. "
                    "WEP provides essentially no security."
                ),
                evidence=f"Security: '{network.security}' | BSSID: {network.bssid} | Signal: {network.signal_dbm} dBm",
                remediation=(
                    "Immediately replace WEP with WPA3-Personal. "
                    "If the access point hardware cannot support WPA3, replace the hardware. "
                    "Ensure all connected devices are patched and update firmware."
                ),
            ))

        # WPS enabled — PIN brute-force and Pixie Dust vulnerabilities
        if network.wps_enabled:
            wps_count += 1
            findings.append(WiFiFinding(
                network_ssid=network.ssid,
                bssid=network.bssid,
                severity="medium",
                title="WPS (Wi-Fi Protected Setup) Enabled",
                description=(
                    f"The network '{network.ssid}' has WPS enabled. "
                    "WPS PIN mode is vulnerable to brute-force attacks (Reaver) "
                    "and the Pixie Dust attack, which can recover the WPS PIN in seconds "
                    "on many router models. This can reveal the WPA2 passphrase without "
                    "needing to brute-force it."
                ),
                evidence=f"WPS detected on BSSID: {network.bssid} | SSID: {network.ssid}",
                remediation=(
                    "Disable WPS in the access point admin panel. "
                    "If WPS is required for setup, disable it after initial device pairing. "
                    "Update router firmware to the latest version."
                ),
            ))

        # WPA (TKIP only, no AES) — KRACK and TKIP vulnerabilities
        if _is_weak_wpa(network):
            findings.append(WiFiFinding(
                network_ssid=network.ssid,
                bssid=network.bssid,
                severity="medium",
                title="WPA with TKIP — Weak Cipher Mode",
                description=(
                    f"The network '{network.ssid}' uses WPA with TKIP cipher, "
                    "which is vulnerable to the KRACK (Key Reinstallation Attack) and "
                    "several TKIP-specific attacks. TKIP was deprecated in 2012."
                ),
                evidence=f"Security: '{network.security}' | BSSID: {network.bssid}",
                remediation=(
                    "Upgrade to WPA2-AES or WPA3. "
                    "In router settings, select 'WPA2-AES only' or 'WPA3' — "
                    "avoid 'WPA/WPA2 mixed mode' with TKIP."
                ),
            ))

        # Very strong signal that might indicate rogue AP / evil twin
        if network.signal_dbm > -40 and not _is_open(network):
            findings.append(WiFiFinding(
                network_ssid=network.ssid,
                bssid=network.bssid,
                severity="info",
                title="Unusually Strong Signal — Verify AP Identity",
                description=(
                    f"'{network.ssid}' has an unusually strong signal ({network.signal_dbm} dBm). "
                    "Rogue access points (evil twin attacks) are often placed physically close "
                    "to victims to produce stronger-than-expected signal. Verify this is a known, "
                    "legitimate AP by checking the BSSID against your network inventory."
                ),
                evidence=f"Signal: {network.signal_dbm} dBm | BSSID: {network.bssid}",
                remediation=(
                    "Verify the BSSID matches your known access point hardware MAC addresses. "
                    "Use 802.1X/RADIUS authentication to prevent rogue AP connections. "
                    "Deploy a wireless intrusion detection system (WIDS)."
                ),
            ))

        # Hidden SSID — empty or null network name
        if not network.ssid or network.ssid in ("<hidden>", ""):
            findings.append(WiFiFinding(
                network_ssid="<hidden>",
                bssid=network.bssid,
                severity="info",
                title="Hidden SSID Detected",
                description=(
                    "An access point is broadcasting with a hidden (empty) SSID. "
                    "Hidden SSIDs provide only the illusion of security — the SSID is "
                    "visible in probe requests from any connecting device and can be "
                    "captured passively with tools like airodump-ng."
                ),
                evidence=f"SSID: '' (hidden) | BSSID: {network.bssid} | Signal: {network.signal_dbm} dBm",
                remediation=(
                    "Do not rely on hidden SSIDs as a security measure. "
                    "Use WPA3 or WPA2-AES with a strong passphrase instead. "
                    "Enable 802.11w (PMF) to protect management frames."
                ),
            ))

        # WPA2-Personal without PMF indicator — deauth attack surface
        if _is_deauth_vulnerable(network):
            findings.append(WiFiFinding(
                network_ssid=network.ssid,
                bssid=network.bssid,
                severity="medium",
                title="Deauthentication Attack Surface (No 802.11w / PMF)",
                description=(
                    f"'{network.ssid}' appears to use WPA2-Personal without Protected "
                    "Management Frames (802.11w / PMF). Deauthentication frames are "
                    "unauthenticated and can be forged to disconnect clients, enabling "
                    "denial-of-service or forcing clients to reconnect (for PMKID capture "
                    "or evil twin attacks)."
                ),
                evidence=f"Security: '{network.security}' | BSSID: {network.bssid} | PMF: not indicated",
                remediation=(
                    "Enable 802.11w (Protected Management Frames) in your AP settings. "
                    "Upgrade to WPA3 which mandates PMF. "
                    "Use an enterprise-grade wireless controller with WIDS."
                ),
            ))

        # WPA downgrade risk — mixed WPA/WPA2 mode
        if _is_wpa_downgrade_risk(network):
            findings.append(WiFiFinding(
                network_ssid=network.ssid,
                bssid=network.bssid,
                severity="medium",
                title="WPA/WPA2 Mixed Mode — Downgrade Attack Risk",
                description=(
                    f"'{network.ssid}' advertises both WPA and WPA2 in mixed mode. "
                    "Attackers can force clients to connect using the weaker WPA/TKIP "
                    "standard, enabling TKIP attacks and reducing effective security."
                ),
                evidence=f"Security: '{network.security}' | BSSID: {network.bssid}",
                remediation=(
                    "Configure the AP for WPA2-AES (CCMP) only, or WPA3. "
                    "Remove WPA-TKIP compatibility modes from your router settings."
                ),
            ))

    # Evil twin detection — cross-network check (same SSID, different BSSIDs)
    ssid_to_bssids: dict[str, list[str]] = {}
    for network in scan_result.networks:
        if network.ssid and network.ssid not in ("<hidden>", ""):
            ssid_to_bssids.setdefault(network.ssid, []).append(network.bssid)

    for ssid, bssids in ssid_to_bssids.items():
        if len(bssids) > 1:
            findings.append(WiFiFinding(
                network_ssid=ssid,
                bssid=bssids[0],
                severity="high",
                title=f"Possible Evil Twin — Multiple BSSIDs for '{ssid}'",
                description=(
                    f"The SSID '{ssid}' is broadcast by {len(bssids)} different access points "
                    f"with BSSIDs: {', '.join(bssids)}. "
                    "While this may be a legitimate multi-AP deployment, it is also the "
                    "signature of an evil twin attack where an attacker impersonates a "
                    "known network to perform MITM attacks."
                ),
                evidence=f"SSIDs: {ssid} → BSSIDs: {', '.join(bssids)}",
                remediation=(
                    "Verify that all detected BSSIDs belong to your legitimate hardware "
                    "by cross-referencing MAC addresses with your network inventory. "
                    "Deploy a WIDS to detect and alert on unauthorised APs. "
                    "Use 802.1X/RADIUS authentication to prevent rogue AP associations."
                ),
            ))

    logger.info(
        "WiFi analysis: %d findings across %d networks",
        len(findings), len(scan_result.networks),
    )

    return WiFiAnalysisResult(
        findings=tuple(findings),
        networks_analyzed=len(scan_result.networks),
        open_count=open_count,
        wep_count=wep_count,
        wps_count=wps_count,
        wpa2_count=wpa2_count,
        wpa3_count=wpa3_count,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_open(network: WiFiNetwork) -> bool:
    sec = network.security.upper()
    return sec in ("", "OPEN", "NONE", "--", "ESS") or not network.security


def _is_wep(network: WiFiNetwork) -> bool:
    return "WEP" in network.security.upper()


def _is_weak_wpa(network: WiFiNetwork) -> bool:
    sec = network.security.upper()
    return "TKIP" in sec or (("WPA" in sec) and ("WPA2" not in sec) and ("WPA3" not in sec))


def _is_deauth_vulnerable(network: WiFiNetwork) -> bool:
    """True for WPA2-Personal networks without a PMF indicator."""
    sec = network.security.upper()
    # Only flag WPA2-Personal (not WPA3 which mandates PMF, not open/WEP which have other issues)
    if "WPA2" not in sec or "WPA3" in sec:
        return False
    if _is_open(network) or _is_wep(network):
        return False
    # If security string mentions PMF, 802.11w, or Enterprise/RADIUS, skip
    if any(kw in sec for kw in ("PMF", "802.11W", "ENTERPRISE", "EAP", "RADIUS")):
        return False
    return True


def _is_wpa_downgrade_risk(network: WiFiNetwork) -> bool:
    """True when both WPA and WPA2 are advertised simultaneously (mixed mode)."""
    sec = network.security.upper()
    return "WPA2" in sec and "WPA" in sec and "WPA3" not in sec and "WPA2" != sec.strip()
