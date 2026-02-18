#!/usr/bin/env python3
"""Download external wordlists from public repositories for deep scanning.

Sources used:
  - SecLists (danielmiessler/SecLists) — MIT license
  - rockyou.txt — public domain, originally from the 2009 RockYou breach disclosure

Usage:
    python wordlists/download_wordlists.py
    python wordlists/download_wordlists.py --skip-rockyou   # skip the 130 MB file
"""

from __future__ import annotations

import argparse
import sys
import urllib.request
from pathlib import Path

WORDLISTS_DIR = Path(__file__).parent

SECLISTS_BASE = (
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master"
)

DOWNLOADS: list[dict[str, str]] = [
    {
        "name": "top-10k-passwords.txt",
        "url": f"{SECLISTS_BASE}/Passwords/Common-Credentials/common-passwords-win.txt",
        "description": "Top ~10,000 common passwords (SecLists)",
    },
    {
        "name": "top-100k-passwords.txt",
        "url": f"{SECLISTS_BASE}/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt",
        "description": "Top 100,000 most common passwords — NCSC list (SecLists)",
    },
    {
        "name": "usernames-large.txt",
        "url": f"{SECLISTS_BASE}/Usernames/Names/names.txt",
        "description": "Common first names usable as usernames (SecLists)",
    },
    {
        "name": "web-content-common.txt",
        "url": f"{SECLISTS_BASE}/Discovery/Web-Content/common.txt",
        "description": "Common web paths and files for directory discovery (SecLists)",
    },
    {
        "name": "web-content-big.txt",
        "url": f"{SECLISTS_BASE}/Discovery/Web-Content/big.txt",
        "description": "Large web paths list for deep directory brute force (SecLists)",
    },
    {
        "name": "api-endpoints.txt",
        "url": f"{SECLISTS_BASE}/Discovery/Web-Content/api/api-endpoints.txt",
        "description": "Common REST API endpoint paths (SecLists)",
    },
    {
        "name": "subdomains-top5000.txt",
        "url": f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-5000.txt",
        "description": "Top 5000 subdomain names for DNS enumeration (SecLists)",
    },
    {
        "name": "subdomains-top20000.txt",
        "url": f"{SECLISTS_BASE}/Discovery/DNS/subdomains-top1million-20000.txt",
        "description": "Top 20,000 subdomain names for deep DNS enumeration (SecLists)",
    },
    {
        "name": "wifi-passwords.txt",
        "url": f"{SECLISTS_BASE}/Passwords/WiFi-WPA/probable-v2-wpa-top4800.txt",
        "description": "Top 4,800 probable WPA passwords for WiFi auditing (SecLists)",
    },
]

ROCKYOU: dict[str, str] = {
    "name": "rockyou.txt",
    "url": "https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt",
    "description": "rockyou.txt — 14 million passwords, the classic pentest wordlist (~130 MB)",
}


def _download(url: str, dest: Path, description: str) -> bool:
    """Download a file with progress display. Returns True on success."""
    if dest.exists():
        size_kb = dest.stat().st_size // 1024
        print(f"  [skip] {dest.name} already exists ({size_kb:,} KB)")
        return True

    print(f"  Downloading {dest.name} — {description}")
    print(f"    From: {url}")

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "WebScanner-WordlistDownloader/0.1.0"},
        )
        with urllib.request.urlopen(req, timeout=60) as response:
            total = int(response.headers.get("Content-Length", 0))
            downloaded = 0
            chunk_size = 65536  # 64 KB chunks

            with open(dest, "wb") as f:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    f.write(chunk)
                    downloaded += len(chunk)
                    if total:
                        pct = downloaded / total * 100
                        bar = "#" * int(pct / 4)
                        print(f"\r    [{bar:<25}] {pct:5.1f}%  {downloaded//1024:,} KB", end="", flush=True)

        print(f"\r    Done — {downloaded // 1024:,} KB saved to {dest.name}            ")
        return True

    except urllib.error.HTTPError as e:
        print(f"\n    [error] HTTP {e.code}: {e.reason} — skipping {dest.name}")
        if dest.exists():
            dest.unlink()
        return False
    except Exception as e:
        print(f"\n    [error] {e} — skipping {dest.name}")
        if dest.exists():
            dest.unlink()
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--skip-rockyou",
        action="store_true",
        help="Skip downloading rockyou.txt (~130 MB)",
    )
    parser.add_argument(
        "--only",
        metavar="NAME",
        help="Download only the wordlist with this filename",
    )
    args = parser.parse_args()

    print("WebScanner — Wordlist Downloader")
    print("=" * 40)
    print(f"Saving to: {WORDLISTS_DIR.resolve()}")
    print()

    targets = DOWNLOADS
    if args.only:
        targets = [d for d in DOWNLOADS if d["name"] == args.only]
        if not targets:
            print(f"No wordlist named '{args.only}' found.")
            print("Available:", ", ".join(d["name"] for d in DOWNLOADS))
            sys.exit(1)

    ok = 0
    failed = 0

    for entry in targets:
        dest = WORDLISTS_DIR / entry["name"]
        success = _download(entry["url"], dest, entry["description"])
        if success:
            ok += 1
        else:
            failed += 1

    if not args.skip_rockyou and not args.only:
        print()
        print("  rockyou.txt (~130 MB) — download? [y/N] ", end="", flush=True)
        try:
            answer = input().strip().lower()
        except (EOFError, KeyboardInterrupt):
            answer = "n"
        if answer == "y":
            dest = WORDLISTS_DIR / ROCKYOU["name"]
            success = _download(ROCKYOU["url"], dest, ROCKYOU["description"])
            if success:
                ok += 1
            else:
                failed += 1

    print()
    print(f"Done: {ok} downloaded, {failed} failed.")
    print()
    print("Built-in wordlists (always available):")
    for f in sorted(WORDLISTS_DIR.glob("*.txt")):
        if not f.name.startswith("."):
            print(f"  {f.name:<35} {f.stat().st_size // 1024:>6,} KB")


if __name__ == "__main__":
    main()
