#!/usr/bin/env python3
import argparse
import subprocess
from pathlib import Path
from datetime import datetime, timezone

HTTPX = "/home/kali/go/bin/httpx"
SUBFINDER = "subfinder"
NAABU = "naabu"
NUCLEI = "nuclei"

def run(cmd, desc, shell=False):
    print(f"\n[+] {desc}")
    if shell:
        print(f"    $ {cmd}")
        p = subprocess.run(cmd, shell=True, text=True)
    else:
        print(f"    $ {' '.join(cmd)}")
        p = subprocess.run(cmd, text=True)
    if p.returncode != 0:
        raise SystemExit(f"[-] Failed: {desc}")
    return p.returncode

def count_lines(path):
    p = Path(path)
    if not p.exists():
        return 0
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        return sum(1 for line in f if line.strip())

def normalize_host(s):
    s = s.strip()
    if not s:
        return ""
    if s.startswith("[") and "](" in s:
        s = s.split("](", 1)[0].lstrip("[")
    if s.startswith("http://"):
        s = s[len("http://"):]
    elif s.startswith("https://"):
        s = s[len("https://"):]
    s = s.split("/", 1)[0].strip()
    s = s.strip("[]()")
    return s

def clean_subdomains(src, dst):
    seen = set()
    with open(src, "r", encoding="utf-8", errors="ignore") as inp, open(dst, "w", encoding="utf-8") as out:
        for line in inp:
            host = normalize_host(line)
            if host and host not in seen:
                seen.add(host)
                out.write(host + "\n")

def extract_hosts_from_httpx(src, dst):
    seen = set()
    with open(src, "r", encoding="utf-8", errors="ignore") as inp, open(dst, "w", encoding="utf-8") as out:
        for line in inp:
            line = line.strip()
            if not line:
                continue
            first = line.split()[0]
            host = normalize_host(first)
            if host and host not in seen:
                seen.add(host)
                out.write(host + "\n")

def banner(target, outdir):
    print(r"""
 ____              _           ____              _
|  _ \  ___   ___ | | __      | __ )  ___   ___ | |_
| |_) |/ _ \ / _ \| |/ /_____|  _ \ / _ \ / _ \| __|
|  __/| (_) | (_) |   <______| |_) | (_) | (_) | |_
|_|    \___/ \___/|_|\_\     |____/ \___/ \___/ \__|
""")
    print(f"Target : {target}")
    print(f"Output : {outdir}")
    print(f"Time   : {datetime.now(timezone.utc).isoformat()}")

def main():
    ap = argparse.ArgumentParser(description="Bug bounty recon workflow")
    ap.add_argument("-d", "--domain", required=True)
    ap.add_argument("-o", "--out", default="results")
    args = ap.parse_args()

    target = args.domain.strip()
    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)

    subdomains = outdir / "subdomains.txt"
    subdomains_clean = outdir / "subdomains_clean.txt"
    web_targets = outdir / "web_targets.txt"
    live = outdir / "live.txt"
    ports = outdir / "ports.txt"
    nuclei_out = outdir / "nuclei.jsonl"
    report = outdir / "report.txt"

    banner(target, outdir)

    run([SUBFINDER, "-d", target, "-all", "-silent", "-o", str(subdomains)],
        "Enumerating subdomains with Subfinder")
    clean_subdomains(subdomains, subdomains_clean)
    print(f"    Subdomains found: {count_lines(subdomains_clean)}")

    run(f'cat "{subdomains_clean}" | "{HTTPX}" -sc -title -tech-detect -o "{live}"',
        "Probing live web hosts with HTTPX", shell=True)
    print(f"    Live web targets found: {count_lines(live)}")

    extract_hosts_from_httpx(live, web_targets)
    print(f"    Hosts extracted for port scan: {count_lines(web_targets)}")

    run([NAABU, "-list", str(web_targets), "-top-ports", "1000", "-silent", "-o", str(ports)],
        "Scanning open ports with Naabu")
    print(f"    Port findings: {count_lines(ports)}")

    run([NUCLEI, "-list", str(live), "-severity", "critical,high,medium", "-jsonl", "-o", str(nuclei_out)],
        "Scanning vulnerabilities with Nuclei")
    print(f"    Nuclei findings: {count_lines(nuclei_out)}")

    with report.open("w", encoding="utf-8") as f:
        f.write("Bug Bounty Workflow Report\n")
        f.write(f"Target: {target}\n")
        f.write(f"Generated: {datetime.now(timezone.utc).isoformat()}\n\n")
        f.write(f"Subdomains: {count_lines(subdomains_clean)}\n")
        f.write(f"Live web targets: {count_lines(live)}\n")
        f.write(f"Hosts for naabu: {count_lines(web_targets)}\n")
        f.write(f"Ports: {count_lines(ports)}\n")
        f.write(f"Nuclei findings: {count_lines(nuclei_out)}\n")

    print(f"\n[+] Done. Report saved to: {report}")

if __name__ == "__main__":
    main()
