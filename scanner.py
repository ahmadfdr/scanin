#!/usr/bin/env python3
"""Scan.in — Sensitive File Discovery Tool"""

import sys
import json
import socket
import time
import argparse
import random
import string
import re
import os
import concurrent.futures
from datetime import datetime
from urllib.parse import urljoin

try:
    import requests
    from urllib3.util.retry import Retry
    from requests.adapters import HTTPAdapter
    from urllib3.exceptions import InsecureRequestWarning
    import urllib3
    urllib3.disable_warnings(InsecureRequestWarning)
except ImportError:
    sys.exit("[!] requests not found. Run: pip3 install requests")

# Constants & Configuration
COLORS = {
    "CRITICAL": "\033[91m", "HIGH": "\033[38;5;208m", "MEDIUM": "\033[93m",
    "LOW": "\033[96m", "INFO": "\033[37m", "RESET": "\033[0m",
    "BOLD": "\033[1m", "GREEN": "\033[92m", "GRAY": "\033[90m"
}

SEVERITY_MAP = {
    "VCS": "CRITICAL", "ENV_SECRETS": "CRITICAL", "KEYS_CERTS": "CRITICAL",
    "APP_CONFIG": "HIGH", "BACKUP_FILES": "HIGH", "LOG_FILES": "HIGH",
    "CLOUD_INFRA": "HIGH", "ADMIN_INTERFACES": "MEDIUM", "CICD": "MEDIUM",
    "PACKAGE_MANIFESTS": "LOW", "MISC": "INFO"
}

# Catalogue defined at the bottom for cleanliness
SENSITIVE_PATHS = {} 

class SensitiveScanner:
    def __init__(self, args):
        self.args = args
        self.session = self._make_session()
        self.findings = []
        self.soft404_registry = {}  # host -> {length, text_snippet}
        self.start_time = None

    def _make_session(self):
        session = requests.Session()
        retry = Retry(
            total=2, backoff_factor=0.3,
            status_forcelist=[500, 502, 503, 504],
            allowed_methods=["HEAD", "GET"]
        )
        session.mount("http://", HTTPAdapter(max_retries=retry))
        session.mount("https://", HTTPAdapter(max_retries=retry))
        session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; ScanIn/1.0; Security-Audit)",
            "Accept": "*/*"
        })
        return session

    def log(self, message, color="RESET", bold=False):
        prefix = COLORS.get(color, "")
        if bold: prefix += COLORS["BOLD"]
        print(f"{prefix}{message}{COLORS['RESET']}")

    # Subdomain Discovery
    def fetch_crtsh(self, domain):
        subdomains = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        max_retries = 3
        
        if self.args.debug:
            self.log(f"[DEBUG] Querying crt.sh: {url}", "GRAY")

        for attempt in range(max_retries):
            try:
                resp = self.session.get(url, timeout=30)
                resp.raise_for_status()
                data = resp.json()
                
                if self.args.debug:
                    self.log(f"[DEBUG] crt.sh returned {len(data)} certificate entries", "GRAY")

                for entry in data:
                    # Extract from all possible fields that might contain names
                    names_found = set()
                    for field in ["common_name", "name_value"]:
                        raw = entry.get(field, "")
                        if raw:
                            # Split by common delimiters and handle wildcards
                            for name in re.split(r"[\s\n,]+", raw):
                                clean_name = name.strip().lower().lstrip("*.")
                                if clean_name:
                                    names_found.add(clean_name)
                    
                    for name in names_found:
                        if name.endswith(f".{domain}") or name == domain:
                            if name not in subdomains:
                                if self.args.debug:
                                    self.log(f"[DEBUG] Found subdomain: {name}", "GRAY")
                                subdomains.add(name)
                        elif self.args.debug:
                            # Log why a name was rejected
                            self.log(f"[DEBUG] Skipping name (out of scope): {name}", "GRAY")
                            
                return subdomains
            except (requests.exceptions.RequestException, json.JSONDecodeError) as e:
                if attempt < max_retries - 1:
                    self.log(f"  [!] crt.sh timeout/error, retrying ({attempt + 1}/{max_retries})...", "GRAY")
                    time.sleep(2)
                else:
                    self.log(f"  [!] crt.sh failed after {max_retries} attempts: {e}", "GRAY")
        return subdomains

    def resolve_hosts(self, hosts):
        live = set()
        if self.args.debug:
            self.log(f"[DEBUG] Attempting to resolve {len(hosts)} unique hosts...", "GRAY")

        def check(h):
            try:
                # Use a specific port to help resolution if needed, though 80 is standard
                socket.getaddrinfo(h, None)
                if self.args.debug:
                    self.log(f"[DEBUG] Resolution SUCCESS: {h}", "GREEN")
                return h
            except socket.gaierror as e:
                if self.args.debug:
                    self.log(f"[DEBUG] Resolution FAILED: {h} ({e})", "GRAY")
                return None
            except Exception as e:
                if self.args.debug:
                    self.log(f"[DEBUG] Resolution ERROR: {h} ({e})", "GRAY")
                return None
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=50) as executor:
            results = executor.map(check, hosts)
            for r in results:
                if r: live.add(r)
        return live

    # Probing Logic
    def autocalibrate(self, host, scheme):
        """Fingerprint a non-existent path to establish a baseline for 404/Soft 404 pages."""
        key = f"{scheme}://{host}"
        rand_path = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
        url = urljoin(f"{scheme}://{host}/", rand_path)
        
        try:
            resp = self.session.get(url, timeout=self.args.timeout, verify=False, allow_redirects=True)
            self.soft404_registry[key] = {
                "status_code": resp.status_code,
                "length": len(resp.content),
                "words": len(resp.text.split()),
                "lines": len(resp.text.splitlines()),
                "title": self._extract_tag(resp.text, "title"),
                "h1": self._extract_tag(resp.text, "h1")
            }
            if self.args.debug:
                f = self.soft404_registry[key]
                self.log(f"[DEBUG] Autocalibrated {key}: HTTP {f['status_code']}, {f['words']} words, Title: '{f['title']}'", "GRAY")
        except Exception as e:
            if self.args.debug:
                self.log(f"[DEBUG] Autocalibration failed for {key}: {e}", "GRAY")

    def _extract_tag(self, html, tag):
        """Simple regex extraction for HTML tags."""
        match = re.search(rf"<{tag}[^>]*>(.*?)</{tag}>", html, re.IGNORECASE | re.DOTALL)
        return match.group(1).strip() if match else ""

    def is_soft_404(self, host, scheme, url, resp):
        """Compare response against the host's autocalibration fingerprint."""
        key = f"{scheme}://{host}"
        if key not in self.soft404_registry:
            return False
            
        f = self.soft404_registry[key]
        
        # 1. Exact Status Code Match (if the baseline was already a 404/403)
        if resp.status_code == f["status_code"] and resp.status_code >= 400:
            return True

        # 2. Extract current features
        # For performance, only do full body analysis if status is 200/206
        if resp.status_code not in (200, 206):
            return False

        # Fetch full body for analysis
        full_text = resp.text
        curr_words = len(full_text.split())
        curr_lines = len(full_text.splitlines())
        curr_title = self._extract_tag(full_text, "title")
        curr_h1 = self._extract_tag(full_text, "h1")

        # 3. Fuzzy Comparison
        # Title/H1 match is a very strong indicator of a template error page
        if f["title"] and curr_title == f["title"]:
            if self.args.debug: self.log(f"[DEBUG] Soft 404 Match (Title): {url}", "GRAY")
            return True
        if f["h1"] and curr_h1 == f["h1"]:
            if self.args.debug: self.log(f"[DEBUG] Soft 404 Match (H1): {url}", "GRAY")
            return True

        # Word/Line count within a tight 5% tolerance
        word_diff = abs(curr_words - f["words"])
        line_diff = abs(curr_lines - f["lines"])
        
        if word_diff <= (f["words"] * 0.05) and line_diff <= (f["lines"] * 0.05):
            if self.args.debug: 
                self.log(f"[DEBUG] Soft 404 Match (Fuzzy Words/Lines): {url} (Diff: {word_diff}w, {line_diff}l)", "GRAY")
            return True

        # 4. Heuristic: Common 404 keywords in body
        body_lower = full_text.lower()
        indicators = ["page not found", "404 error", "nothing here", "does not exist", "site not found"]
        if any(ind in body_lower for ind in indicators):
            # Only trigger if the word count is also relatively small (avoids false positives on blog posts about 404s)
            if curr_words < 500:
                if self.args.debug: self.log(f"[DEBUG] Heuristic 404 Match (Keywords): {url}", "GRAY")
                return True

        return False

    def probe_url(self, host, scheme, category, path):
        url = urljoin(f"{scheme}://{host}/", path.lstrip("/"))
        try:
            if self.args.debug:
                self.log(f"[DEBUG] Probing: {url}", "GRAY")

            # Try HEAD first
            resp = self.session.head(url, timeout=self.args.timeout, verify=False, 
                                     allow_redirects=not self.args.no_redirects)
            
            if resp.status_code in (405, 501):
                resp = self.session.get(url, timeout=self.args.timeout, verify=False, 
                                        allow_redirects=not self.args.no_redirects, stream=True)

            if resp.status_code in (200, 206):
                # If we have a fingerprint, we MUST fetch the body to validate
                full_resp = self.session.get(url, timeout=self.args.timeout, verify=False)
                
                if self.is_soft_404(host, scheme, url, full_resp):
                    return None

                severity = SEVERITY_MAP.get(category, "INFO")
                finding = {
                    "host": host, "url": url, "category": category, "severity": severity,
                    "status": full_resp.status_code, "length": len(full_resp.content),
                    "type": full_resp.headers.get("Content-Type", "?").split(";")[0],
                    "timestamp": datetime.utcnow().isoformat()
                }
                self._print_finding(finding)
                return finding
                
            elif self.args.debug:
                self.log(f"[DEBUG] {url} returned HTTP {resp.status_code}", "GRAY")
        except Exception as e:
            if self.args.debug:
                self.log(f"[DEBUG] Error probing {url}: {e}", "GRAY")
        return None

    def _print_finding(self, f):
        color = COLORS.get(f["severity"], COLORS["RESET"])
        print(f"  {color}[{f['severity']}] {COLORS['RESET']}{COLORS['BOLD']}{f['url']}{COLORS['RESET']} "
              f"({f['type']}, {f['length']} bytes)")

    def run(self):
        self.start_time = time.time()
        
        # Phase 1: Discovery
        self.log("\n[*] Phase 1: Subdomain Discovery", "BOLD")
        hosts = set()
        if self.args.hosts:
            if os.path.exists(self.args.hosts):
                with open(self.args.hosts) as f:
                    hosts.update(line.strip().lower() for line in f if line.strip())
        else:
            if not self.args.no_crtsh:
                self.log("[*] Querying crt.sh...", "GRAY")
                hosts.update(self.fetch_crtsh(self.args.domain))
        
        if self.args.include_domain or not hosts:
            hosts.add(self.args.domain)

        live_hosts = self.resolve_hosts(hosts)
        self.log(f"[+] Identified {len(live_hosts)} live hosts\n", "GREEN")

        if self.args.phase1_only:
            self.log("[!] Phase 1 only requested. Exiting.", "INFO")
            return

        if not live_hosts: return

        # Phase 2: Autocalibration
        self.log("[*] Phase 2: Establishing Soft 404 Baselines", "BOLD")
        for host in live_hosts:
            for scheme in self.args.schemes:
                self.autocalibrate(host, scheme)
        self.log(f"[+] Calibrated fingerprints for {len(self.soft404_registry)} endpoints\n", "GREEN")

        # Phase 3: Probing
        self.log("[*] Phase 3: Vulnerability Probing", "BOLD")
        self.log(f"[*] Analysis: Multi-factor fuzzy matching enabled. Threads: {self.args.threads}\n", "GRAY")

        tasks = set()
        for host in live_hosts:
            for scheme in self.args.schemes:
                for cat in self.args.categories:
                    for path in SENSITIVE_PATHS.get(cat, []):
                        tasks.add((host, scheme, cat, path))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.args.threads) as executor:
            future_to_probe = {executor.submit(self.probe_url, *t): t for t in tasks}
            for future in concurrent.futures.as_completed(future_to_probe):
                res = future.result()
                if res: self.findings.append(res)

        self.report()

    def report(self):
        elapsed = time.time() - self.start_time
        self.log(f"\n{'-'*60}", "GRAY")
        self.log(f"  SCAN COMPLETE — {len(self.findings)} findings in {elapsed:.1f}s", "BOLD", True)
        self.log(f"{'-'*60}\n", "GRAY")

        if self.args.output:
            report_data = {
                "target": self.args.domain,
                "scan_time": datetime.utcnow().isoformat(),
                "duration_seconds": round(elapsed, 2),
                "total_findings": len(self.findings),
                "findings": self.findings
            }
            with open(f"{self.args.output}.json", "w") as f:
                json.dump(report_data, f, indent=2)
            self.log(f"[+] Results saved to {self.args.output}.json", "GREEN")

# Sensitive Path Catalogue
SENSITIVE_PATHS = {
    "VCS": [".git/config"],
    "ENV_SECRETS": [".env"],
    "APP_CONFIG": ["web.config"],
    "BACKUP_FILES": ["backup.sql", "phpinfo.php"],
    "LOG_FILES": ["error.log"],
    "PACKAGE_MANIFESTS": ["package.json"],
    "CLOUD_INFRA": ["Dockerfile"],
    "ADMIN_INTERFACES": ["admin/"],
    "CICD": [".github/workflows/"],
    "KEYS_CERTS": ["server.key"],
    "MISC": ["robots.txt"]
}

def main():
    parser = argparse.ArgumentParser(description="Scan.in - Sensitive File Scanner")
    parser.add_argument("-d", "--domain", required=True, help="Target domain")
    parser.add_argument("--hosts", help="File with list of hosts to scan")
    parser.add_argument("-t", "--threads", type=int, default=30, help="Threads (default 30)")
    parser.add_argument("--timeout", type=int, default=5, help="Timeout in seconds")
    parser.add_argument("--no-crtsh", action="store_true", help="Skip crt.sh")
    parser.add_argument("--no-redirects", action="store_true", help="Don't follow redirects")
    parser.add_argument("--include-domain", action="store_true", help="Include root domain")
    parser.add_argument("--schemes", nargs="+", default=["https", "http"])
    parser.add_argument("--categories", nargs="+", default=list(SENSITIVE_PATHS.keys()))
    parser.add_argument("--output", default="scan_report", help="Output filename (base)")
    parser.add_argument("--debug", action="store_true", help="Enable verbose debug logging")
    parser.add_argument("--phase1-only", action="store_true", help="Stop after Phase 1 discovery")
    
    args = parser.parse_args()
    print(f"\n{COLORS['BOLD']}{COLORS['GRAY']}Scan.in — Lightweight Sensitive File Discovery{COLORS['RESET']}")

    scanner = SensitiveScanner(args)
    try:
        scanner.run()
    except KeyboardInterrupt:
        print("\n[!] Scan aborted by user.")
        sys.exit(1)

if __name__ == "__main__":
    main()
