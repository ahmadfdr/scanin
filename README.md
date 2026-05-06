# Scan.in — Sensitive File Discovery Tool

**Scan.in** is a high-performance, lightweight black-box security tool designed to discover exposed sensitive files and directories across subdomains. It leverages a three-phase engine with multi-factor autocalibration to eliminate false positives while maintaining maximum scanning speed.

## 🚀 Key Features

*   **Phase 1: Discovery** — Automated subdomain enumeration via `crt.sh` and rapid DNS resolution using optimized thread pools.
*   **Phase 2: Autocalibration** — Dynamically establishes a "Not Found" baseline for every host/scheme. It fingerprints response attributes like word counts, line counts, and HTML tags (`<title>`, `<h1>`) to detect custom error pages.
*   **Phase 3: High-Performance Probing** — Executes thousands of probes in parallel using a flattened concurrency model, bypassing the per-host bottlenecks found in traditional scanners.
*   **Intelligent Filtering** — Uses fuzzy logic (5% tolerance on size/words) and keyword heuristics to verify findings, ensuring that a `200 OK` from a custom error page is never flagged as a valid exposure.

---

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/ahmadfdr/scanin.git
    cd scan-in
    ```

2.  **Install dependencies:**
    ```bash
    pip install requests
    ```

---

## 📖 Detailed Usage & Scenarios

### 1. The "Quick Recon" (Passive Discovery)
Scan a domain using only passive certificate transparency logs. Ideal for initial surface mapping.
```bash
python scanner.py -d example.com
```

### 2. High-Speed Surface Scan (Aggressive Threading)
If you are on a high-bandwidth connection, you can increase threads to drastically reduce scan time.
```bash
python scanner.py -d example.com -t 100 --timeout 3
```

### 3. Precision Scan (Targeted Categories)
Focus only on high-impact exposures like Version Control and Environment secrets.
```bash
python scanner.py -d example.com --categories VCS ENV_SECRETS APP_CONFIG
```

### 4. Guided Scan (Using a Host List)
If you have already performed subdomain enumeration with other tools (like `subfinder`), provide the list directly.
```bash
python scanner.py -d example.com --hosts live_subdomains.txt
```

### 5. Troubleshooting & Debugging
Run a verbose scan to see exactly why certain subdomains are being processed or why specific URLs are filtered as Soft 404s.
```bash
# Isolate Phase 1 to debug discovery issues
python scanner.py -d example.com --debug --phase1-only

# Full scan with technical traces for all phases
python scanner.py -d example.com --debug
```

---

## ⚙️ Command Line Arguments Reference

| Argument | Flag | Description | Default |
| :--- | :--- | :--- | :--- |
| **Domain** | `-d`, `--domain` | The target root domain (e.g., `google.com`). | (Required) |
| **Hosts File** | `--hosts` | Path to a file containing one subdomain per line. | None |
| **Threads** | `-t`, `--threads` | Total concurrent network probes across all hosts. | 30 |
| **Timeout** | `--timeout` | Seconds to wait for each HTTP response. | 5 |
| **No Passive** | `--no-crtsh` | Skip the `crt.sh` discovery phase. | False |
| **No Redirects**| `--no-redirects`| Do not follow HTTP 301/302 redirects. | False |
| **Include Root**| `--include-domain`| Force scanning of the root domain itself. | False |
| **Categories** | `--categories` | Filter scan categories (VCS, ENV_SECRETS, etc.). | All |
| **Output** | `--output` | Base filename for the JSON report. | scan_report |
| **Debug Mode** | `--debug` | Enable detailed logs for all three phases. | False |
| **Phase 1 Only**| `--phase1-only` | Exit after host discovery and resolution. | False |

---

## 📊 Report Integration

The tool outputs a structured `.json` report designed for easy integration with security pipelines or custom dashboards.

```json
{
  "target": "example.com",
  "scan_time": "2026-05-06T14:30:05",
  "duration_seconds": 12.45,
  "total_findings": 1,
  "findings": [
    {
      "host": "dev.example.com",
      "url": "https://dev.example.com/.env",
      "category": "ENV_SECRETS",
      "severity": "CRITICAL",
      "status": 200,
      "length": 452,
      "type": "text/plain",
      "timestamp": "2026-05-06T14:30:15"
    }
  ]
}
```

---

## ⚠️ Security Disclaimer

**For authorized security testing only.** This tool is designed for Security Engineers and Penetration Testers. Always obtain explicit written permission from the target organization before initiating a scan. Use of this tool against unauthorized targets is strictly prohibited.

---
*Built with ❤️ by ahmadfdr.*