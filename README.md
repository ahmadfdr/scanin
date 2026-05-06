# Scan.in — Sensitive File Discovery Tool

**Scan.in** is a high-performance, lightweight black-box security tool designed to discover exposed sensitive files and directories across subdomains. It aligns with **OWASP Top 10 A05: Security Misconfiguration** to help security engineers and researchers identify data leaks and server misconfigurations.

## 🚀 Key Features

*   **Subdomain Discovery:** 
    *   **Passive:** Automated querying of `crt.sh` (Certificate Transparency logs) with robust retry logic.
    *   **Active:** Fast DNS resolution for user-provided host lists.
*   **High-Performance Probing:**
    *   **Optimized Threading:** Uses a flattened `ThreadPoolExecutor` to probe hosts and paths concurrently.
    *   **Efficient Requests:** Employs `HTTP HEAD` requests for speed, falling back to `GET` only when necessary.
*   **Accuracy (Anti-False Positive):**
    *   **Soft 404 Detection:** Automatically identifies and filters out "fake 200 OK" responses by fingerprinting non-existent random paths.
*   **Debugging & Troubleshooting:**
    *   **Verbose Logging:** Use `--debug` to see detailed discovery and DNS resolution traces.
    *   **Phase Isolation:** Use `--phase1-only` to test subdomain discovery without running the full scan.

## 🛠️ Installation

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-repo/scan-in.git
    cd scan-in
    ```

2.  **Install dependencies:**
    ```bash
    pip install requests
    ```

## 📖 Usage

### Basic Scan
Perform a passive subdomain discovery and scan for all sensitive categories:
```bash
python scanner.py -d example.com
```

### Debugging Subdomain Discovery
If you suspect subdomains are being missed, run with verbose logging and isolate Phase 1:
```bash
python scanner.py -d example.com --debug --phase1-only
```

### Advanced Scan
Bruteforce using a custom host list with high concurrency and custom output:
```bash
python scanner.py -d example.com --hosts hosts.txt -t 50 --output my_scan
```

### Command Line Options

| Argument | Description | Default |
| :--- | :--- | :--- |
| `-d`, `--domain` | Root domain to scan | (Required) |
| `--hosts` | File containing a list of subdomains (one per line) | None |
| `-t`, `--threads` | Number of concurrent threads | 30 |
| `--timeout` | HTTP request timeout in seconds | 5 |
| `--no-crtsh` | Skip passive discovery via crt.sh | False |
| `--no-redirects`| Do not follow HTTP redirects | False |
| `--output` | Base filename for the JSON report | scan_report |
| `--debug` | Enable verbose debug logging | False |
| `--phase1-only` | Stop after Phase 1 discovery | False |

## 📊 Report Format

The tool generates a `.json` file containing:
*   `target`: The root domain scanned.
*   `scan_time`: Timestamp of the scan.
*   `duration_seconds`: Total execution time.
*   `total_findings`: Number of exposed files found.
*   `findings`: A detailed list including URL, category, severity, status code, and content type.

## ⚠️ Disclaimer

**For authorized security testing only.** Always obtain written permission from the target organization before running this tool. The author is not responsible for any misuse or damage caused by this application.

---
*Built with ❤️ by ahmadfdr.*
