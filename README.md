# Scan.in — Sensitive File Discovery Tool

**Scan.in** is a high-performance, lightweight black-box security tool designed to discover exposed sensitive files and directories across subdomains. It aligns with **OWASP Top 10 A05: Security Misconfiguration** to help security engineers and researchers identify data leaks and server misconfigurations.

## 🚀 Key Features

*   **Subdomain Discovery:** 
    *   **Passive:** Automated querying of `crt.sh` (Certificate Transparency logs).
    *   **Active:** Fast DNS resolution for user-provided host lists.
*   **High-Performance Probing:**
    *   **Optimized Threading:** Uses a flattened `ThreadPoolExecutor` to probe hosts and paths concurrently, preventing bottlenecks from slow targets.
    *   **Efficient Requests:** Employs `HTTP HEAD` requests for speed, falling back to `GET` only when necessary.
*   **Accuracy (Anti-False Positive):**
    *   **Soft 404 Detection:** Automatically identifies and filters out "fake 200 OK" responses by fingerprinting non-existent random paths.
*   **Comprehensive Catalogue:** Scans for common leak patterns including:
    *   Version Control Systems (`.git`, `.svn`)
    *   Environment & Secrets (`.env`, `credentials.json`)
    *   Application Configs (`wp-config.php`, `web.config`)
    *   Backups, Logs, and CI/CD configurations.
*   **Clean Reporting:** Generates structured `.json` reports for easy analysis and integration with other tools.

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

## 📖 Usage

### Basic Scan
Perform a passive subdomain discovery and scan for all sensitive categories:
```bash
python scanner.py -d example.com
```

### Advanced Scan
Bruteforce using a custom host list with high concurrency and custom output:
```bash
python scanner.py -d example.com --hosts hosts.txt -t 50 --output my_scan
```

### Specific Categories
Limit the scan to specific types of files (e.g., VCS and Environment secrets):
```bash
python scanner.py -d example.com --categories VCS ENV_SECRETS
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
*Built with ❤️ by @ahmadfdr.*
