# Scan.in — Project Instructions

## Architecture & Design
- **Engine:** Python-based CLI tool utilizing `ThreadPoolExecutor` for high-concurrency network probing.
- **Accuracy:** Implements Soft 404 fingerprinting per host/scheme to minimize false positives.
- **Logic:** The `SensitiveScanner` class handles the lifecycle: Discovery -> Resolution -> Probing -> Reporting.
- **Configuration:** The `SENSITIVE_PATHS` catalogue is located at the bottom of `scanner.py` to maintain focus on the core logic.

## Engineering Conventions
- **Code Style:** Strictly follow PEP 8.
- **Performance:** Maintain the flattened threading model. Avoid introducing nested loops that block the global executor.
- **Dependencies:** Keep dependencies minimal. Currently only requires `requests`.
- **Surgical Updates:** When modifying `scanner.py`, use the `replace` tool for targeted edits. Do not refactor the entire class unless explicitly requested.

## Workflow & Safety
- **Vulnerability Assessment:** Only run against authorized domains.
- **Artifacts:** All scan results must be saved as `.json`. Avoid re-introducing HTML reporting unless requested.
- **Context:** Use `grep_search` to locate specific categories in the `SENSITIVE_PATHS` catalogue before modification.
