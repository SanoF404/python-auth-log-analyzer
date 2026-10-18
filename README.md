# Python Authentication Log Analyzer

A lightweight Python tool for defensive cybersecurity analysis. It processes authentication logs, identifies repeated failed login attempts, and exports potentially suspicious activity to CSV reports.

## Overview

Authentication logs can help identify unusual login activity, including repeated authentication failures that may indicate a brute-force attempt.

This project analyzes authentication events within a configurable time window. It demonstrates practical Python skills in data processing, input validation, basic security monitoring, automated testing, and report generation.

The project uses fictional authentication data and is intended for educational and defensive security purposes.

## Features

- **CSV Log Parsing:** Reads authentication events from CSV files.
- **Input Validation:** Checks required columns, timestamp formats, usernames, IP addresses, and supported event types.
- **Failed Login Statistics:** Counts failed attempts by IP address and username.
- **Time-Based Detection:** Identifies repeated failed login attempts from the same IP address within a configurable time window.
- **Configurable Detection Rules:** Allows the failure threshold and time window to be customized when calling the analysis function.
- **CSV Report Generation:** Exports detected alerts to a structured CSV report.
- **Automated Unit Tests:** Tests detection behavior, configurable thresholds, input parameters, successful logins, and CSV exports.

## Technologies

- Python 3
- CSV processing
- `datetime` and `timedelta`
- `collections.Counter` and `collections.defaultdict`
- `unittest`
- Git and GitHub

The project uses Python's standard library and does not require third-party packages.

## Project Structure

```text
python-auth-log-analyzer/
├── log_analyzer.py
├── sample_logs.csv
├── test_log_analyzer.py
├── alerts_report.csv
├── .gitignore
└── README.md
```

| File | Description |
|---|---|
| `log_analyzer.py` | Main application, log validation, detection logic, and report generation |
| `sample_logs.csv` | Fictional authentication events used for analysis |
| `test_log_analyzer.py` | Automated unit tests |
| `alerts_report.csv` | Generated report containing detected alerts |
| `.gitignore` | Excludes Python cache files and other unnecessary files from Git |

The report is generated when the application runs.

## Requirements

- Python 3.10 or newer recommended.
- Git is optional if you download the repository as a ZIP archive.

## Installation

Clone the repository:

```bash
git clone https://github.com/la3rous/python-auth-log-analyzer.git
```

Navigate to the project directory:

```bash
cd python-auth-log-analyzer
```

Check your Python version:

```bash
python --version
```

No additional package installation is required.

## Usage

Run the analyzer:

```bash
python log_analyzer.py
```

By default, the application reads `sample_logs.csv`, analyzes failed authentication attempts, displays statistics, and generates `alerts_report.csv`.

### Example Output

```text
=== Authentication Log Analysis ===

Failed attempts by IP:
- 192.0.2.10: 4

Failed attempts by user:
- amine: 4

Suspicious activity (3+ failures within 5 minutes):
[ALERT] IP 192.0.2.10: 3 failures between 2026-10-01 09:01:00 and 2026-10-01 09:03:00

[OK] Report saved to: alerts_report.csv
```

The example uses fictional authentication events and documentation-only IP addresses.

## Running the Tests

Run the test suite:

```bash
python -m unittest -v
```

The current test suite contains **10 unit tests** covering:

- Counting failed authentication attempts by IP address and username.
- Detecting repeated failures within the configured time window.
- Detecting separate suspicious periods.
- Avoiding alerts when attempts are too far apart.
- Ignoring successful logins in failed-attempt statistics.
- Supporting a custom failure threshold.
- Rejecting an invalid threshold.
- Rejecting a negative time window.
- Exporting alerts to CSV.
- Generating CSV headers when no alerts are detected.

The tests use Python's built-in `unittest` framework.

## Detection Logic

The analyzer groups failed authentication events by IP address and examines their timestamps using a sliding time window.

Default configuration:

| Parameter | Default |
|---|---|
| Failed-attempt threshold | 3 |
| Time window | 5 minutes |
| Input format | CSV |
| Output format | CSV |

The analysis function also accepts custom parameters:

```python
failed_by_ip, failed_by_user, alerts = analyze_logs(
    logs,
    threshold=2,
    time_window_minutes=5,
)
```

This example lowers the detection threshold to two failed attempts within five minutes.

The current implementation suppresses repeated alerts for a recent period according to its configured time window. Its behavior should be validated against the intended detection policy, particularly for overlapping or continuous sequences of failed attempts.

An alert indicates potentially suspicious activity, not proof of a successful attack.

## Limitations and Future Improvements

This project is an educational prototype, not a replacement for an enterprise Security Information and Event Management (SIEM) platform.

Potential future improvements include:

- More precise handling of overlapping detection windows.
- Configurable rules through command-line arguments or a configuration file.
- Alert severity levels and richer alert details.
- Detection of suspicious activity targeting multiple accounts.
- Additional log formats and more robust validation.
- Improved logging and error reporting.
- A dashboard with graphical statistics.
- Database integration for historical analysis.

## Security and Data Privacy

The included dataset uses fictional authentication events. When analyzing real logs, use only data you are authorized to access and follow applicable privacy and data protection requirements.

## Author

Developed as a personal project to practice Python programming, defensive cybersecurity, authentication log analysis, data validation, and automated testing.

## License

No open-source license has been specified yet. Add a license file if you decide to distribute the project for reuse.
