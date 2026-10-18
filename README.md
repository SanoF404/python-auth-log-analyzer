# Python Authentication Log Analyzer

A lightweight Python tool for defensive security analysis that processes authentication logs, identifies repeated failed login attempts, and generates CSV reports of potentially suspicious activity.

## Overview

Authentication logs are useful for identifying unusual login activity. This project analyzes authentication events to help detect repeated failed login attempts within a defined time window.

The tool is designed as an educational cybersecurity project using sample log data. It demonstrates log processing, basic threat detection, data validation, automated testing, and report generation in Python.

## Features

- **Log parsing:** Reads authentication events from CSV files.
- **Data validation:** Checks required columns, timestamps, and supported event types.
- **Failed login analysis:** Counts failed authentication attempts by IP address and username.
- **Suspicious activity detection:** Flags IP addresses associated with at least 3 failed attempts within a 5-minute window.
- **CSV report generation:** Exports detected alerts into a structured report.
- **Automated testing:** Includes unit tests for detection logic, successful logins, time windows, and CSV exports.

## Technologies

- Python 3
- CSV file processing
- `datetime` for timestamp handling
- `unittest` for automated testing
- Git and GitHub

The project uses Python's standard library and does not require additional Python packages.

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

- `log_analyzer.py`: Main application and detection logic.
- `sample_logs.csv`: Sample authentication events.
- `test_log_analyzer.py`: Automated unit tests.
- `alerts_report.csv`: Generated report containing detected alerts.
- `.gitignore`: Excludes temporary and unnecessary files from Git.

The report is generated when the application runs; it does not need to be maintained manually.

## Requirements

- Python 3.10 or newer recommended.
- Git is optional if you download the project as a ZIP archive.

## Installation

Clone the repository:

```bash
git clone https://github.com/la3rous/python-auth-log-analyzer.git
```

Navigate to the project directory:

```bash
cd python-auth-log-analyzer
```

Check your Python installation:

```bash
python --version
```

## Usage

Run the analyzer:

```bash
python log_analyzer.py
```

The program processes the sample logs, displays failed login statistics, identifies suspicious activity, and generates `alerts_report.csv`.

### Example output

```text
=== Authentication Log Analysis ===

Failed attempts by IP:
- 192.0.2.10: 4

Failed attempts by user:
- amine: 4

Suspicious activity (3+ failures within 5 minutes):
[ALERT] IP 192.0.2.10: 3 failures between
2026-10-01 09:01:00 and 2026-10-01 09:03:00

[OK] Report saved to: alerts_report.csv
```

The example uses fictional authentication events and documentation-only IP addresses.

## Running the Tests

Run the automated test suite:

```bash
python -m unittest -v
```

The current test suite covers:

- Counting failed authentication attempts.
- Detecting repeated failures within five minutes.
- Avoiding alerts when attempts are too far apart.
- Ignoring successful logins during failed-attempt analysis.
- Exporting alerts to CSV.
- Generating CSV headers when no alerts are detected.

## Detection Logic

The analyzer uses a configurable threshold and time window:

| Parameter | Value |
|---|---|
| Failed attempts threshold | 3 |
| Time window | 5 minutes |
| Input format | CSV |
| Output format | CSV |

An alert is generated when the configured threshold is reached by failed attempts associated with the same IP address within the specified time window.

These alerts indicate potentially suspicious activity, not proof of an attack.

## Limitations and Future Improvements

This project is a learning tool and is not intended to replace a production Security Information and Event Management (SIEM) system.

Possible improvements include:

- Configurable detection thresholds.
- More detailed detection rules and alert severity levels.
- Detection of unusual activity across multiple accounts.
- Improved error handling and logging.
- Support for additional log formats.
- Interactive dashboards and graphical statistics.
- Integration with a database for storing historical events.

## Security and Data Privacy

The included dataset contains fictional authentication events. Use authorized logs and respect applicable privacy and data protection requirements when analyzing real authentication data.

## Author

Developed as a personal project to practice Python programming, defensive cybersecurity, authentication log analysis, and automated testing.

## License

This project is intended for educational purposes. A formal open-source license can be added if the project is distributed for reuse.