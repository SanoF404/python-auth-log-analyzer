
import csv
from collections import Counter, defaultdict
from datetime import datetime, timedelta

LOG_FILE = "sample_logs.csv"
REPORT_FILE = "alerts_report.csv"
THRESHOLD = 3
TIME_WINDOW_MINUTES = 5
DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def load_logs(filename):
    """Load and validate authentication logs from a CSV file."""
    required_columns = {
        "timestamp",
        "username",
        "ip_address",
        "event",
    }

    with open(filename, newline="", encoding="utf-8-sig") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("The CSV file is empty.")

        reader.fieldnames = [
            name.strip() for name in reader.fieldnames
        ]

        missing = required_columns - set(reader.fieldnames)

        if missing:
            raise ValueError(
                f"Missing CSV columns: {', '.join(sorted(missing))}"
            )

        logs = []

        for line_number, row in enumerate(reader, start=2):
            try:
                timestamp = datetime.strptime(
                    row["timestamp"].strip(), DATE_FORMAT
                )
                username = row["username"].strip()
                ip_address = row["ip_address"].strip()
                event = row["event"].strip().lower()

                if not username or not ip_address:
                    raise ValueError("Username or IP is empty.")

                if event not in {"success", "failed"}:
                    raise ValueError("Unknown event.")

                logs.append({
                    "timestamp": timestamp,
                    "username": username,
                    "ip_address": ip_address,
                    "event": event,
                })

            except (ValueError, AttributeError, KeyError) as error:
                print(
                    f"[WARNING] Invalid CSV line {line_number}: {error}"
                )

        return logs


def analyze_logs(logs):
    """Count failed attempts and detect repeated failures over time."""
    failed_by_ip = Counter()
    failed_by_user = Counter()
    failures_by_ip = defaultdict(list)

    for log in logs:
        if log["event"] != "failed":
            continue

        ip = log["ip_address"]
        username = log["username"]
        timestamp = log["timestamp"]

        failed_by_ip[ip] += 1
        failed_by_user[username] += 1
        failures_by_ip[ip].append(timestamp)

    suspicious_ips = []
    window = timedelta(minutes=TIME_WINDOW_MINUTES)

    for ip, timestamps in failures_by_ip.items():
        timestamps.sort()
        left = 0

        for right in range(len(timestamps)):
            while timestamps[right] - timestamps[left] > window:
                left += 1

            attempts = right - left + 1

            if attempts >= THRESHOLD:
                suspicious_ips.append({
                    "ip_address": ip,
                    "attempts": attempts,
                    "start": timestamps[left],
                    "end": timestamps[right],
                })
                break

    return failed_by_ip, failed_by_user, suspicious_ips


def export_alerts_csv(alerts, filename=REPORT_FILE):
    """Export suspicious activity alerts to a CSV report."""
    fieldnames = [
        "ip_address",
        "attempts",
        "start",
        "end",
    ]

    with open(
        filename, "w", newline="", encoding="utf-8"
    ) as file:
        writer = csv.DictWriter(file, fieldnames=fieldnames)
        writer.writeheader()

        for alert in alerts:
            writer.writerow({
                "ip_address": alert["ip_address"],
                "attempts": alert["attempts"],
                "start": alert["start"].strftime(DATE_FORMAT),
                "end": alert["end"].strftime(DATE_FORMAT),
            })


def display_alerts(failed_by_ip, failed_by_user, suspicious_ips):
    print("=== Authentication Log Analysis ===")

    print("\nFailed attempts by IP:")
    if failed_by_ip:
        for ip, count in failed_by_ip.most_common():
            print(f"- {ip}: {count}")
    else:
        print("- No failed attempts.")

    print("\nFailed attempts by user:")
    if failed_by_user:
        for username, count in failed_by_user.most_common():
            print(f"- {username}: {count}")
    else:
        print("- No failed attempts.")

    print(
        f"\nSuspicious activity "
        f"({THRESHOLD}+ failures within "
        f"{TIME_WINDOW_MINUTES} minutes):"
    )

    if suspicious_ips:
        for alert in suspicious_ips:
            print(
                f"[ALERT] IP {alert['ip_address']}: "
                f"{alert['attempts']} failures between "
                f"{alert['start']} and {alert['end']}"
            )
    else:
        print("- No activity met the detection threshold.")


def main():
    try:
        logs = load_logs(LOG_FILE)
        failed_by_ip, failed_by_user, suspicious_ips = analyze_logs(logs)

        display_alerts(
            failed_by_ip,
            failed_by_user,
            suspicious_ips,
        )

        export_alerts_csv(suspicious_ips)
        print(f"\n[OK] Report saved to: {REPORT_FILE}")

    except (OSError, ValueError) as error:
        print(f"[ERROR] {error}")


if __name__ == "__main__":
    main()
