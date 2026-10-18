
import csv
import os
import tempfile
import unittest
from datetime import datetime

from log_analyzer import analyze_logs, export_alerts_csv


class TestLogAnalyzer(unittest.TestCase):

    def make_log(self, minute, event="failed", username="amine"):
        return {
            "timestamp": datetime.strptime(
                f"2026-10-01 09:{minute:02d}:00",
                "%Y-%m-%d %H:%M:%S",
            ),
            "username": username,
            "ip_address": "192.0.2.10",
            "event": event,
        }

    def test_counts_failed_attempts(self):
        logs = [
            self.make_log(0),
            self.make_log(1),
            self.make_log(2, event="success"),
        ]

        failed_by_ip, failed_by_user, alerts = analyze_logs(logs)

        self.assertEqual(failed_by_ip["192.0.2.10"], 2)
        self.assertEqual(failed_by_user["amine"], 2)
        self.assertEqual(len(alerts), 0)

    def test_detects_repeated_failures_within_five_minutes(self):
        logs = [
            self.make_log(0),
            self.make_log(2),
            self.make_log(4),
        ]

        _, _, alerts = analyze_logs(logs)

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["attempts"], 3)

    def test_does_not_alert_when_attempts_are_too_far_apart(self):
        logs = [
            self.make_log(0),
            self.make_log(6),
            self.make_log(12),
        ]

        _, _, alerts = analyze_logs(logs)

        self.assertEqual(len(alerts), 0)

    def test_ignores_successful_logins(self):
        logs = [
            self.make_log(0, event="success"),
            self.make_log(1, event="success"),
            self.make_log(2, event="success"),
        ]

        failed_by_ip, failed_by_user, alerts = analyze_logs(logs)

        self.assertEqual(sum(failed_by_ip.values()), 0)
        self.assertEqual(sum(failed_by_user.values()), 0)
        self.assertEqual(len(alerts), 0)

    def test_exports_alerts_to_csv(self):
        logs = [
            self.make_log(0),
            self.make_log(1),
            self.make_log(2),
        ]

        _, _, alerts = analyze_logs(logs)

        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = os.path.join(
                temp_dir, "alerts_report.csv"
            )

            export_alerts_csv(alerts, report_path)

            with open(
                report_path, newline="", encoding="utf-8"
            ) as file:
                rows = list(csv.DictReader(file))

        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["ip_address"], "192.0.2.10")
        self.assertEqual(rows[0]["attempts"], "3")
        self.assertEqual(rows[0]["start"], "2026-10-01 09:00:00")
        self.assertEqual(rows[0]["end"], "2026-10-01 09:02:00")

    def test_exports_headers_when_there_are_no_alerts(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            report_path = os.path.join(
                temp_dir, "alerts_report.csv"
            )

            export_alerts_csv([], report_path)

            with open(
                report_path, newline="", encoding="utf-8"
            ) as file:
                reader = csv.DictReader(file)
                rows = list(reader)
                headers = reader.fieldnames

        self.assertEqual(
            headers, ["ip_address", "attempts", "start", "end"]
        )
        self.assertEqual(rows, [])


if __name__ == "__main__":
    unittest.main()
