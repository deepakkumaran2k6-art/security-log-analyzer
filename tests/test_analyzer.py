"""
tests/test_analyzer.py
======================
A handful of simple tests that check the analyzer's rules work correctly.

Run them with:  python -m unittest discover -s tests -v
"""

import os
import sys
import unittest
from datetime import datetime

# Make it possible to import analyzer.py from the project root folder.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import analyzer  # noqa: E402  (import after sys.path setup on purpose)


# Small helper: build one event dictionary the same way parse_line does.
def make_event(timestamp, action, username, ip):
    return {
        "timestamp": datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S"),
        "action": action,
        "username": username,
        "ip": ip,
        "raw": "",
    }


class TestParsing(unittest.TestCase):
    """Tests for reading a single log line."""

    # A normal line should be parsed into the right fields.
    def test_parse_good_line(self):
        line = ("2026-10-17 03:14:22 sshd[1234]: Failed password "
                "for admin from 203.0.113.45 port 52344")
        event = analyzer.parse_line(line)
        self.assertIsNotNone(event)
        self.assertEqual(event["action"], "Failed")
        self.assertEqual(event["username"], "admin")
        self.assertEqual(event["ip"], "203.0.113.45")
        self.assertEqual(event["timestamp"].hour, 3)

    # Garbage lines should be ignored (returned as None), not crash.
    def test_parse_bad_line_returns_none(self):
        self.assertIsNone(analyzer.parse_line("this is not a log line"))
        self.assertIsNone(analyzer.parse_line(""))


class TestDetectionRules(unittest.TestCase):
    """Tests for the individual attack detection rules."""

    # 6 failures from one IP within 5 minutes should trigger brute force.
    def test_brute_force_detected(self):
        events = []
        for minute in range(6):
            events.append(make_event(
                "2026-10-16 14:3{}:00".format(minute),
                "Failed", "admin", "203.0.113.66"))
        alerts = analyzer.detect_brute_force(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "Brute force suspected")

    # 2 failures should be too few for a brute-force alert.
    def test_brute_force_not_triggered_by_two_failures(self):
        events = [
            make_event("2026-10-16 14:30:00", "Failed", "alice", "198.51.100.10"),
            make_event("2026-10-16 14:31:00", "Failed", "alice", "198.51.100.10"),
        ]
        self.assertEqual(analyzer.detect_brute_force(events), [])

    # One IP trying 6 different usernames should trigger spraying.
    def test_password_spraying_detected(self):
        users = ["admin", "root", "test", "guest", "oracle", "ubuntu"]
        events = [
            make_event("2026-10-16 21:0{}:00".format(i),
                       "Failed", name, "192.0.2.77")
            for i, name in enumerate(users)
        ]
        alerts = analyzer.detect_password_spraying(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "Password spraying suspected")

    # A success at 3 AM should be flagged as an unusual login time.
    def test_off_hours_login_detected(self):
        events = [make_event("2026-10-17 03:14:22",
                             "Accepted", "carol", "192.0.2.99")]
        alerts = analyzer.detect_off_hours_login(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "Unusual login time")

    # Daytime logins should NOT trigger the off-hours rule.
    def test_daytime_login_not_flagged(self):
        events = [make_event("2026-10-16 10:00:00",
                             "Accepted", "alice", "198.51.100.10")]
        self.assertEqual(analyzer.detect_off_hours_login(events), [])

    # Any attempt on 'root' should trigger the sensitive-account rule.
    def test_sensitive_username_detected(self):
        events = [make_event("2026-10-15 10:00:00",
                             "Failed", "root", "203.0.113.50")]
        alerts = analyzer.detect_sensitive_usernames(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["rule"], "Targeted privileged account")

    # 5 failures then a success from the same IP = HIGH severity alert.
    def test_success_after_failures_is_high_severity(self):
        events = []
        for minute in range(5):
            events.append(make_event(
                "2026-10-16 14:3{}:00".format(minute),
                "Failed", "admin", "203.0.113.66"))
        events.append(make_event("2026-10-16 14:35:00",
                                 "Accepted", "admin", "203.0.113.66"))
        alerts = analyzer.detect_success_after_failures(events)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
