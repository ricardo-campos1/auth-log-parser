"""Tests for parser.py, run against the sample log.

Run from the repo root:
    python3 -m unittest discover tests
"""

import csv
import os
import sys
import tempfile
import unittest

# Let the tests import parser.py from the repo root
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, REPO_ROOT)

import parser as auth_parser  # noqa: E402

SAMPLE_LOG = os.path.join(REPO_ROOT, "sample_logs", "auth.log")


def findings_of_type(results, name):
    """Return only the findings with the given 'finding' name."""
    return [f for f in results["findings"] if f["finding"] == name]


class ParseLineTests(unittest.TestCase):
    def test_failed_password_valid_user(self):
        line = ("Nov 12 09:02:14 web01 sshd[2191]: Failed password for root "
                "from 203.0.113.45 port 50143 ssh2")
        event = auth_parser.parse_line(line)
        self.assertEqual(event["type"], "failed")
        self.assertEqual(event["user"], "root")
        self.assertEqual(event["ip"], "203.0.113.45")
        self.assertFalse(event["invalid"])

    def test_failed_password_invalid_user(self):
        line = ("Nov 12 09:02:27 web01 sshd[2212]: Failed password for invalid user "
                "support from 203.0.113.45 port 50152 ssh2")
        event = auth_parser.parse_line(line)
        self.assertEqual(event["user"], "support")
        self.assertTrue(event["invalid"])

    def test_accepted_publickey(self):
        line = ("Nov 12 06:12:44 web01 sshd[2107]: Accepted publickey for alice "
                "from 192.168.1.10 port 52210 ssh2: ED25519 SHA256:abc")
        event = auth_parser.parse_line(line)
        self.assertEqual(event["type"], "accepted")
        self.assertEqual(event["method"], "publickey")
        self.assertEqual(event["user"], "alice")

    def test_other_lines_are_ignored(self):
        ignored = [
            "Nov 12 06:00:01 web01 CRON[1888]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)",
            "Nov 12 08:14:05 web01 sshd[2121]: Invalid user admin from 198.51.100.23 port 50113",
            "Nov 12 09:04:03 web01 sshd[2254]: Disconnected from user deploy 203.0.113.45 port 50170",
        ]
        for line in ignored:
            self.assertIsNone(auth_parser.parse_line(line), line)


class SampleLogTests(unittest.TestCase):
    def setUp(self):
        self.events = auth_parser.parse_log(SAMPLE_LOG)
        self.results = auth_parser.analyze(self.events, threshold=5)

    def test_totals(self):
        self.assertEqual(self.results["total_failed"], 22)
        self.assertEqual(self.results["total_accepted"], 5)

    def test_brute_force_ips(self):
        ips = {f["ip"] for f in findings_of_type(self.results, "Brute force")}
        self.assertEqual(ips, {"198.51.100.23", "203.0.113.45"})

    def test_successful_brute_force_is_high(self):
        hits = findings_of_type(self.results, "Success after failures")
        high = [f for f in hits if f["severity"] == "HIGH"]
        self.assertEqual(len(high), 1)
        self.assertEqual(high[0]["ip"], "203.0.113.45")
        self.assertEqual(high[0]["usernames"], "deploy")
        self.assertEqual(high[0]["failed_attempts"], 9)

    def test_single_typo_is_low_and_not_repeated(self):
        # bob mistypes once, logs in, then logs in again later.
        # Only the first login should be flagged, and only as LOW.
        bob = [f for f in findings_of_type(self.results, "Success after failures")
               if f["ip"] == "10.0.0.25"]
        self.assertEqual(len(bob), 1)
        self.assertEqual(bob[0]["severity"], "LOW")

    def test_invalid_usernames(self):
        by_ip = {f["ip"]: f["usernames"] for f in findings_of_type(self.results, "Invalid usernames")}
        self.assertEqual(by_ip["198.51.100.77"], "git, pi")
        self.assertIn("oracle", by_ip["198.51.100.23"])

    def test_threshold_option(self):
        # With a high threshold, nothing counts as brute force
        results = auth_parser.analyze(self.events, threshold=50)
        self.assertEqual(findings_of_type(results, "Brute force"), [])

    def test_csv_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "findings.csv")
            auth_parser.write_csv(self.results["findings"], path)
            with open(path, newline="", encoding="utf-8") as f:
                rows = list(csv.DictReader(f))
        self.assertEqual(len(rows), len(self.results["findings"]))
        self.assertEqual(rows[0]["severity"], "HIGH")


if __name__ == "__main__":
    unittest.main()
