#!/usr/bin/env python3
"""
auth-log-parser

Reads a Linux SSH authentication log (the Debian/Ubuntu /var/log/auth.log
format) and prints a short triage report:

  - totals for failed and successful SSH logins
  - the source IPs with the most failed attempts
  - findings worth a closer look:
      1. brute force: one IP with many failed attempts
      2. a successful login from an IP that failed first
      3. login attempts against usernames that don't exist on the server

Uses only the Python standard library.

Example:
    python3 parser.py sample_logs/auth.log
    python3 parser.py sample_logs/auth.log --threshold 3 --csv findings.csv
"""

import argparse
import csv
import re
import sys
from collections import Counter, defaultdict

# ---------------------------------------------------------------------------
# Regular expressions
#
# A typical auth.log line looks like this:
#
#   Nov 12 09:02:14 web01 sshd[2191]: Failed password for root from 203.0.113.45 port 50143 ssh2
#   |-- timestamp --| host  process   |----------------- message -----------------------------|
#
# Each pattern below matches one kind of sshd message we care about.
# Named groups like (?P<user>...) let us pull values out by name.
# ---------------------------------------------------------------------------

# The start of every syslog line: "Mon DD HH:MM:SS hostname sshd[PID]: "
#   (?P<timestamp>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})  -> "Nov 12 09:02:14"
#                                                        (\s+ handles "Nov  2",
#                                                        which syslog pads with a space)
#   (?P<host>\S+)                                    -> "web01"
#   sshd\[\d+\]:                                     -> "sshd[2191]:" (we only want sshd lines)
LINE_PREFIX = r"^(?P<timestamp>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd\[\d+\]: "

# A failed password attempt. Covers both of these:
#   Failed password for root from 203.0.113.45 port 50143 ssh2
#   Failed password for invalid user support from 203.0.113.45 port 50152 ssh2
#   (?P<invalid>invalid user )?  -> optional; present when the username doesn't exist
#   (?P<user>\S+)                -> the username that was tried
#   (?P<ip>[\d.]+)               -> the source IPv4 address
FAILED_RE = re.compile(
    LINE_PREFIX
    + r"Failed password for (?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)

# A successful login, by password or by SSH key:
#   Accepted password for deploy from 203.0.113.45 port 50170 ssh2
#   Accepted publickey for alice from 192.168.1.10 port 52210 ssh2: ED25519 SHA256:...
#   (?P<method>\S+)  -> "password" or "publickey"
ACCEPTED_RE = re.compile(
    LINE_PREFIX
    + r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>[\d.]+) port \d+"
)

# Note: sshd also writes a separate "Invalid user X from IP" line just before
# the matching "Failed password for invalid user X" line. We only count the
# "Failed password" line, so the same attempt isn't counted twice.


def parse_line(line):
    """Turn one log line into an event dictionary, or return None.

    Returns a dict with these keys when the line is a failed or successful
    SSH login:
        type       "failed" or "accepted"
        timestamp  the syslog timestamp text, e.g. "Nov 12 09:02:14"
        user       the username that was tried
        ip         the source IP address
        invalid    True if sshd said the username doesn't exist (failed only)
        method     "password" or "publickey" (accepted only)

    Any other line (cron, session open/close, disconnects) returns None.
    """
    match = FAILED_RE.match(line)
    if match:
        return {
            "type": "failed",
            "timestamp": match.group("timestamp"),
            "user": match.group("user"),
            "ip": match.group("ip"),
            "invalid": match.group("invalid") is not None,
        }

    match = ACCEPTED_RE.match(line)
    if match:
        return {
            "type": "accepted",
            "timestamp": match.group("timestamp"),
            "user": match.group("user"),
            "ip": match.group("ip"),
            "method": match.group("method"),
        }

    return None


def parse_log(path):
    """Read a log file and return a list of login events, in file order."""
    events = []
    # errors="replace" keeps the script running if the log has odd bytes in it
    with open(path, "r", encoding="utf-8", errors="replace") as log_file:
        for line in log_file:
            event = parse_line(line.strip())
            if event:
                events.append(event)
    return events


def analyze(events, threshold=5):
    """Count the events and build a list of findings.

    threshold is the number of failed attempts from one IP that counts as
    brute force.

    Returns a dict with:
        total_failed, total_accepted   overall counts
        failed_by_ip                   Counter of failed attempts per IP
        findings                       list of finding dicts (see below)

    Each finding has: finding, severity, ip, usernames, failed_attempts, detail.
    """
    failed_by_ip = Counter()
    users_tried_by_ip = defaultdict(set)
    invalid_users_by_ip = defaultdict(set)
    first_failure = {}
    # Failures from each IP since its last successful login. This resets on a
    # success, so one old typo doesn't get flagged again on every later login.
    failures_since_success = Counter()
    findings = []

    total_failed = 0
    total_accepted = 0

    # Walk through the events in the order they happened. Because we go in
    # order, "how many failures came before this login?" is just the counter's
    # current value when we reach a successful login.
    for event in events:
        ip = event["ip"]

        if event["type"] == "failed":
            total_failed += 1
            failed_by_ip[ip] += 1
            failures_since_success[ip] += 1
            users_tried_by_ip[ip].add(event["user"])
            first_failure.setdefault(ip, event["timestamp"])
            if event["invalid"]:
                invalid_users_by_ip[ip].add(event["user"])

        elif event["type"] == "accepted":
            total_accepted += 1
            prior_failures = failures_since_success[ip]
            failures_since_success[ip] = 0
            if prior_failures > 0:
                # A few failures before a success is usually a typo.
                # Many failures before a success may mean a guessed password.
                severity = "HIGH" if prior_failures >= threshold else "LOW"
                findings.append({
                    "finding": "Success after failures",
                    "severity": severity,
                    "ip": ip,
                    "usernames": event["user"],
                    "failed_attempts": prior_failures,
                    "detail": (
                        f"Logged in as '{event['user']}' by {event['method']} at "
                        f"{event['timestamp']} after {prior_failures} failed attempt(s)"
                    ),
                })

    # Brute force: any IP at or above the threshold.
    # most_common() sorts by count, highest first.
    for ip, count in failed_by_ip.most_common():
        if count >= threshold:
            findings.append({
                "finding": "Brute force",
                "severity": "MEDIUM",
                "ip": ip,
                "usernames": ", ".join(sorted(users_tried_by_ip[ip])),
                "failed_attempts": count,
                "detail": f"{count} failed attempts starting at {first_failure[ip]}",
            })

    # Invalid usernames: attempts against accounts that don't exist.
    for ip in sorted(invalid_users_by_ip):
        names = sorted(invalid_users_by_ip[ip])
        findings.append({
            "finding": "Invalid usernames",
            "severity": "LOW",
            "ip": ip,
            "usernames": ", ".join(names),
            "failed_attempts": failed_by_ip[ip],
            "detail": f"Tried {len(names)} username(s) that don't exist on this server",
        })

    # Show the most serious findings first.
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    findings.sort(key=lambda f: severity_order[f["severity"]])

    return {
        "total_failed": total_failed,
        "total_accepted": total_accepted,
        "failed_by_ip": failed_by_ip,
        "findings": findings,
    }


def print_report(results, top=5):
    """Print a plain-text summary of the analysis."""
    print("SSH Auth Log Summary")
    print("=" * 40)
    print(f"Failed login attempts:   {results['total_failed']}")
    print(f"Successful logins:       {results['total_accepted']}")
    print(f"IPs with failed logins:  {len(results['failed_by_ip'])}")
    print()

    print(f"Top {top} IPs by failed attempts")
    print("-" * 40)
    if not results["failed_by_ip"]:
        print("(none)")
    for ip, count in results["failed_by_ip"].most_common(top):
        print(f"{ip:<18} {count}")
    print()

    print("Findings")
    print("-" * 40)
    if not results["findings"]:
        print("No findings.")
    for f in results["findings"]:
        print(f"[{f['severity']}] {f['finding']}: {f['ip']}")
        print(f"    users: {f['usernames']}")
        print(f"    {f['detail']}")


def write_csv(findings, path):
    """Save the findings to a CSV file (opens in Excel or a SIEM import)."""
    fields = ["severity", "finding", "ip", "usernames", "failed_attempts", "detail"]
    with open(path, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fields)
        writer.writeheader()
        for f in findings:
            writer.writerow({key: f[key] for key in fields})


def main(argv=None):
    """Read command-line options, run the analysis and print the report."""
    arg_parser = argparse.ArgumentParser(
        description="Summarize SSH logins in a Linux auth.log and flag suspicious activity."
    )
    arg_parser.add_argument("logfile", help="path to the auth log, e.g. /var/log/auth.log")
    arg_parser.add_argument(
        "--threshold", type=int, default=5,
        help="failed attempts from one IP that count as brute force (default: 5)",
    )
    arg_parser.add_argument("--csv", metavar="FILE", help="also save findings to this CSV file")
    args = arg_parser.parse_args(argv)

    if args.threshold < 1:
        arg_parser.error("--threshold must be 1 or more")

    try:
        events = parse_log(args.logfile)
    except OSError as error:
        # Covers a missing file and permission errors (auth.log usually needs sudo)
        print(f"Could not read {args.logfile}: {error}", file=sys.stderr)
        return 1

    results = analyze(events, threshold=args.threshold)
    print_report(results)

    if args.csv:
        write_csv(results["findings"], args.csv)
        print()
        print(f"Findings saved to {args.csv}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
