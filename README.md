# auth-log-parser

A small Python script that reads a Linux SSH authentication log and summarizes failed and successful logins, then flags activity a SOC analyst would want to look at first.

## What it does and why

SSH servers that face the internet get password-guessing attempts constantly. Reading auth.log line by line to find the ones that matter is slow, so I wrote this to do the first pass of triage:

- Counts failed and successful SSH logins
- Lists the source IPs with the most failed attempts
- Flags three things:
  1. **Brute force:** one IP with 5 or more failed attempts (adjustable with `--threshold`)
  2. **Success after failures:** a successful login from an IP that failed first. Many failures before a success is marked HIGH, because it may mean a password was guessed. A single typo is marked LOW.
  3. **Invalid usernames:** attempts against accounts that don't exist, a common sign of automated scanning
- Optionally saves the findings to a CSV file

It uses only the Python standard library, so there is nothing to install.

## How to run

Requires Python 3.

```
python3 parser.py sample_logs/auth.log
python3 parser.py sample_logs/auth.log --threshold 3
python3 parser.py sample_logs/auth.log --csv findings.csv
```

On a real Debian or Ubuntu system the log is at /var/log/auth.log and usually needs sudo to read:

```
sudo python3 parser.py /var/log/auth.log
```

Run the tests:

```
python3 -m unittest discover tests
```

## Example output

From the included sample log:

```
SSH Auth Log Summary
========================================
Failed login attempts:   22
Successful logins:       5
IPs with failed logins:  4

Top 5 IPs by failed attempts
----------------------------------------
198.51.100.23      10
203.0.113.45       9
198.51.100.77      2
10.0.0.25          1

Findings
----------------------------------------
[HIGH] Success after failures: 203.0.113.45
    users: deploy
    Logged in as 'deploy' by password at Nov 12 09:02:53 after 9 failed attempt(s)
[MEDIUM] Brute force: 198.51.100.23
    users: admin, guest, oracle, postgres, root, test, ubuntu
    10 failed attempts starting at Nov 12 08:14:07
[MEDIUM] Brute force: 203.0.113.45
    users: deploy, root, support
    9 failed attempts starting at Nov 12 09:02:14
[LOW] Success after failures: 10.0.0.25
    users: bob
    Logged in as 'bob' by password at Nov 12 07:30:09 after 1 failed attempt(s)
[LOW] Invalid usernames: 198.51.100.23
    users: admin, guest, oracle, postgres, test, ubuntu
    Tried 6 username(s) that don't exist on this server
[LOW] Invalid usernames: 198.51.100.77
    users: git, pi
    Tried 2 username(s) that don't exist on this server
[LOW] Invalid usernames: 203.0.113.45
    users: support
    Tried 1 username(s) that don't exist on this server
```

The sample log is synthetic. It uses private and documentation IP ranges and made-up usernames, and includes a scanner that only fails, a brute-force attempt that eventually gets in, a user who mistypes a password once, and normal logins.

## How it works

1. **Parse:** each line is checked against two regular expressions, one for `Failed password` lines (including `invalid user`) and one for `Accepted password` / `Accepted publickey` lines. Everything else (cron, session open and close, disconnects) is skipped. The patterns are commented in parser.py.
2. **Analyze:** the events are walked in the order they happened. Failed attempts are counted per IP, and when a login succeeds the script checks how many failures that IP had since its last successful login.
3. **Report:** findings are sorted by severity and printed, and optionally written to CSV.

sshd writes an `Invalid user X from IP` line just before each `Failed password for invalid user X` line. I only count the second one so the same attempt isn't counted twice.

## What I learned

- How sshd records failed and successful logins in auth.log, and which lines describe the same event
- Writing and testing regular expressions with named groups to pull out usernames and IPs
- Why a success after many failures matters more than the failures alone
- Keeping detection logic small and testable with unittest

## Possible next steps

- Add GeoIP or threat-intel lookups for the offending IPs
- Use time windows (for example, 5 failures within 2 minutes) instead of a total count
- Handle `message repeated N times` lines and IPv6 addresses
- Read rotated and compressed logs (auth.log.1, auth.log.2.gz)
- Send findings to a SIEM such as Splunk, or write them as JSON
