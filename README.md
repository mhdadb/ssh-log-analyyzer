# SSH Log Analyzer

A Python tool that reads an SSH `auth.log`, detects brute-force attacks and
account compromise with **rule-based detection**, and finds "low and slow"
attackers that rules miss with an **Isolation Forest** anomaly model. Results are
written as an HTML report with charts, a CSV of alerts and a JSON summary.

## Why this project

Security teams cannot read logs by hand. This project shows the full pipeline in
a small, testable codebase: parsing, detection logic, machine learning, reporting.

## Results on the included sample data

`sample_data/auth.log` is a synthetic log (896 lines, 48 source IPs, 7 days) with
known attack scenarios. All attacker addresses use the reserved documentation
ranges from RFC 5737, so the data is safe to publish.

| Scenario in the data | Found by |
|---|---|
| Fast brute force, 300 attempts in about 10 min (`203.0.113.50`) | Brute-force rule and ML |
| Account guessing, 25 usernames in about 3 min (`198.51.100.23`) | Enumeration rule and ML |
| 40 failures, then a successful login as `deploy` (`203.0.113.99`) | **Success-after-failures rule (high severity)** and ML |
| Two smaller brute-force bursts (`198.51.100.77`, `192.0.2.14`) | Brute-force rule |
| **Low and slow**: 1 attempt every ~4 min for 13 h (`192.0.2.77`) | **ML only**, rules miss it by design |

The rule engine raised 7 alerts and all of them were real attackers. None of the
internal users (`10.0.0.x`) was flagged. The slow attacker is the reason the ML
step exists: it stays under every per-minute threshold, but its overall behaviour
(200 events, 100% failures, active for 13 hours) is unusual compared with other
addresses.

Open `reports/report.html` to see the generated report.

## Detection logic

| Rule | What it looks for | Severity |
|---|---|---|
| `brute_force` | N or more failed logins from one IP inside a sliding time window (default 5 in 60 s) | medium, high at 3x threshold |
| `user_enumeration` | 5 or more distinct usernames from one IP within 10 minutes | medium |
| `success_after_failures` | A successful login right after many failures from the same IP | high |

**ML step:** per-IP features (event count, failure ratio, distinct usernames,
peak events per minute, active duration) are standardised and passed to an
Isolation Forest. Only IPs whose traffic is mostly failures are reported, because
a heavy legitimate user is also "unusual" and would be a false alarm.

## Install and run

Requires Python 3.9 or newer.

```bash
git clone <your-repo-url>
cd log-analyzer
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt

# 1. (optional) create a fresh synthetic log
python -m loganalyzer generate -o sample_data/auth.log

# 2. analyze a log
python -m loganalyzer analyze sample_data/auth.log --year 2026 -o reports
```

Useful options:

```
--threshold 5     failures per window to flag
--window 60       window size in seconds
--min-users 5     distinct usernames to flag enumeration
--year 2026       syslog has no year, so you provide it (default: current year)
--no-ml           skip the Isolation Forest step
```

To analyze a real server, point it at `/var/log/auth.log` (Debian and Ubuntu) on
a machine you own or administer.

## Run the tests

```bash
python -m unittest discover -s tests -v
```

23 tests cover parsing (including IPv6 and malformed lines), every rule at its
boundaries, the full pipeline against the known attackers, and HTML escaping.

## Security notes

- Log content is attacker-controlled (an attacker can choose their username), so
  every value is HTML-escaped in the report. A test checks that a username like
  `<script>alert(1)</script>` is not executed.
- The tool only reads files; it never connects to any host.

## Project structure

```
loganalyzer/
  parser.py     regex parsing of sshd lines into Event objects
  detector.py   rule-based detection and summary statistics
  anomaly.py    feature engineering and Isolation Forest
  generator.py  reproducible synthetic log with labelled attacks
  report.py     CSV, JSON and HTML report with matplotlib charts
  cli.py        command-line interface
tests/          unit and end-to-end tests
sample_data/    generated example log
reports/        example output
```

## Limitations and ideas

- Only OpenSSH password and public-key messages are parsed.
- Syslog timestamps have no year, so a log that spans New Year is not handled.
- The model has no labelled data. It is a triage aid, not a replacement for a SIEM.
- Possible next steps: GeoIP enrichment, Fail2ban rule export, streaming mode.

## License

MIT
