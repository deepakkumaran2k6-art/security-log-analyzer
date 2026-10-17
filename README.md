# Security Log Analyzer

A beginner-friendly Python project that reads fake SSH authentication logs
and flags suspicious activity: brute-force attacks, password spraying,
odd-hour logins, new/unusual IPs, and attacks on privileged accounts.

> **Educational and defensive only.** This tool just *reads a text file*.
> It never connects to, scans, or attacks any system. All sample data is
> fake and uses reserved documentation IP addresses (203.0.113.x,
> 198.51.100.x, 192.0.2.x) that belong to no real computer.

---

## Why does log analysis matter?

Every server keeps a **log** — a running diary of what happened. For SSH
(the common way admins log into servers remotely), the log records every
login attempt: who tried, from which IP address, when, and whether it
worked.

Attackers almost always show up in these logs:

* A hacker guessing passwords produces dozens of **failed logins**.
* A compromised account often logs in from an **IP nobody recognizes**,
  or at **3 in the morning**.
* Attacks on `admin` or `root` are almost never accidents.

Looking through logs by hand is slow and boring — that's what this
program is for. It reads the log in a second and points a finger at the
lines worth a human's attention. This is one of the core jobs of a real
job role called a **SOC Analyst** (Security Operations Center).

---

## What you need (Windows)

1. **Install Python** — go to <https://www.python.org/downloads/> and
   click the big yellow *Download Python* button. Run the installer and
   **tick the box that says "Add python.exe to PATH"** (it's at the
   bottom of the first screen). Then click *Install Now*.
2. **Check it worked** — open *Command Prompt* (press `Win + R`, type
   `cmd`, press Enter) and type:

   ```
   python --version
   ```

   You should see something like `Python 3.12.x`. If you see an error,
   close the Command Prompt, open a new one, and try again.

No other installs are needed — the core project uses only Python's
**standard library** (the tools that come with Python itself).

---

## How to run the project

Open Command Prompt in the project folder (`D:\SecurityLogAnalyzer`) and run:

```
python generate_sample_logs.py
python analyzer.py --file sample_logs/auth.log
python -m unittest discover -s tests -v
```

1. The first command creates `sample_logs/auth.log` (about 670 fake lines).
2. The second analyzes it, prints a summary, and writes:
   * `reports/report.txt` — the full readable report
   * `reports/report.csv` — every alert as spreadsheet rows (opens in Excel)
   * `reports/failed_by_ip.png` — bar chart *(only if matplotlib is installed)*
3. The third runs the tests and should say `OK`.

**Optional chart:** `pip install matplotlib` — if you skip it, the
analyzer just prints a friendly note and carries on.

---

## The detection rules, in plain English

| Rule | What it means | Severity |
|---|---|---|
| **Possible compromised account** | Someone failed 5+ times from an IP, then *succeeded* from that same IP within 10 minutes. The password was probably guessed. | HIGH |
| **Brute force suspected** | One IP failed 5+ times in 10 minutes — like a robot trying password after password. | MEDIUM |
| **Password spraying suspected** | One IP tried 5+ *different* usernames. Instead of guessing one password, the attacker spreads weak guesses across many accounts. | MEDIUM |
| **Many IPs attacking one user** | One username was failed on from 5+ different IPs — possibly a coordinated effort. | MEDIUM |
| **Targeted privileged account** | Someone attempted `admin`, `root`, `test`, or `guest`. These are high-value targets. | MEDIUM |
| **Unusual login time** | A successful login between midnight and 5 AM. Most legitimate users are asleep. | LOW |
| **New IP for user** | A user logged in from an address that almost never appears with their account. Could be travel, a VPN, or a stolen session. | LOW |

All thresholds live as clearly named variables at the top of
`analyzer.py` (for example `FAILED_LOGIN_THRESHOLD = 5`), so you can make
the tool stricter or more relaxed without touching the rest of the code.

---

## How to read the report

**In the terminal** you get a quick summary: total events, how many
failed/succeeded, the top 5 IPs by failures, the top 5 targeted
usernames, then every alert grouped with **HIGH first**.

**`reports/report.txt`** contains the same information plus the full
detail: which rule fired, which IP, which account, the exact timestamp,
and a one-sentence explanation of *why* it was flagged.

**`reports/report.csv`** is one row per alert with columns:
`severity, rule, ip, username, timestamp, explanation`.
Open it with Excel or Google Sheets to sort/filter alerts yourself.

A typical alert looks like:

```
1. [HIGH] Possible compromised account  (203.0.113.66) at 2026-10-16 14:34:30
   Why: 35 failed attempts from 203.0.113.66 in the 10 minutes BEFORE this
   successful login - then it worked. The password may have been guessed...
```

**Reading tip:** start with HIGH alerts, then MEDIUM. LOW alerts are
noisy by design — useful hints, not emergencies.

---

## Project structure

```
SecurityLogAnalyzer/
├── README.md                 ← you are here
├── generate_sample_logs.py   ← creates the fake log data
├── analyzer.py               ← the analysis engine
├── sample_logs/
│   └── auth.log              ← generated fake data
├── reports/
│   ├── report.txt            ← full text report
│   ├── report.csv            ← alerts for spreadsheets
│   └── failed_by_ip.png      ← optional chart
└── tests/
    └── test_analyzer.py      ← checks that the rules work
```

---

## 5 ideas to improve it next

1. **GeoIP lookup** — translate an IP into a country/city using a free
   database, and flag logins from another part of the world.
2. **Email alerts** — when a HIGH alert fires, send yourself an email
   with Python's built-in `smtplib`.
3. **Windows Event Log support** — parse Windows security events
   (Event ID 4625 = failed logon) so the tool works beyond Linux SSH.
4. **Web dashboard** — serve the reports with Flask and show charts on
   a simple web page.
5. **Real-time monitoring** — watch a log file as it grows (like a tiny
   version of `tail -f`) and print alerts the moment they happen.

---

## Troubleshooting

* **`Log file not found`** — run `python generate_sample_logs.py` first.
* **`python is not recognized`** — reinstall Python with "Add to PATH"
  ticked, or try `py analyzer.py` instead of `python analyzer.py`.
* **`No readable log lines found`** — the file format is different from
  the sample. This analyzer understands lines shaped like
  `... sshd[1234]: Failed password for user from 1.2.3.4 port 1234`.
