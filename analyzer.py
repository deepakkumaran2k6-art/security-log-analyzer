"""
analyzer.py
===========
Reads an SSH authentication log and looks for signs of trouble.

This is a DEFENSIVE tool: it only READS a log file you give it.
It never connects to any computer, never scans anything, never attacks.

Run it with:  python analyzer.py --file sample_logs/auth.log
"""

import argparse
import csv
import os
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta

# ---------------------------------------------------------------------------
# DETECTION SETTINGS - change these numbers to make the tool stricter
# or more relaxed. They are all in one place on purpose.
# ---------------------------------------------------------------------------

# 5 or more failures from ONE IP within 10 minutes = brute force suspected.
FAILED_LOGIN_THRESHOLD = 5
BRUTE_FORCE_WINDOW_MINUTES = 10

# One IP trying 5 or more DIFFERENT usernames = password spraying suspected.
MANY_USERNAMES_THRESHOLD = 5

# One username failing from 5 or more DIFFERENT IPs = coordinated attack.
MANY_IPS_PER_USER_THRESHOLD = 5

# A success after 5+ recent failures from the same IP = possible compromise.
SUCCESS_AFTER_FAILURES_THRESHOLD = 5
SUCCESS_AFTER_FAILURES_WINDOW_MINUTES = 10

# Successful logins between 00:00 and 04:59 are considered unusual.
OFF_HOURS_START = 0
OFF_HOURS_END = 5

# Attempts on these accounts are always worth flagging.
SENSITIVE_USERNAMES = {"admin", "root", "test", "guest"}

# Severity levels used in alerts (highest danger first).
SEVERITY_ORDER = ["HIGH", "MEDIUM", "LOW"]

# Matches lines like:
#   2026-10-17 03:14:22 sshd[1234]: Failed password for admin from 203.0.113.45 port 52344
LOG_LINE_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\s+"
    r"sshd\[\d+\]:\s+"
    r"(?P<action>Failed|Accepted) password for (?P<username>\S+) "
    r"from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+"
)


# ---------------------------------------------------------------------------
# Reading and parsing
# ---------------------------------------------------------------------------

# Turns one text line into a Python dictionary, or None if the line is junk.
def parse_line(line):
    """Parse one log line; return a dict with time/action/user/ip, or None."""
    match = LOG_LINE_PATTERN.match(line.strip())
    if not match:
        return None
    return {
        "timestamp": datetime.strptime(match.group("timestamp"),
                                       "%Y-%m-%d %H:%M:%S"),
        "action": match.group("action"),      # "Failed" or "Accepted"
        "username": match.group("username"),
        "ip": match.group("ip"),
        "raw": line.strip(),
    }


# Reads the whole log file and returns (list_of_events, number_of_bad_lines).
def load_events(path):
    """Read a log file and return (events, skipped_line_count)."""
    if not os.path.isfile(path):
        raise FileNotFoundError(
            "Log file not found: {}\n"
            "Tip: run 'python generate_sample_logs.py' first.".format(path))

    events = []
    skipped = 0
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if not line.strip():
                continue
            parsed = parse_line(line)
            if parsed is None:
                skipped += 1
            else:
                events.append(parsed)
    events.sort(key=lambda event: event["timestamp"])
    return events, skipped


# ---------------------------------------------------------------------------
# Detection rules - each returns a list of alert dictionaries
# ---------------------------------------------------------------------------

# A "brute force" is one IP failing over and over very quickly.
def detect_brute_force(events):
    """Find IPs with many failures inside a short time window."""
    alerts = []
    failures_by_ip = defaultdict(list)
    for event in events:
        if event["action"] == "Failed":
            failures_by_ip[event["ip"]].append(event)

    window = timedelta(minutes=BRUTE_FORCE_WINDOW_MINUTES)
    for ip, failures in failures_by_ip.items():
        failures.sort(key=lambda e: e["timestamp"])
        start_index = 0
        while start_index < len(failures):
            # Extend the window as far as failures stay close together.
            end_index = start_index
            while (end_index + 1 < len(failures)
                   and failures[end_index + 1]["timestamp"]
                   - failures[start_index]["timestamp"] <= window):
                end_index += 1
            count = end_index - start_index + 1
            if count >= FAILED_LOGIN_THRESHOLD:
                window_events = failures[start_index:end_index + 1]
                usernames = sorted({e["username"] for e in window_events})
                alerts.append({
                    "severity": "MEDIUM",
                    "rule": "Brute force suspected",
                    "ip": ip,
                    "username": ", ".join(usernames),
                    "timestamp": window_events[0]["timestamp"],
                    "explanation": (
                        "{} failed logins from {} between {} and {} "
                        "({} attempted). That fast, repeated guessing looks "
                        "like a brute-force attack.").format(
                            count, ip,
                            window_events[0]["timestamp"].strftime("%H:%M:%S"),
                            window_events[-1]["timestamp"].strftime("%H:%M:%S"),
                            "/".join(usernames)),
                })
                start_index = end_index + 1   # don't count these again
            else:
                start_index += 1
    return alerts


# "Password spraying" is one IP trying a few passwords on MANY accounts.
def detect_password_spraying(events):
    """Find IPs that tried to log in as many different usernames."""
    alerts = []
    attempts_by_ip = defaultdict(list)
    for event in events:
        attempts_by_ip[event["ip"]].append(event)

    for ip, attempts in attempts_by_ip.items():
        usernames = sorted({e["username"] for e in attempts})
        if len(usernames) >= MANY_USERNAMES_THRESHOLD:
            first = min(e["timestamp"] for e in attempts)
            shown = ", ".join(usernames[:8])
            if len(usernames) > 8:
                shown += ", ..."
            alerts.append({
                "severity": "MEDIUM",
                "rule": "Password spraying suspected",
                "ip": ip,
                "username": shown,
                "timestamp": first,
                "explanation": (
                    "{} tried {} different usernames ({}). Attackers do this "
                    "to find any weak account instead of guessing one "
                    "account's password.").format(ip, len(usernames), shown),
            })
    return alerts


# One username attacked from many IPs can mean a coordinated campaign.
def detect_distributed_attack(events):
    """Find usernames whose failed logins came from many different IPs."""
    alerts = []
    failures_by_user = defaultdict(set)
    first_seen = {}
    for event in events:
        if event["action"] != "Failed":
            continue
        failures_by_user[event["username"]].add(event["ip"])
        if event["username"] not in first_seen:
            first_seen[event["username"]] = event["timestamp"]

    for username, ips in failures_by_user.items():
        if len(ips) >= MANY_IPS_PER_USER_THRESHOLD:
            alerts.append({
                "severity": "MEDIUM",
                "rule": "Many IPs attacking one user",
                "ip": "{} IPs".format(len(ips)),
                "username": username,
                "timestamp": first_seen[username],
                "explanation": (
                    "Account '{}' was targeted from {} different IPs ({}). "
                    "Someone may be attacking this account from several "
                    "places at once.").format(
                        username, len(ips),
                        ", ".join(sorted(ips)[:5])),
            })
    return alerts


# A success right after many failures often means the password was finally
# guessed - treat this as the most serious alert.
def detect_success_after_failures(events):
    """Find successful logins that came right after repeated failures."""
    alerts = []
    failures_by_ip = defaultdict(list)
    for event in events:
        if event["action"] == "Failed":
            failures_by_ip[event["ip"]].append(event)
    for ip in failures_by_ip:
        failures_by_ip[ip].sort(key=lambda e: e["timestamp"])

    window = timedelta(minutes=SUCCESS_AFTER_FAILURES_WINDOW_MINUTES)
    for event in events:
        if event["action"] != "Accepted":
            continue
        recent_failures = [
            failure for failure in failures_by_ip.get(event["ip"], [])
            if event["timestamp"] - failure["timestamp"] <= window
            and failure["timestamp"] <= event["timestamp"]
        ]
        if len(recent_failures) >= SUCCESS_AFTER_FAILURES_THRESHOLD:
            alerts.append({
                "severity": "HIGH",
                "rule": "Possible compromised account",
                "ip": event["ip"],
                "username": event["username"],
                "timestamp": event["timestamp"],
                "explanation": (
                    "{} failed attempts from {} in the {} minutes BEFORE this "
                    "successful login - then it worked. The password may have "
                    "been guessed, so this account should be checked "
                    "immediately.").format(
                        len(recent_failures), event["ip"],
                        SUCCESS_AFTER_FAILURES_WINDOW_MINUTES),
            })
    return alerts


# Nobody legitimate logs in at 3 AM (usually).
def detect_off_hours_login(events):
    """Find successful logins during the quiet night hours."""
    alerts = []
    for event in events:
        hour = event["timestamp"].hour
        if (event["action"] == "Accepted"
                and OFF_HOURS_START <= hour < OFF_HOURS_END):
            alerts.append({
                "severity": "LOW",
                "rule": "Unusual login time",
                "ip": event["ip"],
                "username": event["username"],
                "timestamp": event["timestamp"],
                "explanation": (
                    "{} logged in at {} from {}. Normal activity here happens "
                    "during the day, so a night login is worth a "
                    "look.").format(
                        event["username"],
                        event["timestamp"].strftime("%H:%M:%S"),
                        event["ip"]),
            })
    return alerts


# If an IP shows up with this user only once in the whole log, it is
# probably not one of their usual computers.
def detect_new_ip_for_user(events):
    """Find logins from IPs that a user hardly ever (or never) uses."""
    alerts = []
    pair_counts = Counter((e["username"], e["ip"]) for e in events)
    for event in events:
        if event["action"] != "Accepted":
            continue
        if pair_counts[(event["username"], event["ip"])] < 2:
            alerts.append({
                "severity": "LOW",
                "rule": "New IP for user",
                "ip": event["ip"],
                "username": event["username"],
                "timestamp": event["timestamp"],
                "explanation": (
                    "{} logged in from {}, an address almost never seen with "
                    "this account in the log. Could be travel, VPN, or "
                    "something stolen.").format(
                        event["username"], event["ip"]),
            })
    return alerts


# Hackers love default/admin accounts, so every attempt is worth noting.
def detect_sensitive_usernames(events):
    """Find any login attempt on admin/root/test/guest (grouped per IP)."""
    alerts = []
    grouped = {}
    for event in events:
        if event["username"] not in SENSITIVE_USERNAMES:
            continue
        key = (event["ip"], event["username"])
        if key not in grouped:
            grouped[key] = {"count": 0, "first": event["timestamp"],
                            "last": event["timestamp"],
                            "actions": set()}
        grouped[key]["count"] += 1
        grouped[key]["last"] = event["timestamp"]
        grouped[key]["actions"].add(event["action"])

    for (ip, username), info in grouped.items():
        alerts.append({
            "severity": "MEDIUM",
            "rule": "Targeted privileged account",
            "ip": ip,
            "username": username,
            "timestamp": info["first"],
            "explanation": (
                "{} attempts on the sensitive account '{}' from {} between {} "
                "and {}. Privileged accounts are prime targets.").format(
                    info["count"], username, ip,
                    info["first"].strftime("%H:%M:%S"),
                    info["last"].strftime("%H:%M:%S")),
        })
    return alerts


# Runs every rule above and returns one combined, sorted list of alerts.
def analyze(events):
    """Run all detection rules and return alerts sorted HIGH first."""
    alerts = []
    alerts += detect_success_after_failures(events)
    alerts += detect_brute_force(events)
    alerts += detect_password_spraying(events)
    alerts += detect_distributed_attack(events)
    alerts += detect_sensitive_usernames(events)
    alerts += detect_off_hours_login(events)
    alerts += detect_new_ip_for_user(events)
    alerts.sort(key=lambda a: (SEVERITY_ORDER.index(a["severity"]),
                               a["timestamp"]))
    return alerts


# ---------------------------------------------------------------------------
# Summary statistics and output
# ---------------------------------------------------------------------------

# Builds all the counting info shown at the top of the report.
def build_summary(events, alerts):
    """Return a dictionary of totals, top IPs and top usernames."""
    failed = [e for e in events if e["action"] == "Failed"]
    accepted = [e for e in events if e["action"] == "Accepted"]
    targeted = Counter()
    for event in events:
        targeted[event["username"]] += 1
    return {
        "total": len(events),
        "failed": len(failed),
        "accepted": len(accepted),
        "top_failed_ips": Counter(e["ip"] for e in failed).most_common(5),
        "top_usernames": targeted.most_common(5),
        "alert_counts": Counter(a["severity"] for a in alerts),
    }


# Formats one alert as a block of readable text.
def format_alert(index, alert):
    """Return a nicely formatted multi-line string for a single alert."""
    return ("  {}. [{}] {}  ({}) at {}\n"
            "     Why: {}".format(
                index, alert["severity"], alert["rule"], alert["ip"],
                alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                alert["explanation"]))


# Writes the full text report to reports/report.txt.
def write_text_report(path, summary, alerts, skipped, source_file):
    """Save the complete human-readable report as a text file."""
    lines = []
    lines.append("=" * 70)
    lines.append("SECURITY LOG ANALYSIS REPORT")
    lines.append("=" * 70)
    lines.append("Source file     : {}".format(source_file))
    lines.append("Generated at    : {}".format(
        datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
    lines.append("Unparsed lines  : {}".format(skipped))
    lines.append("")
    lines.append("-" * 70)
    lines.append("OVERVIEW")
    lines.append("-" * 70)
    lines.append("Total events    : {}".format(summary["total"]))
    lines.append("Failed logins   : {}".format(summary["failed"]))
    lines.append("Successful logins: {}".format(summary["accepted"]))
    lines.append("Alerts          : {} (HIGH {}, MEDIUM {}, LOW {})".format(
        len(alerts), summary["alert_counts"]["HIGH"],
        summary["alert_counts"]["MEDIUM"], summary["alert_counts"]["LOW"]))
    lines.append("")
    lines.append("Top 5 IPs by failed logins:")
    for rank, (ip, count) in enumerate(summary["top_failed_ips"], 1):
        lines.append("  {}. {} - {} failures".format(rank, ip, count))
    lines.append("")
    lines.append("Top 5 targeted usernames (all attempts):")
    for rank, (name, count) in enumerate(summary["top_usernames"], 1):
        lines.append("  {}. {} - {} attempts".format(rank, name, count))
    lines.append("")

    if not alerts:
        lines.append("No alerts found. The log looks quiet.")
    for severity in SEVERITY_ORDER:
        group = [a for a in alerts if a["severity"] == severity]
        if not group:
            continue
        lines.append("=" * 70)
        lines.append("{} ALERTS ({})".format(severity, len(group)))
        lines.append("=" * 70)
        for i, alert in enumerate(group, 1):
            lines.append(format_alert(i, alert))
            lines.append("")
    lines.append("=" * 70)
    lines.append("End of report")
    lines.append("=" * 70)

    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write("\n".join(lines) + "\n")
    return path


# Saves every alert as spreadsheet-friendly CSV rows.
def write_csv_report(path, alerts):
    """Save all alerts to reports/report.csv (openable in Excel)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(["severity", "rule", "ip", "username",
                         "timestamp", "explanation"])
        for alert in alerts:
            writer.writerow([
                alert["severity"],
                alert["rule"],
                alert["ip"],
                alert["username"],
                alert["timestamp"].strftime("%Y-%m-%d %H:%M:%S"),
                alert["explanation"],
            ])
    return path


# Optional bonus: a bar chart of failures per IP (needs matplotlib).
def write_chart(path, top_failed_ips):
    """Try to save a simple bar chart; skip politely if matplotlib is missing."""
    try:
        import matplotlib
        matplotlib.use("Agg")               # draw without opening a window
        import matplotlib.pyplot as plt
    except ImportError:
        print("Note: matplotlib is not installed, so no chart was created.")
        print("      (Optional - everything else still works fine.)")
        return None

    ips = [ip for ip, _ in top_failed_ips]
    counts = [count for _, count in top_failed_ips]
    plt.figure(figsize=(8, 4))
    plt.bar(ips, counts, color="salmon")
    plt.xlabel("IP address")
    plt.ylabel("Failed logins")
    plt.title("Top IPs by failed login attempts")
    plt.tight_layout()
    os.makedirs(os.path.dirname(path), exist_ok=True)
    plt.savefig(path)
    plt.close()
    return path


# Prints the friendly summary you see in the terminal.
def print_summary(summary, alerts, skipped, report_path, csv_path, chart_path):
    """Print the terminal summary of totals and alerts."""
    print("")
    print("=" * 60)
    print(" SECURITY LOG ANALYSIS SUMMARY")
    print("=" * 60)
    print("Total events      : {}".format(summary["total"]))
    print("Failed logins     : {}".format(summary["failed"]))
    print("Successful logins : {}".format(summary["accepted"]))
    if skipped:
        print("Skipped bad lines : {}".format(skipped))
    print("")
    print("Top 5 IPs by failed logins:")
    for rank, (ip, count) in enumerate(summary["top_failed_ips"], 1):
        print("  {}. {}  ({} failures)".format(rank, ip, count))
    print("")
    print("Top 5 targeted usernames:")
    for rank, (name, count) in enumerate(summary["top_usernames"], 1):
        print("  {}. {}  ({} attempts)".format(rank, name, count))
    print("")

    if not alerts:
        print("No alerts found - the log looks clean!")
    for severity in SEVERITY_ORDER:
        group = [a for a in alerts if a["severity"] == severity]
        if not group:
            continue
        print("-" * 60)
        print("{} ALERTS ({})".format(severity, len(group)))
        print("-" * 60)
        for i, alert in enumerate(group, 1):
            print(format_alert(i, alert))
            print("")

    print("=" * 60)
    print("Files written:")
    print("  Report : {}".format(report_path))
    print("  Alerts : {}".format(csv_path))
    if chart_path:
        print("  Chart  : {}".format(chart_path))


# ---------------------------------------------------------------------------
# Main program - runs when you execute: python analyzer.py --file ...
# ---------------------------------------------------------------------------
def main():
    """Parse command-line options, analyze the log, and write the reports."""
    parser = argparse.ArgumentParser(
        description="Analyze an SSH authentication log for suspicious activity.")
    parser.add_argument("--file", default="sample_logs/auth.log",
                        help="path to the log file (default: sample_logs/auth.log)")
    parser.add_argument("--outdir", default="reports",
                        help="folder for reports (default: reports)")
    args = parser.parse_args()

    try:
        events, skipped = load_events(args.file)
    except FileNotFoundError as error:
        print("ERROR: {}".format(error))
        sys.exit(1)
    except PermissionError:
        print("ERROR: Cannot read '{}'. Check the file permissions.".format(args.file))
        sys.exit(1)

    if not events:
        print("No readable log lines found in '{}'. Is it a real auth "
              "log? Try 'python generate_sample_logs.py' first.".format(args.file))
        sys.exit(1)

    alerts = analyze(events)
    summary = build_summary(events, alerts)

    report_path = write_text_report(
        os.path.join(args.outdir, "report.txt"),
        summary, alerts, skipped, args.file)
    csv_path = write_csv_report(
        os.path.join(args.outdir, "report.csv"), alerts)
    chart_path = write_chart(
        os.path.join(args.outdir, "failed_by_ip.png"),
        summary["top_failed_ips"])

    print_summary(summary, alerts, skipped, report_path, csv_path, chart_path)


# Standard "only run if executed directly" guard.
if __name__ == "__main__":
    main()
