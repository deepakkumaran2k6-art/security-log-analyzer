"""
generate_sample_logs.py
=======================
Creates FAKE Linux SSH authentication log data and saves it to
sample_logs/auth.log

Everything in this file is fake and educational. It uses only IP addresses
from special "documentation only" ranges (203.0.113.x, 198.51.100.x,
192.0.2.x) that are reserved for examples, so no real computers are used.

The script mixes:
  * normal daily activity (office hours, a handful of trusted users)
  * a brute-force attack (many failures from one IP in a few minutes)
  * a successful login right after that burst of failures
  * password spraying (one IP trying many different usernames)
  * a login at 3 AM from an IP never seen before
  * attempts on sensitive usernames: admin, root, test, guest

Run it with:  python generate_sample_logs.py
"""

import os
import random
from datetime import datetime, timedelta

# Fix the random number generator so every run produces the exact same file.
random.seed(42)

# ---------------------------------------------------------------------------
# Settings you can change
# ---------------------------------------------------------------------------

# Where the fake log file will be saved (next to this script's folder).
OUTPUT_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                           "sample_logs", "auth.log")

# How many "normal" (non-attack) log lines to create.
NORMAL_EVENT_COUNT = 600

# The days we generate normal activity for.
DAYS = [datetime(2026, 10, 15), datetime(2026, 10, 16), datetime(2026, 10, 17)]

# Normal users and the office IP addresses they normally log in from.
NORMAL_USERS = ["alice", "bob", "carol", "dave", "erin", "frank"]
USER_IPS = {
    "alice": ["198.51.100.10", "198.51.100.11"],
    "bob":   ["198.51.100.10", "203.0.113.10"],
    "carol": ["198.51.100.11", "203.0.113.11"],
    "dave":  ["203.0.113.10", "203.0.113.11"],
    "erin":  ["198.51.100.10", "198.51.100.11"],
    "frank": ["203.0.113.10", "198.51.100.11"],
}

# Usernames that attackers love to try (privileged / default accounts).
SENSITIVE_USERNAMES = ["admin", "root", "test", "guest"]


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

# Builds one fake log line in the same shape as a real Linux sshd log line.
def make_line(timestamp, action, username, ip):
    """Return a single fake log line as a string."""
    pid = random.randint(1000, 9999)        # fake process id
    port = random.randint(30000, 65000)     # fake source port
    return ("{} sshd[{}]: {} password for {} from {} port {}"
            .format(timestamp.strftime("%Y-%m-%d %H:%M:%S"),
                    pid, action, username, ip, port))


# Creates ordinary daily traffic: users logging in and out during the day.
def generate_normal_events():
    """Return a list of fake log lines for normal office-hours activity."""
    lines = []
    for i in range(NORMAL_EVENT_COUNT):
        day = random.choice(DAYS)
        # Working hours: 07:00 to 19:00, so normal users never log in at night.
        hour = random.randint(7, 19)
        minute = random.randint(0, 59)
        second = random.randint(0, 59)
        timestamp = day.replace(hour=hour, minute=minute, second=second)

        username = random.choice(NORMAL_USERS)
        ip = random.choice(USER_IPS[username])

        # Most of the time people log in fine; sometimes they mistype a password.
        action = "Accepted" if random.random() < 0.88 else "Failed"
        lines.append(make_line(timestamp, action, username, ip))
    return lines


# Plants the biggest attack: one IP hammering the "admin" account,
# then finally getting in with a accepted password.
def generate_brute_force_attack():
    """Return log lines for a brute-force burst plus the success after it."""
    lines = []
    attacker_ip = "203.0.113.66"
    username = "admin"
    start = datetime(2026, 10, 16, 14, 30, 0)

    # 35 failed attempts, one every 6-8 seconds (about 4 minutes total).
    for n in range(35):
        timestamp = start + timedelta(seconds=7 * n + random.randint(0, 2))
        lines.append(make_line(timestamp, "Failed", username, attacker_ip))

    # A minute later the attacker finally guesses the password.
    success_time = start + timedelta(minutes=4, seconds=30)
    lines.append(make_line(success_time, "Accepted", username, attacker_ip))
    return lines


# Plants a "password spraying" attack: one IP tries the same few passwords
# against lots of different usernames.
def generate_password_spray_attack():
    """Return log lines where one IP tries many different usernames."""
    lines = []
    attacker_ip = "192.0.2.77"
    usernames = ["admin", "root", "test", "guest", "user", "oracle",
                 "postgres", "ubuntu", "backup", "ftp", "git", "jenkins"]
    start = datetime(2026, 10, 16, 21, 0, 0)

    for i, name in enumerate(usernames):
        # 1 or 2 failed tries per username, one every ~30 seconds.
        for attempt in range(random.randint(1, 2)):
            timestamp = start + timedelta(seconds=30 * (2 * i + attempt))
            lines.append(make_line(timestamp, "Failed", name, attacker_ip))
    return lines


# Plants a suspicious 3 AM login from an IP that user never used before.
def generate_odd_hour_login():
    """Return log lines for a successful login at 3:14 AM from a new IP."""
    return [make_line(datetime(2026, 10, 17, 3, 14, 22),
                      "Accepted", "carol", "192.0.2.99")]


# Plants occasional tries on sensitive accounts spread far apart in time
# (so they do not accidentally trigger the brute-force rule).
def generate_sensitive_username_attempts():
    """Return scattered failed attempts on admin/root/test/guest accounts."""
    lines = []
    attacker_ip = "203.0.113.50"
    start = datetime(2026, 10, 15, 10, 0, 0)
    for i, name in enumerate(["admin", "root", "test", "guest",
                              "admin", "root", "guest", "admin"]):
        # One attempt every 15 minutes - spaced out on purpose.
        timestamp = start + timedelta(minutes=15 * i)
        lines.append(make_line(timestamp, "Failed", name, attacker_ip))
    return lines


# ---------------------------------------------------------------------------
# Main program - this runs when you execute the script
# ---------------------------------------------------------------------------
def main():
    """Create the fake log file and print a short summary."""
    print("Generating fake sample logs...")

    all_lines = []
    all_lines += generate_normal_events()
    all_lines += generate_brute_force_attack()
    all_lines += generate_password_spray_attack()
    all_lines += generate_odd_hour_login()
    all_lines += generate_sensitive_username_attempts()

    # Put the lines in chronological order, like a real log file.
    all_lines.sort(key=lambda line: line[:19])

    # Make sure the sample_logs folder exists before writing to it.
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as handle:
        handle.write("\n".join(all_lines) + "\n")

    print("Wrote {} fake log lines to:".format(len(all_lines)))
    print("  " + OUTPUT_FILE)
    print("Next run:  python analyzer.py --file sample_logs/auth.log")


# This makes the script runnable with "python generate_sample_logs.py"
# but still importable from other files (like the tests) without running.
if __name__ == "__main__":
    main()
