#!/usr/bin/env python3

import argparse
import csv
import glob
import os
import re
from collections import defaultdict, Counter
from datetime import datetime


# -----------------------------
# Regex patterns for OpenVPN logs
# -----------------------------

IP_RE = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
PORT_RE = r"(?::(?P<port>\d+))?"

PATTERNS = {
    "auth_failed": re.compile(r"AUTH_FAILED|authentication failed|Auth failed", re.IGNORECASE),
    "tls_error": re.compile(r"TLS Error|TLS Auth Error|TLS key negotiation failed|tls-error", re.IGNORECASE),
    "verify_error": re.compile(r"VERIFY ERROR|certificate verify failed|VERIFY FAIL", re.IGNORECASE),
    "connection_reset": re.compile(r"Connection reset|connection-reset|ECONNRESET", re.IGNORECASE),
    "reconnect": re.compile(r"client-instance restarting|SIGUSR1|restarting", re.IGNORECASE),
    "possible_success": re.compile(
        r"Peer Connection Initiated|Initialization Sequence Completed|MULTI_sva|PUSH_REPLY",
        re.IGNORECASE
    ),
    "bad_source": re.compile(r"MULTI: bad source address", re.IGNORECASE),
}

IP_PATTERNS = [
    re.compile(r"\[AF_INET\]" + IP_RE + PORT_RE),
    re.compile(r"from " + IP_RE + PORT_RE, re.IGNORECASE),
    re.compile(r"TCP/UDP: Incoming packet from " + IP_RE + PORT_RE, re.IGNORECASE),
    re.compile(r"TLS: Initial packet from \[AF_INET\]" + IP_RE + PORT_RE, re.IGNORECASE),
]

# Common OpenVPN format:
# username/1.2.3.4:12345 message
USER_IP_RE = re.compile(
    r"(?P<user>[A-Za-z0-9_.@\-\\]+)/(?:\[AF_INET\])?"
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})(?::(?P<port>\d+))?"
)

# Certificate common name examples:
# VERIFY OK: depth=0, CN=username
CN_RE = re.compile(r"CN=(?P<cn>[A-Za-z0-9_.@\-\\]+)")

# OpenVPN username prompt examples:
# username 'bob'
USERNAME_RE = re.compile(r"username ['\"]?(?P<user>[A-Za-z0-9_.@\-\\]+)['\"]?", re.IGNORECASE)


# -----------------------------
# Timestamp parsing
# -----------------------------

TIMESTAMP_FORMATS = [
    "%Y-%m-%d %H:%M:%S",
    "%a %b %d %H:%M:%S %Y",
    "%b %d %H:%M:%S",
]


def parse_timestamp(line):
    """
    Tries to extract common OpenVPN timestamps.
    Returns datetime or None.
    """

    # Example: 2026-05-20 14:33:01 message
    m = re.match(r"^(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
    if m:
        try:
            return datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass

    # Example: Wed May 20 14:33:01 2026 message
    m = re.match(r"^([A-Z][a-z]{2} [A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2} \d{4})", line)
    if m:
        try:
            return datetime.strptime(m.group(1), "%a %b %d %H:%M:%S %Y")
        except ValueError:
            pass

    # Example: May 20 14:33:01 message
    # No year, so use current year.
    m = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})", line)
    if m:
        try:
            dt = datetime.strptime(m.group(1), "%b %d %H:%M:%S")
            return dt.replace(year=datetime.now().year)
        except ValueError:
            pass

    return None


# -----------------------------
# Extraction helpers
# -----------------------------

def extract_ip_port(line):
    for pattern in IP_PATTERNS:
        m = pattern.search(line)
        if m:
            return m.group("ip"), m.groupdict().get("port")
    return None, None


def extract_user_cn_ip(line):
    user = None
    cn = None
    ip = None
    port = None

    m = USER_IP_RE.search(line)
    if m:
        user = m.group("user")
        ip = m.group("ip")
        port = m.groupdict().get("port")

    m = CN_RE.search(line)
    if m:
        cn = m.group("cn")
        if not user:
            user = cn

    m = USERNAME_RE.search(line)
    if m and not user:
        user = m.group("user")

    if not ip:
        ip, port = extract_ip_port(line)

    return user, cn, ip, port


def classify_event(line):
    events = []

    for event_type, pattern in PATTERNS.items():
        if pattern.search(line):
            events.append(event_type)

    return events if events else ["info"]


def numeric_sort_key(path):
    """
    Sorts files like:
    openvpn.log
    openvpn.log.1
    openvpn.log.2
    openvpn.log.10
    """

    basename = os.path.basename(path)
    m = re.search(r"\.(\d+)$", basename)

    if m:
        return int(m.group(1))

    return -1


# -----------------------------
# Core parser
# -----------------------------

def parse_logs(file_pattern):
    files = sorted(glob.glob(file_pattern), key=numeric_sort_key)

    if not files:
        raise FileNotFoundError(f"No files matched pattern: {file_pattern}")

    parsed_events = []

    for file_path in files:
        with open(file_path, "r", errors="replace") as f:
            for line_number, line in enumerate(f, start=1):
                line = line.strip()

                if not line:
                    continue

                timestamp = parse_timestamp(line)
                user, cn, ip, port = extract_user_cn_ip(line)
                event_types = classify_event(line)

                for event_type in event_types:
                    parsed_events.append({
                        "timestamp": timestamp.isoformat() if timestamp else "",
                        "event_type": event_type,
                        "user": user or "",
                        "cn": cn or "",
                        "source_ip": ip or "",
                        "source_port": port or "",
                        "file": os.path.basename(file_path),
                        "line_number": line_number,
                        "raw": line,
                    })

    return parsed_events


# -----------------------------
# Detection logic
# -----------------------------

def detect_suspicious_activity(events, failed_threshold, tls_threshold, distinct_user_threshold, distinct_ip_threshold):
    findings = []

    failed_by_ip = Counter()
    tls_by_ip = Counter()
    verify_by_ip = Counter()
    reset_by_ip = Counter()
    reconnect_by_ip = Counter()

    users_by_ip = defaultdict(set)
    ips_by_user = defaultdict(set)

    failures_by_user_ip = Counter()
    success_by_user_ip = Counter()

    suspicious_raw_events = []

    for e in events:
        ip = e["source_ip"]
        user = e["user"] or e["cn"]
        event_type = e["event_type"]

        if ip and user:
            users_by_ip[ip].add(user)
            ips_by_user[user].add(ip)

        if event_type == "auth_failed" and ip:
            failed_by_ip[ip] += 1
            if user:
                failures_by_user_ip[(user, ip)] += 1

        elif event_type == "tls_error" and ip:
            tls_by_ip[ip] += 1

        elif event_type == "verify_error" and ip:
            verify_by_ip[ip] += 1

        elif event_type == "connection_reset" and ip:
            reset_by_ip[ip] += 1

        elif event_type == "reconnect" and ip:
            reconnect_by_ip[ip] += 1

        elif event_type == "possible_success" and ip and user:
            success_by_user_ip[(user, ip)] += 1

        if event_type in {
            "auth_failed",
            "tls_error",
            "verify_error",
            "bad_source",
            "connection_reset",
            "reconnect",
        }:
            suspicious_raw_events.append(e)

    # Brute force or password spraying by IP
    for ip, count in failed_by_ip.items():
        if count >= failed_threshold:
            findings.append({
                "severity": "HIGH",
                "finding": "Repeated authentication failures from one source IP",
                "indicator": ip,
                "details": f"{count} authentication failures",
            })

    # TLS scanning, broken clients, or probing
    for ip, count in tls_by_ip.items():
        if count >= tls_threshold:
            findings.append({
                "severity": "MEDIUM",
                "finding": "Repeated TLS errors from one source IP",
                "indicator": ip,
                "details": f"{count} TLS-related errors",
            })

    # Certificate issues
    for ip, count in verify_by_ip.items():
        if count > 0:
            findings.append({
                "severity": "MEDIUM",
                "finding": "Certificate verification errors",
                "indicator": ip,
                "details": f"{count} certificate verification errors",
            })

    # Many usernames from same IP
    for ip, users in users_by_ip.items():
        if len(users) >= distinct_user_threshold:
            findings.append({
                "severity": "HIGH",
                "finding": "One source IP attempted multiple usernames",
                "indicator": ip,
                "details": f"{len(users)} usernames observed: {', '.join(sorted(users))}",
            })

    # Same user from many IPs
    for user, ips in ips_by_user.items():
        if len(ips) >= distinct_ip_threshold:
            findings.append({
                "severity": "MEDIUM",
                "finding": "One user appeared from multiple source IPs",
                "indicator": user,
                "details": f"{len(ips)} source IPs observed: {', '.join(sorted(ips))}",
            })

    # Success after failures
    for user_ip, fail_count in failures_by_user_ip.items():
        if fail_count > 0 and success_by_user_ip.get(user_ip, 0) > 0:
            user, ip = user_ip
            findings.append({
                "severity": "HIGH",
                "finding": "Possible successful login after failed attempts",
                "indicator": f"{user} from {ip}",
                "details": f"{fail_count} failures followed by {success_by_user_ip[user_ip]} possible success events",
            })

    # Bad source address
    bad_source_count = sum(1 for e in events if e["event_type"] == "bad_source")
    if bad_source_count:
        findings.append({
            "severity": "MEDIUM",
            "finding": "Bad source address events observed",
            "indicator": "MULTI: bad source address",
            "details": f"{bad_source_count} events observed",
        })

    return findings, suspicious_raw_events


# -----------------------------
# Output helpers
# -----------------------------

def write_csv(path, rows, fieldnames):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def print_summary(events, findings):
    total_events = len(events)

    event_counts = Counter(e["event_type"] for e in events)
    top_ips = Counter(e["source_ip"] for e in events if e["source_ip"])
    top_users = Counter((e["user"] or e["cn"]) for e in events if e["user"] or e["cn"])

    print("\n========== OpenVPN Log Analysis Summary ==========\n")
    print(f"Total parsed events: {total_events}")

    print("\nEvent counts:")
    for event_type, count in event_counts.most_common():
        print(f"  {event_type}: {count}")

    print("\nTop source IPs:")
    for ip, count in top_ips.most_common(10):
        print(f"  {ip}: {count}")

    print("\nTop users / CNs:")
    for user, count in top_users.most_common(10):
        print(f"  {user}: {count}")

    print("\nSuspicious findings:")
    if not findings:
        print("  No major suspicious patterns detected with the current thresholds.")
    else:
        for f in findings:
            print(f"\n  [{f['severity']}] {f['finding']}")
            print(f"    Indicator: {f['indicator']}")
            print(f"    Details: {f['details']}")

    print("\n==================================================\n")


# -----------------------------
# Main
# -----------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Parse OpenVPN logs and identify suspicious activity."
    )

    parser.add_argument(
        "-p",
        "--pattern",
        required=True,
        help="Glob pattern for OpenVPN logs, example: '/var/log/openvpn.log*' or './openvpn.log*'"
    )

    parser.add_argument(
        "-o",
        "--output-dir",
        default="openvpn_analysis_output",
        help="Directory to write CSV output files."
    )

    parser.add_argument(
        "--failed-threshold",
        type=int,
        default=5,
        help="Authentication failures from one IP before flagging."
    )

    parser.add_argument(
        "--tls-threshold",
        type=int,
        default=10,
        help="TLS errors from one IP before flagging."
    )

    parser.add_argument(
        "--distinct-user-threshold",
        type=int,
        default=3,
        help="Different usernames from one IP before flagging."
    )

    parser.add_argument(
        "--distinct-ip-threshold",
        type=int,
        default=3,
        help="Different IPs for one user before flagging."
    )

    args = parser.parse_args()

    os.makedirs(args.output_dir, exist_ok=True)

    events = parse_logs(args.pattern)

    findings, suspicious_events = detect_suspicious_activity(
        events=events,
        failed_threshold=args.failed_threshold,
        tls_threshold=args.tls_threshold,
        distinct_user_threshold=args.distinct_user_threshold,
        distinct_ip_threshold=args.distinct_ip_threshold,
    )

    events_csv = os.path.join(args.output_dir, "parsed_events.csv")
    suspicious_csv = os.path.join(args.output_dir, "suspicious_events.csv")
    findings_csv = os.path.join(args.output_dir, "findings.csv")

    write_csv(
        events_csv,
        events,
        [
            "timestamp",
            "event_type",
            "user",
            "cn",
            "source_ip",
            "source_port",
            "file",
            "line_number",
            "raw",
        ]
    )

    write_csv(
        suspicious_csv,
        suspicious_events,
        [
            "timestamp",
            "event_type",
            "user",
            "cn",
            "source_ip",
            "source_port",
            "file",
            "line_number",
            "raw",
        ]
    )

    write_csv(
        findings_csv,
        findings,
        [
            "severity",
            "finding",
            "indicator",
            "details",
        ]
    )

    print_summary(events, findings)

    print(f"CSV output written to: {args.output_dir}")
    print(f"  Parsed events:      {events_csv}")
    print(f"  Suspicious events:  {suspicious_csv}")
    print(f"  Findings:           {findings_csv}")


if __name__ == "__main__":
    main()