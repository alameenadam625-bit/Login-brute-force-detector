import os

LOG_FILE = "server_auth.log"
BLOCKLIST_FILE = "blocked_ips.txt"
FAILURE_THRESHOLD = 3


def parse_log_line(line: str):
    """Parses a single log entry into (timestamp, ip, user, status) or returns None if malformed."""
    parts = [part.strip() for part in line.strip().split("|")]
    if len(parts) != 4:
        return None

    timestamp = parts[0]
    ip_address = parts[1].replace("IP:", "").strip()
    username = parts[2].replace("USER:", "").strip()
    status = parts[3].replace("STATUS:", "").strip()

    if not ip_address or not status:
        return None

    return timestamp, ip_address, username, status


def analyze_logs(file_path: str, threshold: int, blocklist_path: str) -> list[str]:
    if not os.path.exists(file_path):
        print(f"[ERROR] Log file '{file_path}' not found.")
        return []

    failed_attempts = {}
    targeted_users = {}
    timestamps = {}

    total_lines = 0
    malformed_lines = 0
    total_failed = 0

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            if not line.strip():
                continue

            total_lines += 1
            parsed = parse_log_line(line)

            if parsed is None:
                malformed_lines += 1
                continue

            timestamp, ip_address, username, status = parsed

            if status == "FAILED":
                total_failed += 1
                failed_attempts[ip_address] = failed_attempts.get(ip_address, 0) + 1
                targeted_users.setdefault(ip_address, set()).add(username)
                timestamps.setdefault(ip_address, []).append(timestamp)

    print("=" * 62)
    print("        SIWES CYBERSECURITY LAB: BRUTE-FORCE DETECTOR")
    print("=" * 62)
    print(f"Log File Analyzed  : {file_path}")
    print(f"Total Events Read  : {total_lines} (Malformed skipped: {malformed_lines})")
    print(f"Total Failed Logins: {total_failed}")
    print(f"Alert Threshold    : > {threshold} failed attempts")
    print("-" * 62)

    flagged_ips = []
    for ip, count in failed_attempts.items():
        if count > threshold:
            flagged_ips.append(ip)
            users_list = ", ".join(sorted(targeted_users[ip]))
            first_seen = timestamps[ip][0]
            last_seen = timestamps[ip][-1]

            print(f"[ALERT #{len(flagged_ips)}] POSSIBLE BRUTE-FORCE ATTACK DETECTED")
            print(f"  -> Source IP      : {ip}")
            print(f"  -> Failed Attempts: {count}")
            print(f"  -> Targeted Users : {users_list}")
            print(f"  -> Time Window    : {first_seen}  to  {last_seen}")
            print("-" * 62)

    if flagged_ips:
        with open(blocklist_path, "w", encoding="utf-8") as out:
            for ip in flagged_ips:
                out.write(f"DENY IP {ip}\n")
        print(f"[ACTION] Exported {len(flagged_ips)} malicious IPs to '{blocklist_path}'.")
    else:
        print("[OK] No brute-force activity detected above threshold.")

    print("=" * 62)
    return flagged_ips


if __name__ == "__main__":
    analyze_logs(LOG_FILE, FAILURE_THRESHOLD, BLOCKLIST_FILE)
