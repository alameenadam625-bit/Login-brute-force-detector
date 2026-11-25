from brute_force_detector import parse_log_line, analyze_logs

# 1. Verify valid log parsing
parsed = parse_log_line("2026-11-25 08:15:33 | IP: 192.168.1.45 | USER: admin | STATUS: FAILED")
assert parsed == ("2026-11-25 08:15:33", "192.168.1.45", "admin", "FAILED"), "Valid line failed to parse"

# 2. Verify malformed line handling
assert parse_log_line("CORRUPTED_LOG_ENTRY") is None, "Malformed line should return None"

# 3. Verify threshold detection on sample log
flagged = analyze_logs("server_auth.log", threshold=3, blocklist_path="blocked_ips.txt")
assert flagged == ["192.168.1.45", "172.16.0.99"], f"Unexpected flagged IPs: {flagged}"

print("\n[PASS] All automated verification tests passed!")
