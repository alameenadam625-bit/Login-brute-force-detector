# Login Brute-Force Detector

A lightweight Python command-line security log analyzer that detects credential-stuffing and brute-force login attempts in $O(n)$ linear time and exports malicious IP addresses to a firewall blocklist.

## How It Works
- **Defensive Parsing (`parse_log_line`)**: Streams `server_auth.log` line-by-line and safely skips malformed entries without crashing.
- **Hash-Map Aggregation ($O(n)$)**: Uses Python dictionaries (`O(1)` lookup) to count failed attempts per IP and `set` structures to deduplicate targeted usernames.
- **Threshold Filtering**: Flags IPs exceeding `> 3` failed attempts to ignore normal human typing errors.
- **Automated Mitigation**: Exports flagged IPs to `blocked_ips.txt` in `DENY IP <address>` format.

## Usage
```bash
python brute_force_detector.py
```

## Sample Output
```text
==============================================================
        SIWES CYBERSECURITY LAB: BRUTE-FORCE DETECTOR
==============================================================
Log File Analyzed  : server_auth.log
Total Events Read  : 12 (Malformed skipped: 0)
Total Failed Logins: 10
Alert Threshold    : > 3 failed attempts
--------------------------------------------------------------
[ALERT #1] POSSIBLE BRUTE-FORCE ATTACK DETECTED
  -> Source IP      : 192.168.1.45
  -> Failed Attempts: 5
  -> Targeted Users : admin, administrator, root
  -> Time Window    : 2026-11-25 08:15:33  to  2026-11-25 08:15:42
--------------------------------------------------------------
[ALERT #2] POSSIBLE FRUTE-FORCE ATTACK DETECTED  -> Source IP      : 172.16.0.99
  -> Failed Attempts: 4
  -> Targeted Users : admin, guest
  -> Time Window    : 2026-11-25 09:05:11  to  2026-11-25 09:05:22
--------------------------------------------------------------
[ACTION] Exported 2 malicious IPs to 'blocked_ips.txt'.
==============================================================

```

## Verification Tests
```bash
python test_detector.py
```
