# Sample Evidence Files

These synthetic log files simulate a digital forensics scenario for testing
the Cybercrime Digital Evidence Analyzer. All data is fictional.

## Scenarios

### Scenario 1: Brute Force Attack (auth.log)
- IP 10.0.0.15 makes 4 failed login attempts against the admin account
- Followed by a successful login
- This pattern suggests a brute-force attack leading to account compromise

### Scenario 2: Sensitive File Access (file_events.csv)
- After successful login, the admin account accesses passwords.txt and users.csv
- users.csv is then modified
- This suggests unauthorized access to sensitive resources

### Scenario 3: Unusual Login Times (auth.log)
- Successful logins at 23:30 and 02:15 (outside business hours)
- May indicate compromised credentials being used by an attacker

### Scenario 4: Suspicious Network Activity (network_events.csv)
- Connection to 185.220.101.1 (a known Tor exit node)
- Connection on non-standard port 9001
- Suggests data exfiltration or C2 communication

### Scenario 5: Web Server Activity (web.log)
- GET requests to /admin/dashboard, /api/users/export
- PUT to /files/users.csv (file modification via web)
- POST to /admin/config (configuration changes)

## Usage

1. Create a new case in the application
2. Upload these files as evidence
3. The system will parse them, extract events, and run detection rules
4. Review the timeline, alerts, and indicators

## Important

All IP addresses, usernames, and events in these files are SYNTHETIC.
They do not represent real systems or real attacks.
