# Mini-SIEM-tool
Mini SIEM tool
Combined Alert Tool (Mini SIEM)

This project is a simple Mini SIEM tool written in Python. It analyzes login events and generates alerts based on multiple detection rules.

## Detection Rules

- Unusual login time
- Multiple failed login attempts
- Login from unknown IP

## Project Files

- `main.py` → Main program
- `rules.py` → Detection rules
- `sample_logs.jsonl` → Example login logs
- `README.md` → Project documentation

## How It Works

The tool reads login events from a `.jsonl` file and applies three detection rules:

### 1. Unusual login time
If a successful login happens outside working hours (09:00–18:00), it creates an alert.

### 2. Multiple failed login attempts
If a user has 3 or more failed login attempts within 5 minutes, it creates an alert.

### 3. Login from unknown IP
If a successful login happens from an IP address not listed as known for that user, it creates an alert.

## How to Run

```bash
python main.py
```

## Example Output

```json
{
    "rule": "Unusual login time",
    "username": "ali",
    "ip": "45.33.22.10",
    "timestamp": "2026-03-28T02:15:00",
    "severity": "medium",
    "description": "User 'ali' logged in outside working hours."
}
```

## Future Improvements

- Read known IPs from a config file
- Save alerts to a file or database
- Send alerts by email or Slack
- Add more detection rules
- Process logs in real time