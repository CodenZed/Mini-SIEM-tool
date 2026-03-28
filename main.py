import json
from rules import (
    detect_unusual_login_time,
    detect_unknown_ip,
    FailedLoginDetector,
)


def load_logs(file_path):
    """Read JSONL logs line by line."""
    with open(file_path, "r", encoding="utf-8") as file:
        for line_number, line in enumerate(file, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                print(f"[WARNING] Invalid JSON on line {line_number}")


def main():
    log_file = "sample_logs.jsonl"
    failed_login_detector = FailedLoginDetector(threshold=3, window_minutes=5)
    alerts = []

    for event in load_logs(log_file):
        unusual_time_alert = detect_unusual_login_time(event)
        if unusual_time_alert:
            alerts.append(unusual_time_alert)

        unknown_ip_alert = detect_unknown_ip(event)
        if unknown_ip_alert:
            alerts.append(unknown_ip_alert)

        failed_login_alert = failed_login_detector.process(event)
        if failed_login_alert:
            alerts.append(failed_login_alert)

    print("\n=== DETECTED ALERTS ===\n")
    if not alerts:
        print("No suspicious activity detected.")
        return

    for alert in alerts:
        print(json.dumps(alert, indent=4))


if __name__ == "__main__":
    main()