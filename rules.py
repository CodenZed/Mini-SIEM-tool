from collections import defaultdict, deque
from datetime import datetime

# Example of known IPs for users
KNOWN_IPS = {
    "ali": {"192.168.1.10", "10.0.0.5"},
    "leyla": {"172.16.0.2"},
    "nigar": {"192.168.0.20"},
}

# Define working hours
WORK_HOURS_START = 9
WORK_HOURS_END = 18


def detect_unusual_login_time(event):
    """
    Detect if login happens outside normal working hours.
    """
    if event.get("status") != "success":
        return None

    timestamp = event.get("timestamp")
    username = event.get("username")
    ip = event.get("ip")

    if not timestamp or not username or not ip:
        return None

    try:
        event_time = datetime.fromisoformat(timestamp)
    except ValueError:
        return None

    if event_time.hour < WORK_HOURS_START or event_time.hour >= WORK_HOURS_END:
        return {
            "rule": "Unusual login time",
            "username": username,
            "ip": ip,
            "timestamp": timestamp,
            "severity": "medium",
            "description": f"User '{username}' logged in outside working hours."
        }

    return None


def detect_unknown_ip(event):
    """
    Detect successful logins from an IP not previously known for that user.
    """
    if event.get("status") != "success":
        return None

    username = event.get("username")
    ip = event.get("ip")
    timestamp = event.get("timestamp")

    if not username or not ip or not timestamp:
        return None

    known_user_ips = KNOWN_IPS.get(username, set())

    if ip not in known_user_ips:
        return {
            "rule": "Login from unknown IP",
            "username": username,
            "ip": ip,
            "timestamp": timestamp,
            "severity": "high",
            "description": f"User '{username}' logged in from an unknown IP address."
        }

    return None


class FailedLoginDetector:
    """
    Detect multiple failed login attempts within a time window.
    """

    def __init__(self, threshold=3, window_minutes=5):
        self.threshold = threshold
        self.window_minutes = window_minutes
        self.failed_attempts = defaultdict(deque)

    def process(self, event):
        if event.get("status") != "failed":
            return None

        username = event.get("username")
        ip = event.get("ip")
        timestamp = event.get("timestamp")

        if not username or not ip or not timestamp:
            return None

        try:
            current_time = datetime.fromisoformat(timestamp)
        except ValueError:
            return None

        user_attempts = self.failed_attempts[username]
        user_attempts.append(current_time)

        while user_attempts and (current_time - user_attempts[0]).total_seconds() > self.window_minutes * 60:
            user_attempts.popleft()

        if len(user_attempts) >= self.threshold:
            return {
                "rule": "Multiple failed login attempts",
                "username": username,
                "ip": ip,
                "timestamp": timestamp,
                "severity": "high",
                "count": len(user_attempts),
                "description": (
                    f"User '{username}' had {len(user_attempts)} failed login attempts "
                    f"within {self.window_minutes} minutes."
                )
            }

        return None