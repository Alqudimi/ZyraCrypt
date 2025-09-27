

from datetime import datetime
import json
import os

class CryptographicAuditLog:
    def __init__(self, log_file: str = "./audit.log"):
        self.log_file = log_file

    def _write_log(self, entry: dict):
        """Writes a log entry to the audit log file."""
        with open(self.log_file, "a") as f:
            f.write(json.dumps(entry) + "\n")

    def log_event(self, event_type: str, user_id: str = "system", details: dict = None):
        """Logs a cryptographic event."""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "user_id": user_id,
            "details": details if details is not None else {}
        }
        self._write_log(log_entry)

    def get_logs(self) -> list[dict]:
        """Retrieves all log entries."""
        logs = []
        if os.path.exists(self.log_file):
            with open(self.log_file, "r") as f:
                for line in f:
                    try:
                        logs.append(json.loads(line))
                    except json.JSONDecodeError:
                        # Handle malformed log entries
                        pass
        return logs


