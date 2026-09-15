class LogEntry:
    """
    LogEntry — Model representing a single network log event.

    Fields:
      - id          : Database row ID (0 or None if not persisted)
      - time        : Timestamp when the event was recorded
      - ip          : Source IP address
      - action      : Event type (LOGIN_FAIL, LOGIN_SUCCESS, REQUEST)
      - score       : Risk score computed by SecurityBot (0–100, default 0)
      - status      : Status label (PASS, SUSPICIOUS, MONITORING, BLOCKED)
      - attack_type : Attack classification (NORMAL, BRUTE_FORCE, REQUEST_FLOOD)
      - description : Optional detail string
      - is_modified : Track if score/status/attack_type changed after creation/load
    """

    def __init__(self, time: str, ip: str, action: str, id_val: int = 0):
        self.id = id_val
        self.time = time
        self.ip = ip
        self.action = action
        self.score = 0
        self.status = "PASS"
        self.attack_type = "NORMAL"
        self.description = None
        self.is_modified = False

    def is_modified_flag(self) -> bool:
        return self.is_modified

    def get_id(self) -> int:
        return self.id

    def set_id(self, id_val: int):
        self.id = id_val

    def get_time(self) -> str:
        return self.time

    def get_ip(self) -> str:
        return self.ip

    def get_action(self) -> str:
        return self.action

    def get_score(self) -> int:
        return self.score

    def set_score(self, score: int):
        if self.score != score:
            self.score = score
            self.is_modified = True

    def get_status(self) -> str:
        return self.status

    def set_status(self, status: str):
        if self.status != status:
            self.status = status
            self.is_modified = True

    def get_attack_type(self) -> str:
        return self.attack_type

    def set_attack_type(self, attack_type: str):
        if self.attack_type != attack_type:
            self.attack_type = attack_type
            self.is_modified = True

    def get_description(self) -> str:
        return self.description

    def set_description(self, description: str):
        self.description = description

    def reset_modified(self):
        self.is_modified = False

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "time": self.time,
            "ip": self.ip,
            "action": self.action,
            "attack": self.attack_type,
            "score": self.score,
            "status": self.status,
            "description": self.description
        }

    def __repr__(self) -> str:
        return (f"[{self.time}] {self.ip} {self.action} | "
                f"score={self.score} | status={self.status} | attack={self.attack_type}")
