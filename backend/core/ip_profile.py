class IPProfile:
    """
    IPProfile — Tracks the behavior of a single IP address.
    """

    def __init__(self, ip: str):
        self.ip = ip
        self.login_fail = 0
        self.login_success = 0
        self.request = 0
        self.risk_score = 0

    def increase_fail(self):
        self.login_fail += 1

    def increase_success(self):
        self.login_success += 1

    def increase_request(self):
        self.request += 1

    def calculate_risk_score(self):
        self.risk_score = (self.login_fail * 3) + (self.request * 1) - (self.login_success * 2)
        if self.risk_score < 0:
            self.risk_score = 0

    def get_risk_score(self) -> int:
        return self.risk_score

    def get_ip(self) -> str:
        return self.ip

    def get_login_fail(self) -> int:
        return self.login_fail

    def get_login_success(self) -> int:
        return self.login_success

    def get_request(self) -> int:
        return self.request
