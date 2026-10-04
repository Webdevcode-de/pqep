


class Context:
    def __init__(self, key_type, version, reason):
        self.key_type = key_type
        self.version = version
        self.reason = reason

    def get_context(self):
        complete_string = f"pqep/{self.version}-key/{self.key_type}-addinf/{self.reason}"
        return complete_string

    def get_context_bytes(self):
        string = self.get_context()
        return string.encode("utf-8")