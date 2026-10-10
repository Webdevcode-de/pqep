from swoosh import derive_shared_secret

class KeyExchangeError(Exception):
    """Custom exception for key exchange errors."""
    pass

class KeyXchange:
    def __init__(self, private_key, my_public_key, public_key, party_a: bool):
        self.private_key = private_key
        self.public_key = public_key
        self.my_public_key = my_public_key
        self.party_a = party_a

    def exchange(self):
        try:
            shared_secret = derive_shared_secret(self.my_public_key, self.public_key, self.private_key, self.party_a)
            return shared_secret
        except Exception as e:
            raise KeyExchangeError("Failed to derive shared secret.") from e