import secrets

def get_random_bytes(n=32):
   return secrets.token_bytes(n)