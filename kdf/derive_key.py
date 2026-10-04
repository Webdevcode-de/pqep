import blake3


def derive(secret, context, n=32):
    derived_key = blake3.blake3(
        secret,
        derive_key_context=context
    ).digest(lenght=n)
    return derived_key
