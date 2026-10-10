from blake3 import blake3


def get_blake3_hash(data: bytes, n: int) -> bytes:
    """
    Computes the BLAKE3 hash of the given data.

    Args:
        data (bytes): The input data to hash.
        n (int): The length of the output hash in bytes.
    Returns:
        bytes: The BLAKE3 hash of the input data.
    """
    return blake3(data).digest(length=n)