from core.warnings.deprecated import deprecated
from seeds.seeds import tmp_master_seed
from kdf.derive_key import derive
from context.conext_generator import Context
from swoosh import keygen_seeded
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

try:
    from keytypes.mlkem import MLKEMKey
except Exception:
    MLKEMKey = None

@deprecated
def generate_mlkem(key_type=None):
    from cryptography.hazmat.primitives.asymmetric import mlkem as _mlkem
    context = Context(key_type = key_type.__name__, version="INDEV", reason="Generation")
    seed = tmp_master_seed()
    seed64 = derive(seed, context=context.get_context_bytes(), n=64)

    private_key = type.from_seed_bytes(seed64)
    public_key = private_key.public_key()

    return private_key,public_key

def generate_swoosh(is_party_a: bool, seed=None):
    private_key, public_key = keygen_seeded(is_party_a=is_party_a, seed=seed or tmp_master_seed())
    return private_key, public_key


def generate_ed25519(seed=None):
    private_key = Ed25519PrivateKey.from_private_bytes(seed or tmp_master_seed())
    public_key = private_key.public_key()
    return private_key, public_key

def generate_x25519(seed=None):
    private_key = X25519PrivateKey.from_private_bytes(seed or tmp_master_seed())
    public_key = private_key.public_key()
    return private_key, public_key
