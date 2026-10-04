from cryptography.hazmat.primitives.asymmetric import mlkem
from seeds.seeds import tmp_master_seed
from kdf.derive_key import derive
from context.conext_generator import Context
from keytypes.mlkem import MLKEMKey


def generate(key_type: MLKEMKey):
    context = Context(key_type = key_type.__name__, version="INDEV", reason="Generation")
    seed = tmp_master_seed()
    seed64 = derive(seed, context=context.get_context_bytes(), n=64)

    private_key = type.from_seed_bytes(seed64)
    public_key = private_key.public_key()

    return private_key,public_key