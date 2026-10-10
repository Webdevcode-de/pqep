try:
    from cryptography.hazmat.primitives.asymmetric import mlkem

    MLKEMKey = (
        mlkem.MLKEM768PrivateKey
        | mlkem.MLKEM1024PrivateKey
    )
except Exception:
    mlkem = None
    MLKEMKey = None