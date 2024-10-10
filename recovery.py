import argon2.profiles
from mnemonic import Mnemonic
from secrets import token_bytes
from secretsharing import SecretSharer, secret_int_to_points, points_to_secret_int
from sys import argv
from base64 import b64encode, b64decode, urlsafe_b64encode
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.constant_time import bytes_eq
from typing import Tuple, List
from cryptography.hazmat.primitives import hashes
from getpass import getpass
import json
import argon2
from time import perf_counter

SECURITY_BITS = 256
SECURITY_BYTES = SECURITY_BITS // 8
BYTE_ORDER = "little"
SIGNED = False
CHARSET = "utf-8"

mnemo = Mnemonic("english")


class BytesSecretSharer(SecretSharer):
    secret_charset = "123"
    share_charset = "456"

    def charset_to_int(s, charset):
        return int.from_bytes(s)

    def int_to_charset(val: int, charset):
        return val.to_bytes()


def create_recovery_vault(payload: bytes, vault_specs: dict, password=None):
    """
    Creates a recovery vault to encapsulate the data at the secret key path

    The vault specs are stored in json format:
    {
        "_version": "v1.0"
        "password": {
            "salt": base64-str,
            "kdf_params": {
                "algorithm": "ARGON_2_D"
                "time_cost": int,
                "memory_cost": int,
                "parallelism": int
            }
        },
        "master_key": {
            "salt": base64-str
        },
        "secret_shards": {
            "num_shards": int,
            "required_shards": int,
            "checksum": b64-str
        },
        "payload": {
            "enc_payload", base64-str
        }
    }

    The vault secret shards are also stored in json format, make sure to delete them:
    {
        "_version": "v1.0",
        "secret_shards": [
            {
                // You must write down the index and mnemonic or the index and the bytes
                // However, writing all down is recommended
                "mnemonic": str,
                "bytes": base64-str,
                "index": int
            },
            ...
        ]
    }
    """
    vault_specs["_version"] = vault_specs.get("_version", "v1.0")
    if vault_specs["_version"] != "v1.0":
        raise Exception(f"Unknown version: {vault_specs['_version']}")
    vault_key_shards = {
        "_version": "v1.0",
    }

    # Get a key based on a password
    password_params: dict = vault_specs.get("password", {})
    kdf_params = password_params.get("kdf_params", {})
    kdf_params = {
        "algorithm": "ARGON_2_D",
        "time_cost": kdf_params.get("time_cost", 10),
        # Deffault memory cost of 1 Gi
        "memory_cost": kdf_params.get("memory_cost", 1024**2),
        "parallelism": kdf_params.get("parallelism", 8),
    }
    password = password or getpass("Enter secure password: ")
    password_key, salt = get_password_key(password, kdf_params)
    vault_specs["password"] = {
        "salt": str(b64encode(salt), CHARSET),
        "kdf_params": kdf_params,
    }

    # Generate n secret shards
    num_shards = vault_specs.get("secret_shards", {}).get("num_shards", 5)
    shard_threshold = vault_specs.get("secret_shards", {}).get("required_shards", 3)
    key_shards, secondary_key = generate_secret_shards(num_shards, shard_threshold)
    vault_specs["secret_shards"] = {
        "num_shards": num_shards,
        "required_shards": shard_threshold,
    }
    vault_key_shards["secret_shards"] = []
    for index, shard_bytes in key_shards:
        mnemonic = mnemo.to_mnemonic(shard_bytes)
        bytestring = str(b64encode(shard_bytes), CHARSET)
        vault_key_shards["secret_shards"].append(
            {"mnemonic": mnemonic, "bytes": bytestring, "index": index}
        )
    vault_specs["secret_shards"]["checksum"] = str(
        b64encode(generate_checksum(secondary_key)), CHARSET
    )

    # Combine the password key and secondary key to get the master key
    master_key_salt = token_bytes(SECURITY_BYTES)
    master_key = combine_keys(
        [password_key, secondary_key], master_key_salt, "MASTER_KEY"
    )
    vault_specs["master_key"] = {"salt": str(b64encode(master_key_salt), CHARSET)}

    # Encrypt the payload
    enc_payload = encrypt(payload, master_key)
    vault_specs["payload"] = {"enc_payload": str(b64encode(enc_payload), CHARSET)}

    return vault_specs, vault_key_shards


def unlock_recovery_vault(vault_specs: dict, vault_key_shards: dict, password=None):
    # Get a key based on a password
    password_params: dict = vault_specs["password"]
    kdf_params: dict = password_params["kdf_params"]
    password = password or getpass("Enter secure password: ")
    password_key, _ = get_password_key(
        password, kdf_params, salt=b64decode(password_params["salt"])
    )

    # Get the secondary key by combining the shards
    secret_shards_bytes: Tuple[int, bytes] = []
    for shard in vault_key_shards["secret_shards"]:
        index = shard["index"]
        bytes_b64 = shard.get("bytes", None)
        mnemonic = shard.get("mnemonic", None)

        if bytes_b64:
            secret_shards_bytes.append((index, b64decode(bytes_b64)))
        else:
            secret_shards_bytes.append((index, mnemo.to_entropy(mnemonic)))
    secondary_key = combine_secret_shards(secret_shards_bytes)
    secondary_key_checksum = generate_checksum(secondary_key)
    if not bytes_eq(
        secondary_key_checksum, b64decode(vault_specs["secret_shards"]["checksum"])
    ):
        raise Exception("Invalid shards")

    # Combine the password and secondary keys to get the master key
    master_key_salt = b64decode(vault_specs["master_key"]["salt"])
    master_key = combine_keys(
        [password_key, secondary_key], master_key_salt, "MASTER_KEY"
    )

    # Decrypt the payload
    enc_payload = b64decode(vault_specs["payload"]["enc_payload"])
    payload = decrypt(enc_payload, master_key)

    return payload


def get_password_key(
    password: str, kdf_params: dict, salt: bytes = None
) -> Tuple[bytes, bytes]:
    password_bytes = bytes(password, CHARSET)
    salt = salt or token_bytes(SECURITY_BYTES)

    start_time = perf_counter()
    password_key = argon2.low_level.hash_secret_raw(
        password_bytes,
        salt,
        time_cost=kdf_params["time_cost"],
        memory_cost=kdf_params["memory_cost"],
        parallelism=kdf_params["parallelism"],
        hash_len=SECURITY_BYTES,
        type=argon2.profiles.Type.D,
    )
    print(f"KDF took {perf_counter()-start_time:.2f} seconds")

    return password_key, salt


def generate_secret_shards(
    num_shards, threshold
) -> Tuple[List[Tuple[int, bytes]], bytes]:
    secret = token_bytes(SECURITY_BYTES)
    secret_int = int.from_bytes(secret, BYTE_ORDER, signed=SIGNED)

    points: List[Tuple[int, int]] = secret_int_to_points(
        secret_int, threshold, num_shards
    )
    shards_bytes = [
        (x, y.to_bytes(SECURITY_BYTES, BYTE_ORDER, signed=SIGNED)) for (x, y) in points
    ]

    return shards_bytes, secret


def combine_secret_shards(shards_bytes: List[Tuple[int, bytes]]) -> bytes:
    points = [
        (x, int.from_bytes(y, BYTE_ORDER, signed=SIGNED)) for (x, y) in shards_bytes
    ]
    secret_int = points_to_secret_int(points)
    secret_bytes = secret_int.to_bytes(SECURITY_BYTES, BYTE_ORDER, signed=SIGNED)

    return secret_bytes


def combine_keys(keys: List[bytes], salt, tag) -> Tuple[bytes, bytes]:
    for key in keys:
        if len(key) != SECURITY_BYTES:
            raise Exception(f"Key must be 256 bits long. Got {len(key)*8} bits")

    hkdf = HKDF(
        algorithm=hashes.SHA3_256(),
        length=SECURITY_BYTES,
        salt=salt,
        info=bytes(f"RecoverKey::{tag}", CHARSET),
    )

    key_material = b"".join(keys)

    return hkdf.derive(key_material)


def generate_checksum(bytestring: bytes) -> bytes:
    """
    Generates a short checksum of length SECURITY_BYTES/16
    For 256 bit security, this gives us a checksum of 16 bits.
    """
    digest = hashes.Hash(hashes.SHA3_256())
    digest.update(bytestring)
    h = digest.finalize()
    return h[: SECURITY_BYTES // 16]


def encrypt(plain_text: bytes, key: bytes) -> bytes:
    encryptor = Fernet(urlsafe_b64encode(key))
    cipher_text = encryptor.encrypt(plain_text)

    return cipher_text


def decrypt(ciphber_text: bytes, key: bytes) -> bytes:
    encryptor = Fernet(urlsafe_b64encode(key))
    try:
        plain_text = encryptor.decrypt(ciphber_text)
    except InvalidToken:
        raise Exception("Decrypt error. Invalid password, ")

    return plain_text


def load_payload(payload_path) -> bytes:
    with open(payload_path, "rb") as f:
        payload = f.read()
    return payload


def write_payload(payload: bytes, payload_path: str):
    with open(payload_path, "wb") as f:
        f.write(payload)


def write_json(obj: dict, path: str):
    json_str = json.dumps(obj, indent=2)

    with open(path, "wt") as f:
        f.write(json_str)


def read_json(path: str) -> dict:
    with open(path, "rt") as f:
        json_str = f.read()
    return json.loads(json_str)


# CLI handlers


def generate(payload_path, vault_key_shards_path, vault_specs_path):
    payload = load_payload(payload_path)
    try:
        vault_specs = read_json(vault_specs_path)
    except FileNotFoundError:
        vault_specs = {}

    vault_specs, vault_key_shards = create_recovery_vault(payload, vault_specs)

    write_json(vault_specs, vault_specs_path)
    write_json(vault_key_shards, vault_key_shards_path)


def unlock(payload_path, vault_key_shards_path, vault_specs_path):
    vault_specs = read_json(vault_specs_path)
    vault_key_shards = read_json(vault_key_shards_path)

    payload = unlock_recovery_vault(vault_specs, vault_key_shards)
    write_payload(payload, payload_path)


if __name__ == "__main__":
    match argv[1]:
        case "generate":
            generate(*argv[2:])
        case "unlock":
            unlock(*argv[2:])
        case _:
            raise Exception(
                f"Illegal argument `{argv[1]}`. Must be `generate` or `unlock`"
            )
