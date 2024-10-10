import recovery
from random import sample


def end_to_end():
    expected_payload = bytes("this is a secret", "utf-8")
    password = "1234"
    vault_specs, vault_key_shards = recovery.create_recovery_vault(
        payload=expected_payload,
        num_shards=10,
        shard_threshold=6,
        password=password,
    )

    secret_shards_subset = sample(vault_key_shards["secret_shards"], 6)
    vault_key_shards_subset = {
        "_version": "v1.0",
        "secret_shards": secret_shards_subset,
    }

    recovery.unlock_recovery_vault(
        vault_specs, vault_key_shards_subset, password=password
    )


if __name__ == "__main__":
    end_to_end()
