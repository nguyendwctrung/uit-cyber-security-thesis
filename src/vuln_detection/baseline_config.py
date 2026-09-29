import hashlib
import json
from pathlib import Path


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def get_config_sha256(config_path):
    return sha256_file(Path(config_path))


def validate_artifact_hash(config, root, name):
    artifact = config[name]
    path = Path(root) / artifact["path"]

    if not path.is_file():
        raise ValueError(
            name + " file does not exist: " + str(path)
        )

    actual_hash = sha256_file(path)

    if actual_hash != artifact["sha256"]:
        raise ValueError(
            name + " SHA-256 does not match the baseline config."
        )


def validate_input_budget(config):
    options = config["request"]["options"]
    expected = options["num_ctx"] - options["num_predict"]
    actual = config["token_budget"]["max_input_tokens"]

    if actual != expected:
        raise ValueError(
            "max_input_tokens must equal num_ctx minus num_predict"
        )


def load_baseline_config(config_path, root):
    config_path = Path(config_path)
    root = Path(root)

    config = json.loads(config_path.read_text(encoding="utf-8"))

    if config["rag_enabled"] is not False:
        raise ValueError("rag_enabled must be false")

    validate_artifact_hash(config, root, "prompt")
    validate_artifact_hash(config, root, "schema")
    validate_input_budget(config)

    return config