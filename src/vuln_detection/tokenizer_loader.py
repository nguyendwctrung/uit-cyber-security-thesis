import hashlib
import jinja2
from pathlib import Path

import tokenizers
import transformers
from transformers import AutoTokenizer


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate_tokenizer_versions(tokenizer_config):
    if (transformers.__version__ != tokenizer_config["transformers_version"]):
        raise ValueError("transformers version does not match baseline config.")

    if (tokenizers.__version__ != tokenizer_config["tokenizers_version"]):
        raise ValueError("tokenizers version does not match baseline config.")

    if (jinja2.__version__ != tokenizer_config["jinja2_version"]):
        raise ValueError("jinja2 version does not match baseline config.")


def load_tokenizer(asset_dir):
    asset_dir = Path(asset_dir)

    if not asset_dir.is_dir():
        raise ValueError(
            "Tokenizer asset directory does not exist: "
            + str(asset_dir)
        )

    return AutoTokenizer.from_pretrained(
        str(asset_dir),
        local_files_only=True,
        use_fast=True,
    )


def get_tokenizer_assets(asset_dir):
    asset_dir = Path(asset_dir)
    assets = []

    for path in sorted(asset_dir.rglob("*")):
        if not path.is_file():
            continue

        relative_path = path.relative_to(asset_dir)

        if relative_path.parts[0] == ".cache":
            continue

        assets.append(
            {
                "path": relative_path.as_posix(),
                "sha256": sha256_file(path),
            }
        )

    return assets


def get_tokenizer_provenance(tokenizer_config, asset_dir):
    validate_tokenizer_versions(tokenizer_config)

    return {
        "id": tokenizer_config["id"],
        "revision": tokenizer_config["revision"],
        "transformers_version": transformers.__version__,
        "tokenizers_version": tokenizers.__version__,
                "jinja2_version": jinja2.__version__,
        "assets": get_tokenizer_assets(asset_dir),
    }