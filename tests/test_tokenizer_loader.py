import hashlib

import pytest

from vuln_detection import tokenizer_loader


TOKENIZER_CONFIG = {
    "id": "Qwen/Qwen2.5-Coder-7B-Instruct",
    "revision": "0b044f5762b0be9c48fc2b7bc216454c5eff0bb8",
    "transformers_version": "4.57.1",
    "tokenizers_version": "0.22.1",
    "jinja2_version": "3.1.6",
}


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_loads_only_local_tokenizer_assets(
    tmp_path,
    monkeypatch,
):
    asset_dir = tmp_path / "qwen-tokenizer"
    asset_dir.mkdir()
    calls = []

    def fake_from_pretrained(path, **kwargs):
        calls.append(
            {
                "path": path,
                "kwargs": kwargs,
            }
        )
        return "tokenizer"

    monkeypatch.setattr(
        tokenizer_loader.AutoTokenizer,
        "from_pretrained",
        fake_from_pretrained,
    )

    tokenizer = tokenizer_loader.load_tokenizer(asset_dir)

    assert tokenizer == "tokenizer"
    assert calls == [
        {
            "path": str(asset_dir),
            "kwargs": {
                "local_files_only": True,
                "use_fast": True,
            },
        }
    ]


def test_records_configured_tokenizer_asset_provenance(tmp_path):
    asset_dir = tmp_path / "qwen-tokenizer"
    asset_dir.mkdir()

    tokenizer_json = asset_dir / "tokenizer.json"
    tokenizer_config = asset_dir / "tokenizer_config.json"
    tokenizer_json.write_text("tokenizer", encoding="utf-8")
    tokenizer_config.write_text("config", encoding="utf-8")

    provenance = tokenizer_loader.get_tokenizer_provenance(
        TOKENIZER_CONFIG,
        asset_dir,
    )

    assert provenance["id"] == TOKENIZER_CONFIG["id"]
    assert provenance["revision"] == TOKENIZER_CONFIG["revision"]
    assert provenance["transformers_version"] == "4.57.1"
    assert provenance["tokenizers_version"] == "0.22.1"
    assert provenance["jinja2_version"] == "3.1.6"
    assert provenance["assets"] == [
        {
            "path": "tokenizer.json",
            "sha256": sha256_file(tokenizer_json),
        },
        {
            "path": "tokenizer_config.json",
            "sha256": sha256_file(tokenizer_config),
        },
    ]


@pytest.mark.parametrize(
    ("field", "message"),
    [
        ("transformers_version", "transformers version"),
        ("tokenizers_version", "tokenizers version"),
        ("jinja2_version", "jinja2 version"),
    ],
)
def test_rejects_a_tokenizer_dependency_version_mismatch(
    field,
    message,
):
    invalid_config = dict(TOKENIZER_CONFIG)
    invalid_config[field] = "0.0.0"

    with pytest.raises(ValueError, match=message):
        tokenizer_loader.validate_tokenizer_versions(invalid_config)