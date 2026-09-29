import hashlib
import json
from pathlib import Path

import pytest

from vuln_detection.baseline_config import (
    get_config_sha256,
    load_baseline_config,
)


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "configs" / "p0-llm-no-rag-v1.json"


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_loads_and_validates_the_versioned_baseline_config():
    config = load_baseline_config(CONFIG_PATH, ROOT)

    assert config["baseline_config_id"] == "p0-llm-no-rag-v1"
    assert config["rag_enabled"] is False
    assert config["request"]["stream"] is False
    assert config["request"]["max_attempts"] == 1
    assert config["request"]["parallelism"] == 1
    assert config["token_budget"]["max_input_tokens"] == 7680
    assert config["prompt"]["sha256"] == sha256_file(
        ROOT / config["prompt"]["path"]
    )
    assert config["schema"]["sha256"] == sha256_file(
        ROOT / config["schema"]["path"]
    )
    assert get_config_sha256(CONFIG_PATH) == sha256_file(CONFIG_PATH)


def test_rejects_a_rag_enabled_baseline_config(tmp_path):
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    config["rag_enabled"] = True

    path = tmp_path / "invalid-config.json"
    path.write_text(json.dumps(config), encoding="utf-8")

    with pytest.raises(ValueError, match="rag_enabled must be false"):
        load_baseline_config(path, ROOT)


def test_rejects_an_inconsistent_input_budget(tmp_path):
    config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    config["token_budget"]["max_input_tokens"] = 7681

    path = tmp_path / "invalid-config.json"
    path.write_text(json.dumps(config), encoding="utf-8")

    with pytest.raises(
        ValueError,
        match="max_input_tokens must equal num_ctx minus num_predict",
    ):
        load_baseline_config(path, ROOT)