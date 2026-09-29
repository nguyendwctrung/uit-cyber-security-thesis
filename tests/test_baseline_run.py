import hashlib
import json
from pathlib import Path

import pytest

from vuln_detection import baseline_run
from vuln_detection.verdict import get_candidate_id


ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "configs" / "p0-llm-no-rag-v1.json"


class FakeResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class FakeClient:
    def __init__(self, response):
        self.response = response
        self.calls = []

    def post(self, url, json, timeout):
        self.calls.append(
            {
                "url": url,
                "json": json,
                "timeout": timeout,
            }
        )
        return self.response


class FakeTokenizer:
    def apply_chat_template(
        self,
        messages,
        add_generation_prompt,
        tokenize,
    ):
        return [0]


def sha256_file(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def make_context():
    return {
        "candidate": {
            "location": {
                "path": "src/Example.java",
                "start_line": 12,
            },
            "shared_cwe": "CWE-22",
            "member_ids": [
                "codeql-finding",
                "semgrep-finding",
            ],
            "members": [
                {
                    "scanner": "codeql",
                    "rule_id": "java/path-injection",
                    "message": "Uncontrolled data reaches a path operation.",
                }
            ],
        },
        "source_path": "src/Example.java",
        "source_revision": "test-revision",
        "method": {
            "start_line": 10,
            "end_line": 20,
            "text": "public void run() {\n    open(path);\n}",
        },
    }


def write_contexts(path, contexts):
    with path.open("w", encoding="utf-8") as file:
        for context in contexts:
            file.write(json.dumps(context))
            file.write("\n")


def make_model_info():
    return {
        "tag": "qwen2.5-coder:7b",
        "digest": (
            "dae161e27b0e90dd1856c8bb3209201fd6736d8eb66298e75"
            "ed87571486f4364"
        ),
        "ollama_version": "0.34.4",
    }


def make_response(context):
    candidate_id = get_candidate_id(context["candidate"])
    verdict = {
        "schema_version": "llm-verdict-v1",
        "candidate_id": candidate_id,
        "verdict": "VULNERABLE",
        "reason": "The value reaches the path operation.",
        "evidence": [
            {
                "start_line": 12,
                "end_line": 12,
                "claim": "The operation uses the candidate value.",
            }
        ],
    }

    return FakeResponse(
        200,
        json.dumps(
            {
                "message": {
                    "content": json.dumps(verdict),
                }
            }
        ),
    )


def configure_tokenizer(monkeypatch):
    monkeypatch.setattr(
        baseline_run,
        "load_tokenizer",
        lambda asset_dir: FakeTokenizer(),
        raising=False,
    )
    monkeypatch.setattr(
        baseline_run,
        "get_tokenizer_provenance",
        lambda tokenizer_config, asset_dir: {
            "id": tokenizer_config["id"],
            "revision": tokenizer_config["revision"],
            "assets": [],
        },
        raising=False,
    )
    monkeypatch.setattr(
        baseline_run,
        "get_implementation_provenance",
        lambda root: {
            "git_head": "test-head",
            "requirements_sha256": "test-requirements-hash",
            "source_tree_sha256": "test-source-tree-hash",
            "source_files": [],
        },
        raising=False,
    )


def test_creates_configured_no_rag_run_bundle_and_manifest(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        "OLLAMA_URL",
        "http://127.0.0.1:11434/api/chat",
    )
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    configure_tokenizer(monkeypatch)

    context = make_context()
    context_path = tmp_path / "contexts.jsonl"
    run_dir = tmp_path / "P0-LLM-001-test"
    write_contexts(context_path, [context])

    result = baseline_run.run_baseline(
        context_path,
        CONFIG_PATH,
        run_dir,
        FakeClient(make_response(context)),
        make_model_info(),
        ROOT,
    )

    manifest = json.loads(
        result["manifest_path"].read_text(encoding="utf-8")
    )

    assert manifest["baseline_config_id"] == "p0-llm-no-rag-v1"
    assert manifest["rag_enabled"] is False
    assert manifest["config"]["path"] == str(CONFIG_PATH)
    assert manifest["config"]["sha256"] == sha256_file(CONFIG_PATH)
    assert manifest["model"] == make_model_info()
    assert manifest["tokenizer"] == {
        "id": "Qwen/Qwen2.5-Coder-7B-Instruct",
        "revision": "0b044f5762b0be9c48fc2b7bc216454c5eff0bb8",
        "assets": [],
    }
    assert manifest["implementation"] == {
        "git_head": "test-head",
        "requirements_sha256": "test-requirements-hash",
        "source_tree_sha256": "test-source-tree-hash",
        "source_files": [],
    }
    assert manifest["options"] == json.loads(
        CONFIG_PATH.read_text(encoding="utf-8")
    )["request"]["options"]
    assert manifest["counts"] == {
        "contexts": 1,
        "verdicts": 1,
        "errors": 0,
    }


def test_rejects_a_model_digest_mismatch_before_a_request(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        "OLLAMA_URL",
        "http://127.0.0.1:11434/api/chat",
    )
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    configure_tokenizer(monkeypatch)

    context_path = tmp_path / "contexts.jsonl"
    write_contexts(context_path, [make_context()])
    client = FakeClient(make_response(make_context()))
    model_info = make_model_info()
    model_info["digest"] = "wrong-digest"

    with pytest.raises(ValueError, match="Model digest"):
        baseline_run.run_baseline(
            context_path,
            CONFIG_PATH,
            tmp_path / "P0-LLM-001-digest-mismatch",
            client,
            model_info,
            ROOT,
        )

    assert not client.calls


def test_refuses_to_overwrite_an_existing_run_directory(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        "OLLAMA_URL",
        "http://127.0.0.1:11434/api/chat",
    )
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")
    configure_tokenizer(monkeypatch)

    context_path = tmp_path / "contexts.jsonl"
    write_contexts(context_path, [make_context()])

    run_dir = tmp_path / "P0-LLM-001-existing"
    run_dir.mkdir()
    client = FakeClient(make_response(make_context()))

    with pytest.raises(ValueError, match="Output already exists"):
        baseline_run.run_baseline(
            context_path,
            CONFIG_PATH,
            run_dir,
            client,
            make_model_info(),
            ROOT,
        )

    assert not client.calls