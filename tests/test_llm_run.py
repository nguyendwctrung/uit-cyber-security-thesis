import json
from pathlib import Path

import pytest

from vuln_detection.llm_run import run_contexts
from vuln_detection.verdict import get_candidate_id


ROOT = Path(__file__).resolve().parents[1]
PROMPT_PATH = ROOT / "prompts" / "p0-llm-no-rag-v1.txt"
SCHEMA_PATH = ROOT / "schemas" / "llm-verdict-v1.schema.json"

OPTIONS = {
    "temperature": 0.0,
    "seed": 42,
    "top_p": 1.0,
    "top_k": 40,
    "min_p": 0.0,
    "repeat_penalty": 1.0,
    "num_ctx": 8192,
    "num_predict": 512,
}


class FakeResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


class FakeClient:
    def __init__(self, result):
        self.result = result
        self.calls = []

    def post(self, url, json, timeout):
        self.calls.append(
            {
                "url": url,
                "json": json,
                "timeout": timeout,
            }
        )

        if isinstance(self.result, Exception):
            raise self.result

        return self.result


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
                },
                {
                    "scanner": "semgrep",
                    "rule_id": "java.path-traversal",
                    "message": "Potential path traversal.",
                },
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


def make_api_response(verdict):
    return json.dumps(
        {
            "message": {
                "content": json.dumps(verdict),
            }
        }
    )


def make_paths(tmp_path):
    return {
        "verdict_path": tmp_path / "verdicts.jsonl",
        "error_path": tmp_path / "errors.jsonl",
        "request_dir": tmp_path / "raw" / "requests",
        "response_dir": tmp_path / "raw" / "responses",
    }


class UnderBudgetTokenizer:
    def apply_chat_template(
        self,
        messages,
        add_generation_prompt,
        tokenize,
    ):
        return [0]


def run_once(monkeypatch, client, paths):
    monkeypatch.setenv(
        "OLLAMA_URL",
        "http://127.0.0.1:11434/api/chat",
    )
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")

    return run_contexts(
        [make_context()],
        PROMPT_PATH,
        SCHEMA_PATH,
        paths["verdict_path"],
        paths["error_path"],
        paths["request_dir"],
        paths["response_dir"],
        client,
        OPTIONS,
        120,
        UnderBudgetTokenizer(),
        7680,
    )


def read_rows(path):
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
    ]


def test_writes_valid_verdict_and_raw_artifacts(tmp_path, monkeypatch):
    context = make_context()
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
    paths = make_paths(tmp_path)
    client = FakeClient(FakeResponse(200, make_api_response(verdict)))

    run_once(monkeypatch, client, paths)

    rows = read_rows(paths["verdict_path"])
    assert len(rows) == 1
    assert rows[0]["candidate"] == context["candidate"]
    assert rows[0]["source_path"] == "src/Example.java"
    assert rows[0]["source_revision"] == "test-revision"
    assert rows[0]["verdict"] == verdict
    assert paths["error_path"].read_text(encoding="utf-8") == ""
    assert (
        paths["request_dir"] / (candidate_id + ".json")
    ).exists()
    assert (
        paths["response_dir"] / (candidate_id + ".json")
    ).read_text(encoding="utf-8") == make_api_response(verdict)


def test_invalid_model_json_is_an_error_with_raw_response(
    tmp_path,
    monkeypatch,
):
    paths = make_paths(tmp_path)
    raw_response = '{"message":{"content":"not json"}}'
    client = FakeClient(FakeResponse(200, raw_response))

    run_once(monkeypatch, client, paths)

    errors = read_rows(paths["error_path"])
    assert paths["verdict_path"].read_text(encoding="utf-8") == ""
    assert errors[0]["error_type"] == "invalid_json"
    assert list(paths["response_dir"].glob("*.json"))
    assert (
        list(paths["response_dir"].glob("*.json"))[0]
    ).read_text(encoding="utf-8") == raw_response


@pytest.mark.parametrize(
    ("failure", "error_type"),
    [
        (TimeoutError("timed out"), "llm_timeout"),
        (ConnectionError("connection failed"), "ollama_unavailable"),
    ],
)
def test_transport_failures_keep_raw_request(
    tmp_path,
    monkeypatch,
    failure,
    error_type,
):
    paths = make_paths(tmp_path)
    client = FakeClient(failure)

    run_once(monkeypatch, client, paths)

    errors = read_rows(paths["error_path"])
    assert paths["verdict_path"].read_text(encoding="utf-8") == ""
    assert errors[0]["error_type"] == error_type
    assert list(paths["request_dir"].glob("*.json"))
    assert not list(paths["response_dir"].glob("*.json"))


def test_http_error_keeps_raw_response(tmp_path, monkeypatch):
    paths = make_paths(tmp_path)
    client = FakeClient(FakeResponse(500, "Ollama internal error"))

    run_once(monkeypatch, client, paths)

    errors = read_rows(paths["error_path"])
    assert paths["verdict_path"].read_text(encoding="utf-8") == ""
    assert errors[0]["error_type"] == "http_error"
    assert list(paths["response_dir"].glob("*.json"))
    assert (
        list(paths["response_dir"].glob("*.json"))[0]
    ).read_text(encoding="utf-8") == "Ollama internal error"


def test_refuses_to_overwrite_existing_output(tmp_path, monkeypatch):
    paths = make_paths(tmp_path)
    paths["verdict_path"].write_text("keep this file\n", encoding="utf-8")
    client = FakeClient(FakeResponse(200, "{}"))

    with pytest.raises(ValueError, match="Output already exists"):
        run_once(monkeypatch, client, paths)

    assert paths["verdict_path"].read_text(encoding="utf-8") == "keep this file\n"
    assert not client.calls


class OverBudgetTokenizer:
    def apply_chat_template(
        self,
        messages,
        add_generation_prompt,
        tokenize,
    ):
        return list(range(7681))


def test_over_budget_context_is_not_sent_to_ollama(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        "OLLAMA_URL",
        "http://127.0.0.1:11434/api/chat",
    )
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")

    paths = make_paths(tmp_path)
    client = FakeClient(FakeResponse(200, "{}"))

    run_contexts(
        [make_context()],
        PROMPT_PATH,
        SCHEMA_PATH,
        paths["verdict_path"],
        paths["error_path"],
        paths["request_dir"],
        paths["response_dir"],
        client,
        OPTIONS,
        120,
        OverBudgetTokenizer(),
        7680,
    )

    errors = read_rows(paths["error_path"])

    assert paths["verdict_path"].read_text(encoding="utf-8") == ""
    assert errors[0]["error_type"] == "context_window_exceeded"
    assert not client.calls
    assert not list(paths["request_dir"].glob("*.json"))
    assert not list(paths["response_dir"].glob("*.json"))


class BrokenTokenizer:
    def apply_chat_template(
        self,
        messages,
        add_generation_prompt,
        tokenize,
    ):
        raise RuntimeError("tokenizer failed")


def test_tokenizer_failure_is_not_sent_to_ollama(
    tmp_path,
    monkeypatch,
):
    monkeypatch.setenv(
        "OLLAMA_URL",
        "http://127.0.0.1:11434/api/chat",
    )
    monkeypatch.setenv("OLLAMA_MODEL", "qwen2.5-coder:7b")

    paths = make_paths(tmp_path)
    client = FakeClient(FakeResponse(200, "{}"))

    run_contexts(
        [make_context()],
        PROMPT_PATH,
        SCHEMA_PATH,
        paths["verdict_path"],
        paths["error_path"],
        paths["request_dir"],
        paths["response_dir"],
        client,
        OPTIONS,
        120,
        BrokenTokenizer(),
        7680,
    )

    errors = read_rows(paths["error_path"])

    assert paths["verdict_path"].read_text(encoding="utf-8") == ""
    assert errors[0]["error_type"] == "tokenizer_error"
    assert len(errors) == 1
    assert not client.calls
    assert not list(paths["request_dir"].glob("*.json"))
    assert not list(paths["response_dir"].glob("*.json"))