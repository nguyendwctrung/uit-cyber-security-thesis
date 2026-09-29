from pathlib import Path

import pytest

from vuln_detection.prompt import render_prompt
from vuln_detection.verdict import get_candidate_id


ROOT = Path(__file__).resolve().parents[1]
PROMPT_PATH = ROOT / "prompts" / "p0-llm-no-rag-v1.txt"


def make_context():
    candidate = {
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
    }

    return {
        "candidate": candidate,
        "source_path": "src/Example.java",
        "source_revision": "test-revision",
        "method": {
            "start_line": 10,
            "end_line": 20,
            "text": "public void run() {\n    open(path);\n}",
        },
    }


def test_renders_all_locked_prompt_fields():
    context = make_context()

    text = render_prompt(context, PROMPT_PATH)

    assert "candidate_id: " + get_candidate_id(context["candidate"]) in text
    assert "source_path: src/Example.java" in text
    assert "source_revision: test-revision" in text
    assert "candidate_start_line: 12" in text
    assert "shared_cwe: CWE-22" in text
    assert "- codeql | java/path-injection | Uncontrolled data reaches a path operation." in text
    assert "- semgrep | java.path-traversal | Potential path traversal." in text
    assert "method_start_line: 10" in text
    assert "method_end_line: 20" in text
    assert "public void run() {" in text
    assert "{{" not in text
    assert "}}" not in text


def test_rendering_is_deterministic():
    context = make_context()

    first = render_prompt(context, PROMPT_PATH)
    second = render_prompt(context, PROMPT_PATH)

    assert first == second


def test_rejects_an_unknown_placeholder(tmp_path):
    prompt_path = tmp_path / "prompt.txt"
    prompt_path.write_text(
        "candidate: {{candidate_id}}\nunknown: {{unknown}}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unknown prompt placeholder"):
        render_prompt(make_context(), prompt_path)


def test_rejects_context_without_a_method():
    context = make_context()
    del context["method"]

    with pytest.raises(ValueError, match="Context must include method"):
        render_prompt(context, PROMPT_PATH)