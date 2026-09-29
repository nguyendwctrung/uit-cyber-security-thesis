from pathlib import Path

import pytest

from vuln_detection.verdict import get_candidate_id, validate_verdict


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "llm-verdict-v1.schema.json"


def make_candidate():
    return {
        "location": {
            "path": "src/Example.java",
            "start_line": 12,
        },
        "member_ids": [
            "codeql-finding",
            "semgrep-finding",
        ],
        "shared_cwe": "CWE-22",
    }


def make_method():
    return {
        "start_line": 10,
        "end_line": 20,
        "text": "public void run() {}",
    }


def make_verdict(candidate_id, verdict, evidence):
    return {
        "schema_version": "llm-verdict-v1",
        "candidate_id": candidate_id,
        "verdict": verdict,
        "reason": "Source-grounded explanation.",
        "evidence": evidence,
    }


def test_candidate_id_is_stable_for_same_candidate():
    first = make_candidate()
    second = {
        "shared_cwe": "CWE-22",
        "member_ids": [
            "codeql-finding",
            "semgrep-finding",
        ],
        "location": {
            "start_line": 12,
            "path": "src/Example.java",
        },
    }

    assert get_candidate_id(first) == get_candidate_id(second)
    assert len(get_candidate_id(first)) == 64


def test_candidate_id_changes_when_candidate_changes():
    first = make_candidate()
    second = make_candidate()
    second["location"]["start_line"] = 13

    assert get_candidate_id(first) != get_candidate_id(second)


def test_accepts_each_valid_verdict():
    candidate_id = get_candidate_id(make_candidate())
    method = make_method()
    evidence = [
        {
            "start_line": 12,
            "end_line": 12,
            "claim": "The value reaches the reported operation.",
        }
    ]

    validate_verdict(
        make_verdict(candidate_id, "VULNERABLE", evidence),
        candidate_id,
        method,
        SCHEMA_PATH,
    )
    validate_verdict(
        make_verdict(candidate_id, "NOT_VULNERABLE", evidence),
        candidate_id,
        method,
        SCHEMA_PATH,
    )
    validate_verdict(
        make_verdict(candidate_id, "UNCERTAIN", []),
        candidate_id,
        method,
        SCHEMA_PATH,
    )


def test_rejects_schema_invalid_verdict():
    candidate_id = get_candidate_id(make_candidate())
    verdict = make_verdict(candidate_id, "VULNERABLE", [])
    verdict["unexpected"] = "not allowed"

    with pytest.raises(ValueError, match="Schema validation failed"):
        validate_verdict(verdict, candidate_id, make_method(), SCHEMA_PATH)


def test_rejects_candidate_id_mismatch():
    candidate_id = get_candidate_id(make_candidate())
    verdict = make_verdict(
        "a" * 64,
        "VULNERABLE",
        [
            {
                "start_line": 12,
                "end_line": 12,
                "claim": "The value reaches the reported operation.",
            }
        ],
    )

    with pytest.raises(ValueError, match="candidate_id"):
        validate_verdict(verdict, candidate_id, make_method(), SCHEMA_PATH)


def test_rejects_evidence_outside_method():
    candidate_id = get_candidate_id(make_candidate())
    verdict = make_verdict(
        candidate_id,
        "VULNERABLE",
        [
            {
                "start_line": 9,
                "end_line": 12,
                "claim": "The value reaches the reported operation.",
            }
        ],
    )

    with pytest.raises(ValueError, match="Evidence range"):
        validate_verdict(verdict, candidate_id, make_method(), SCHEMA_PATH)


def test_rejects_reversed_evidence_range():
    candidate_id = get_candidate_id(make_candidate())
    verdict = make_verdict(
        candidate_id,
        "NOT_VULNERABLE",
        [
            {
                "start_line": 16,
                "end_line": 12,
                "claim": "The code validates the reported condition.",
            }
        ],
    )

    with pytest.raises(ValueError, match="Evidence range"):
        validate_verdict(verdict, candidate_id, make_method(), SCHEMA_PATH)