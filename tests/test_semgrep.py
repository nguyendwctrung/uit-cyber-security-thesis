from vuln_detection.semgrep import parse_result


def test_parse_result():
    item = {
        "check_id": "java/test-rule",
        "path": "src\\Example.java",
        "start": {"line": 10, "col": 5},
        "end": {"line": 10, "col": 12},
        "extra": {
            "fingerprint": "test-fingerprint",
            "message": "Test message.",
            "severity": "ERROR",
            "metadata": {
                "cwe": ["CWE-89: SQL Injection"],
                "vulnerability_class": ["SQL Injection"],
            },
        },
    }

    finding, error = parse_result(
        item,
        0,
        "test-run",
        "raw/test.json",
        "test-hash",
        "test-revision",
        "src",
    )

    assert error is None
    assert finding["scanner"] == "semgrep"
    assert finding["rule_id"] == "java/test-rule"
    assert finding["cwe_ids"] == ["CWE-89"]
    assert finding["location"]["path"] == "Example.java"
    assert finding["provenance"]["raw_pointer"] == "results[0]"
    assert finding["location"]["end_line"] == 10
    assert finding["provenance"]["raw_path"] == "src\\Example.java"


def test_missing_location():
    item = {
        "check_id": "java/test-rule",
        "path": "src/Example.java",
        "extra": {},
    }

    finding, error = parse_result(
        item,
        0,
        "test-run",
        "raw/test.json",
        "test-hash",
        "test-revision",
        "src",
    )

    assert finding is None
    assert error["error_type"] == "missing_location"