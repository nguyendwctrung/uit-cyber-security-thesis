from vuln_detection.sarif import parse_result


def test_parse_result():
    rules = {
        "java/path-injection": {
            "shortDescription": {
                "text": "Uncontrolled path data",
            },
            "defaultConfiguration": {
                "level": "error",
            },
            "properties": {
                "tags": [
                    "security",
                    "external/cwe/cwe-022",
                ],
            },
        },
    }

    item = {
        "ruleId": "java/path-injection",
        "message": {
            "text": "Path depends on user input.",
        },
        "partialFingerprints": {
            "primaryLocationLineHash": "test-hash",
        },
        "locations": [{
            "physicalLocation": {
                "artifactLocation": {
                    "uri": "src/main/java/Example.java",
                },
                "region": {
                    "startLine": 12,
                    "startColumn": 7,
                    "endLine": 12,
                    "endColumn": 15,
                },
            },
        }],
    }

    finding, error = parse_result(
        item,
        0,
        0,
        rules,
        "test-run",
        "raw/test.sarif",
        "raw-hash",
        "test-revision",
        "",
    )

    assert error is None
    assert finding["scanner"] == "codeql"
    assert finding["rule_id"] == "java/path-injection"
    assert finding["cwe_ids"] == ["CWE-22"]
    assert finding["severity_raw"] == "error"
    assert finding["location"]["path"] == "src/main/java/Example.java"
    assert finding["provenance"]["raw_pointer"] == "runs[0].results[0]"


def test_missing_location():
    finding, error = parse_result(
        {"ruleId": "java/path-injection"},
        0,
        0,
        {},
        "test-run",
        "raw/test.sarif",
        "raw-hash",
        "test-revision",
        "",
    )

    assert finding is None
    assert error["error_type"] == "missing_location"
    assert error["raw_pointer"] == "runs[0].results[0]"