from vuln_detection.correlate import correlate


def make_finding(scanner, finding_id, path, line, cwe_ids):
    return {
        "finding_id": finding_id,
        "scanner": scanner,
        "location": {
            "path": path,
            "start_line": line,
        },
        "cwe_ids": cwe_ids,
        "provenance": {
            "raw_pointer": scanner + "-pointer",
        },
    }


def test_match_same_path_line_and_cwe():
    semgrep = make_finding(
        "semgrep",
        "semgrep-1",
        "src/Example.java",
        10,
        ["CWE-22"],
    )
    codeql = make_finding(
        "codeql",
        "codeql-1",
        "src/Example.java",
        10,
        ["CWE-22", "CWE-23"],
    )

    candidates = correlate([semgrep, codeql])

    assert len(candidates) == 1
    candidate = candidates[0]

    assert candidate["match_rule"] == "path-line-cwe-v1"
    assert candidate["location"] == {
        "path": "src/Example.java",
        "start_line": 10,
    }
    assert candidate["shared_cwe"] == "CWE-22"
    assert candidate["member_ids"] == ["codeql-1", "semgrep-1"]
    assert candidate["members"] == [codeql, semgrep]


def test_different_path_line_or_cwe_does_not_match():
    base = make_finding(
        "semgrep",
        "semgrep-1",
        "src/Example.java",
        10,
        ["CWE-22"],
    )
    different_path = make_finding(
        "codeql",
        "codeql-1",
        "src/Other.java",
        10,
        ["CWE-22"],
    )
    different_line = make_finding(
        "codeql",
        "codeql-2",
        "src/Example.java",
        11,
        ["CWE-22"],
    )
    different_cwe = make_finding(
        "codeql",
        "codeql-3",
        "src/Example.java",
        10,
        ["CWE-79"],
    )

    assert correlate([base, different_path]) == []
    assert correlate([base, different_line]) == []
    assert correlate([base, different_cwe]) == []


def test_same_scanner_does_not_match():
    first = make_finding(
        "semgrep",
        "semgrep-1",
        "src/Example.java",
        10,
        ["CWE-22"],
    )
    second = make_finding(
        "semgrep",
        "semgrep-2",
        "src/Example.java",
        10,
        ["CWE-22"],
    )

    assert correlate([first, second]) == []


def test_output_is_deterministic_and_keeps_provenance():
    semgrep = make_finding(
        "semgrep",
        "semgrep-1",
        "src/Example.java",
        10,
        ["CWE-22"],
    )
    codeql = make_finding(
        "codeql",
        "codeql-1",
        "src/Example.java",
        10,
        ["CWE-22"],
    )

    first = correlate([semgrep, codeql])
    second = correlate([codeql, semgrep])

    assert first == second
    assert first[0]["members"][0]["provenance"]["raw_pointer"] == "codeql-pointer"
    assert first[0]["members"][1]["provenance"]["raw_pointer"] == "semgrep-pointer"