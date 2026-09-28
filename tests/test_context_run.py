import json
import sys

from vuln_detection.context_run import main


def make_candidate(line):
    members = [
        {
            "finding_id": "codeql-1",
            "scanner": "codeql",
            "provenance": {
                "source_revision": "test-revision",
                "raw_pointer": "runs[0].results[1]",
            },
        },
        {
            "finding_id": "semgrep-1",
            "scanner": "semgrep",
            "provenance": {
                "source_revision": "test-revision",
                "raw_pointer": "results[0]",
            },
        },
    ]

    return {
        "match_rule": "path-line-cwe-v1",
        "location": {
            "path": "src/Example.java",
            "start_line": line,
        },
        "shared_cwe": "CWE-22",
        "member_ids": ["codeql-1", "semgrep-1"],
        "members": members,
    }


def write_rows(path, rows):
    with path.open("w", encoding="utf-8") as file:
        for row in rows:
            file.write(json.dumps(row))
            file.write("\n")


def set_args(monkeypatch, input_path, source_root, output_path, error_path):
    monkeypatch.setattr(sys, "argv", [
        "context_run",
        "--input", str(input_path),
        "--source-root", str(source_root),
        "--output", str(output_path),
        "--error-output", str(error_path),
    ])


def test_main_writes_method_context(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "candidates.jsonl"
    source_root = tmp_path / "source"
    source_path = source_root / "src" / "Example.java"
    output_path = tmp_path / "contexts.jsonl"
    error_path = tmp_path / "errors.jsonl"

    source_path.parent.mkdir(parents=True)
    source_path.write_text(
        "\n".join([
            "public class Example {",
            "    public void run() {",
            "        call();",
            "    }",
            "}",
        ]),
        encoding="utf-8",
    )
    write_rows(input_path, [make_candidate(3)])
    set_args(monkeypatch, input_path, source_root, output_path, error_path)

    exit_code = main()
    text = capsys.readouterr().out
    rows = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]

    assert exit_code == 0
    assert "Contexts: 1" in text
    assert "Errors: 0" in text
    assert len(rows) == 1
    assert rows[0]["candidate"]["member_ids"] == [
        "codeql-1",
        "semgrep-1",
    ]
    assert rows[0]["source_revision"] == "test-revision"
    assert rows[0]["method"]["start_line"] == 2
    assert rows[0]["method"]["end_line"] == 4
    assert error_path.read_text(encoding="utf-8") == ""


def test_method_not_found_is_written_as_error(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "candidates.jsonl"
    source_root = tmp_path / "source"
    source_path = source_root / "src" / "Example.java"
    output_path = tmp_path / "contexts.jsonl"
    error_path = tmp_path / "errors.jsonl"

    source_path.parent.mkdir(parents=True)
    source_path.write_text(
        "\n".join([
            "public class Example {",
            "    private String name;",
            "}",
        ]),
        encoding="utf-8",
    )
    write_rows(input_path, [make_candidate(2)])
    set_args(monkeypatch, input_path, source_root, output_path, error_path)

    exit_code = main()
    text = capsys.readouterr().out
    errors = [
        json.loads(line)
        for line in error_path.read_text(encoding="utf-8").splitlines()
    ]

    assert exit_code == 0
    assert "Contexts: 0" in text
    assert "Errors: 1" in text
    assert output_path.read_text(encoding="utf-8") == ""
    assert errors[0]["error"]["error_type"] == "method_not_found"
    assert errors[0]["candidate"]["member_ids"] == [
        "codeql-1",
        "semgrep-1",
    ]


def test_existing_output_is_not_overwritten(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "candidates.jsonl"
    source_root = tmp_path / "source"
    output_path = tmp_path / "contexts.jsonl"
    error_path = tmp_path / "errors.jsonl"

    write_rows(input_path, [make_candidate(3)])
    output_path.write_text("keep this file\n", encoding="utf-8")
    set_args(monkeypatch, input_path, source_root, output_path, error_path)

    exit_code = main()
    text = capsys.readouterr().out

    assert exit_code == 1
    assert "Output already exists" in text
    assert output_path.read_text(encoding="utf-8") == "keep this file\n"
    assert not error_path.exists()


def test_invalid_input_returns_error(tmp_path, monkeypatch, capsys):
    input_path = tmp_path / "candidates.jsonl"
    source_root = tmp_path / "source"
    output_path = tmp_path / "contexts.jsonl"
    error_path = tmp_path / "errors.jsonl"

    input_path.write_text("not json\n", encoding="utf-8")
    set_args(monkeypatch, input_path, source_root, output_path, error_path)

    exit_code = main()
    text = capsys.readouterr().out

    assert exit_code == 1
    assert "Context extraction failed:" in text
    assert not output_path.exists()
    assert not error_path.exists()