import argparse
import json
from pathlib import Path

from vuln_detection.sarif import parse_file as parse_sarif
from vuln_detection.semgrep import parse_file as parse_semgrep

def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--scanner", required=True)
    parser.add_argument("--input", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--raw-artifact", required=True)
    parser.add_argument("--raw-hash", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--error-output", required=True)

    return parser.parse_args()

def get_parser(scanner):
    if scanner == 'semgrep':
        return parse_semgrep

    if scanner == 'codeql':
        return parse_sarif

    raise ValueError("Scanner must be semgrep or codeql.")

def check_output(path):
    if path.exists():
        raise ValueError("Output already exists: " + str(path))

def write_rows(path, rows):
    with path.open("x", encoding="utf-8") as file:
        for row in rows:
            file.write(json.dumps(row, sort_keys=True))
            file.write("\n")

def main():
    args = get_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    error_path = Path(args.error_output)

    try:
        parser = get_parser(args.scanner)
        check_output(output_path)
        check_output(error_path)

        findings, errors = parser(
            str(input_path),
            args.run_id,
            args.raw_artifact,
            args.raw_hash,
            args.source_revision,
            args.source_root,
        )

        write_rows(output_path, findings)
        write_rows(error_path, errors)

    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("Normalization failed: " + str(error))
        return 1

    print("Scanner:", args.scanner)
    print("Findings:", len(findings))
    print("Errors:", len(errors))
    print("Finding output:", output_path)
    print("Error output:", error_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())