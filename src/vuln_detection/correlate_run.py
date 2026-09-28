import argparse
import json
from pathlib import Path

from vuln_detection.correlate import correlate


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--semgrep-input", required=True)
    parser.add_argument("--codeql-input", required=True)
    parser.add_argument("--output", required=True)

    return parser.parse_args()


def read_rows(path):
    rows = []

    with path.open(encoding="utf-8") as file:
        for line in file:
            if line.strip():
                rows.append(json.loads(line))

    return rows


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

    semgrep_path = Path(args.semgrep_input)
    codeql_path = Path(args.codeql_input)
    output_path = Path(args.output)

    try:
        check_output(output_path)

        semgrep_rows = read_rows(semgrep_path)
        codeql_rows = read_rows(codeql_path)
        candidates = correlate(semgrep_rows + codeql_rows)

        write_rows(output_path, candidates)

    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("Correlation failed: " + str(error))
        return 1

    print("Candidates:", len(candidates))
    print("Output:", output_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())