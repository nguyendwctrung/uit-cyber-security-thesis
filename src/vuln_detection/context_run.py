import argparse
import json
from pathlib import Path

from vuln_detection.source_context import find_method


def get_args():
    parser = argparse.ArgumentParser()

    parser.add_argument("--input", required=True)
    parser.add_argument("--source-root", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--error-output", required=True)

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


def get_revision(candidate):
    revisions = {
        member["provenance"]["source_revision"]
        for member in candidate["members"]
    }

    if len(revisions) != 1:
        raise ValueError("Candidate must have one source revision.")

    return revisions.pop()


def get_context(candidate, source_root):
    location = candidate["location"]
    source_path = Path(source_root) / location["path"]
    lines = source_path.read_text(encoding="utf-8").splitlines()

    method, error = find_method(lines, location["start_line"])

    if error:
        return None, {
            "candidate": candidate,
            "error": error,
        }

    return {
        "candidate": candidate,
        "source_path": location["path"],
        "source_revision": get_revision(candidate),
        "method": method,
    }, None


def main():
    args = get_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    error_path = Path(args.error_output)

    try:
        check_output(output_path)
        check_output(error_path)

        candidates = read_rows(input_path)
        contexts = []
        errors = []

        for candidate in candidates:
            context, error = get_context(candidate, args.source_root)

            if context:
                contexts.append(context)

            if error:
                errors.append(error)

        write_rows(output_path, contexts)
        write_rows(error_path, errors)

    except (OSError, ValueError, json.JSONDecodeError) as error:
        print("Context extraction failed: " + str(error))
        return 1

    print("Contexts:", len(contexts))
    print("Errors:", len(errors))
    print("Context output:", output_path)
    print("Error output:", error_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())