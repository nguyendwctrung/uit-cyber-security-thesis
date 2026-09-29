import hashlib
import json

from pathlib import Path
from jsonschema import Draft202012Validator

def get_candidate_id(candidate):
    text = json.dumps(
        candidate,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True
    )
    return hashlib.sha256(text.encode("utf-8")).hexdigest()

def load_schema(schema_path):
    return json.loads(Path(schema_path).read_text(encoding="utf-8"))

def validate_verdict(verdict, candidate_id, method, schema_path):
    schema = load_schema(schema_path)
    validator = Draft202012Validator(schema)
    errors = sorted(
        validator.iter_errors(verdict),
        key=lambda error: list(error.path)
    )

    if errors:
        raise ValueError("Schema validation failed: " + errors[0].message)

    if verdict["candidate_id"] != candidate_id:
        raise ValueError("Verdict candidate_id does not match input candidate_id.")

    for item in verdict["evidence"]:
        start_line = item["start_line"]
        end_line = item["end_line"]

        if (
            start_line > end_line
            or start_line < method["start_line"]
            or end_line > method["end_line"]
        ):
            raise ValueError("Evidence range is outside the supplied method.")
