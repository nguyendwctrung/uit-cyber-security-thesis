import re
from pathlib import Path

from vuln_detection.verdict import get_candidate_id


PLACEHOLDER_PATTERN = re.compile(r"{{([a-z_]+)}}")


def get_scanner_summary(candidate):
    lines = []

    for member in candidate["members"]:
        lines.append(
            "- "
            + member["scanner"]
            + " | "
            + member["rule_id"]
            + " | "
            + member["message"]
        )

    return "\n".join(lines)


def get_values(context):
    if "method" not in context:
        raise ValueError("Context must include method.")

    candidate = context["candidate"]
    method = context["method"]

    return {
        "candidate_id": get_candidate_id(candidate),
        "source_path": context["source_path"],
        "source_revision": context["source_revision"],
        "candidate_start_line": str(
            candidate["location"]["start_line"]
        ),
        "shared_cwe": candidate["shared_cwe"],
        "scanner_summary": get_scanner_summary(candidate),
        "method_start_line": str(method["start_line"]),
        "method_end_line": str(method["end_line"]),
        "method_text": method["text"],
    }


def render_prompt(context, prompt_path):
    text = Path(prompt_path).read_text(encoding="utf-8")
    values = get_values(context)
    names = set(PLACEHOLDER_PATTERN.findall(text))
    unknown = sorted(names - set(values))

    if unknown:
        raise ValueError(
            "Unknown prompt placeholder: " + ", ".join(unknown)
        )

    for name in names:
        text = text.replace("{{" + name + "}}", values[name])

    return text