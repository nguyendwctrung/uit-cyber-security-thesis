CONTROLS = [
    "if",
    "for",
    "while",
    "switch",
    "catch",
    "synchronized",
]


def get_header(lines, line):
    parts = []
    index = line

    while index >= 0:
        text = lines[index].strip()
        parts.insert(0, text)

        if index < line and (
            "{" in text or "}" in text or ";" in text
        ):
            return " ".join(parts), index + 1

        index -= 1

    return " ".join(parts), 0


def is_method(lines, line):
    header, start = get_header(lines, line)

    if "(" not in header or ")" not in header:
        return False

    before = header.rsplit("(", 1)[0]

    for word in CONTROLS:
        if word + " " in before or word + "(" in before:
            return False

    return True


def get_pairs(lines):
    stack = []
    pairs = []

    for line, text in enumerate(lines):
        for char in text:
            if char == "{":
                stack.append(line)

            if char == "}" and stack:
                start = stack.pop()
                pairs.append((start, line))

    return pairs


def find_method(lines, target_line):
    target = target_line - 1
    methods = []

    for start, end in get_pairs(lines):
        if start <= target <= end and is_method(lines, start):
            header, header_start = get_header(lines, start)
            methods.append((header_start, end))

    if not methods:
        return None, {
            "error_type": "method_not_found",
            "target_line": target_line,
        }

    start, end = min(methods, key=lambda item: item[1] - item[0])

    return {
        "start_line": start + 1,
        "end_line": end + 1,
        "text": "\n".join(lines[start:end + 1]),
    }, None
