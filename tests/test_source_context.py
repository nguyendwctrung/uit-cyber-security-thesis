from vuln_detection.source_context import find_method


def test_finds_method_with_nested_braces():
    lines = [
        "public class Demo {",
        "    public void run() {",
        "        if (true) {",
        "            call();",
        "        }",
        "    }",
        "}",
    ]

    context, error = find_method(lines, 4)

    assert error is None
    assert context["start_line"] == 2
    assert context["end_line"] == 6
    assert context["text"] == "\n".join(lines[1:6])


def test_finds_method_with_multi_line_signature():
    lines = [
        "public class Demo {",
        "    public void run(",
        "            String name)",
        "            throws IOException {",
        "        call(name);",
        "    }",
        "}",
    ]

    context, error = find_method(lines, 5)

    assert error is None
    assert context["start_line"] == 2
    assert context["end_line"] == 6
    assert "throws IOException {" in context["text"]


def test_returns_error_when_method_is_not_found():
    lines = [
        "public class Demo {",
        "    private String name;",
        "}",
    ]

    context, error = find_method(lines, 2)

    assert context is None
    assert error["error_type"] == "method_not_found"
    assert error["target_line"] == 2


def test_output_is_deterministic():
    lines = [
        "public class Demo {",
        "    public void run() {",
        "        call();",
        "    }",
        "}",
    ]

    first, first_error = find_method(lines, 3)
    second, second_error = find_method(lines, 3)

    assert first_error is None
    assert second_error is None
    assert first == second