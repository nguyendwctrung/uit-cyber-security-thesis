import pytest

from vuln_detection.token_budget import (
    count_request_tokens,
    ensure_within_input_budget,
)


class FakeTokenizer:
    def __init__(self, token_count):
        self.token_count = token_count
        self.messages = None
        self.add_generation_prompt = None
        self.tokenize = None

    def apply_chat_template(
        self,
        messages,
        add_generation_prompt,
        tokenize,
    ):
        self.messages = messages
        self.add_generation_prompt = add_generation_prompt
        self.tokenize = tokenize
        return list(range(self.token_count))


def test_counts_the_final_chat_request_with_generation_prompt():
    tokenizer = FakeTokenizer(123)

    token_count = count_request_tokens(
        tokenizer,
        "System instruction.",
        "Candidate context.",
    )

    assert token_count == 123
    assert tokenizer.messages == [
        {
            "role": "system",
            "content": "System instruction.",
        },
        {
            "role": "user",
            "content": "Candidate context.",
        },
    ]
    assert tokenizer.add_generation_prompt is True
    assert tokenizer.tokenize is True


def test_accepts_the_exact_input_token_limit():
    ensure_within_input_budget(7680, 7680)


def test_rejects_input_over_the_token_limit():
    with pytest.raises(
        ValueError,
        match="context_window_exceeded",
    ):
        ensure_within_input_budget(7681, 7680)