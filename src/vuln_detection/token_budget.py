NUM_CTX = 8192
NUM_PREDICT = 512
MAX_INPUT_TOKENS = NUM_CTX - NUM_PREDICT


def count_request_tokens(tokenizer, system_prompt, user_prompt):
    messages = [
        {
            "role": "system",
            "content": system_prompt,
        },
        {
            "role": "user",
            "content": user_prompt,
        },
    ]

    tokens = tokenizer.apply_chat_template(
        messages,
        add_generation_prompt=True,
        tokenize=True,
    )

    return len(tokens)


def ensure_within_input_budget(token_count, max_input_tokens):
    if token_count > max_input_tokens:
        raise ValueError(
            "context_window_exceeded: "
            + str(token_count)
            + " input tokens exceed "
            + str(max_input_tokens)
        )