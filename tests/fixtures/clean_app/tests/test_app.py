from app import new_reset_token


def test_reset_tokens_are_unique():
    assert new_reset_token() != new_reset_token()
