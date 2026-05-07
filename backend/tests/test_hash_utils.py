from backend.app.forensic.hash_utils import sha256_json, sha256_text


def test_same_string_has_same_hash():
    assert sha256_text("agenttrace") == sha256_text("agenttrace")


def test_different_strings_have_different_hashes():
    assert sha256_text("alpha") != sha256_text("beta")


def test_sha256_json_ignores_dict_key_order():
    left = {"b": 2, "a": 1, "nested": {"z": 9, "y": 8}}
    right = {"nested": {"y": 8, "z": 9}, "a": 1, "b": 2}
    assert sha256_json(left) == sha256_json(right)
