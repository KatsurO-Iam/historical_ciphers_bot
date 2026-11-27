import pytest

from ciphers.part1_substitution import PolybiusCipher


@pytest.mark.parametrize(
    "text, expected",
    [
        ("ABC", "E11 E12 E13"),
        ("Hello", "E23 E15 E31 E31 E34"),
        ("АБВ", "R11 R12 R13"),
        ("IJij", "E24 E24 E24 E24"),
        ("A Я", "E11 R62 R61"),
        (",.!?", "R63 R64 R65 R66"),
        ("123@", "[1] [2] [3] [@]"),
        ("Ёё", "[Ё] [ё]"),
        ("", ""),
    ],
)
def test_encrypt(text, expected):
    cipher = PolybiusCipher()

    assert cipher.encrypt(text) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        ("E11 E12 E13", "ABC"),
        ("E23 E15 E31 E31 E34", "HELLO"),
        ("R11 R12 R13", "АБВ"),
        ("E24 E24 E24 E24", "IIII"),
        ("E11 R62 R61", "A Я"),
        ("R63 R64 R65 R66", ",.!?"),
        ("[1] [2] [3] [@]", "123@"),
        ("[Ё] [ё]", "Ёё"),
        ("", ""),
    ],
)
def test_decrypt(text, expected):
    cipher = PolybiusCipher()

    assert cipher.decrypt(text) == expected


@pytest.mark.parametrize(
    "token",
    [
        "E66",
        "R77",
        "E00",
        "X11",
        "E1",
        "EAA",
        "E²1",
        "[abc]",
        "[]",
    ],
)
def test_invalid_tokens(token):
    cipher = PolybiusCipher()

    assert cipher.decrypt(token) == token


@pytest.mark.parametrize("key", ["", "любой ключ", "123", "!?"])
def test_key(key):
    cipher = PolybiusCipher()

    assert cipher.validate_key(key) is True
    assert cipher.encrypt("ABC", key) == "E11 E12 E13"
    assert cipher.decrypt("E11 E12 E13", key) == "ABC"


@pytest.mark.parametrize(
    "text, expected",
    [
        ("Hello", "HELLO"),
        ("Java", "IAVA"),
        ("Привет, мир!", "ПРИВЕТ, МИР!"),
        ("A\nB", "A\nB"),
        ("A\tB", "A\tB"),
        ("A\r\nB", "A\r\nB"),
        ("[]", "[]"),
        ("", ""),
    ],
)
def test_round_trip(text, expected):
    cipher = PolybiusCipher()

    encrypted = cipher.encrypt(text)

    assert cipher.decrypt(encrypted) == expected


def test_file_round_trip():
    cipher = PolybiusCipher()
    original = "ABC\nАБВ\t123".encode("utf-8")

    encrypted = cipher.process_file_bytes(original, "")
    decrypted = cipher.process_file_bytes(
        encrypted, "", mode="decrypt"
    )

    assert decrypted == original
