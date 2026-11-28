import pytest

from ciphers.part1_substitution import AtbashCipher


@pytest.mark.parametrize(
    "text, expected",
    [
        ("ABC", "ZYX"),
        ("Hello", "Svool"),
        ("АБВ", "ЯЮЭ"),
        ("Привет", "Поцэъм"),
        ("Ёж", "Щш"),
        ("Hello, мир!", "Svool, тцо!"),
        ("123 !?", "123 !?"),
        ("", ""),
    ],
)
def test_encrypt(text, expected):
    cipher = AtbashCipher()

    assert cipher.encrypt(text) == expected


@pytest.mark.parametrize(
    "text, expected",
    [
        ("ZYX", "ABC"),
        ("Svool", "Hello"),
        ("ЯЮЭ", "АБВ"),
        ("Поцэъм", "Привет"),
        ("Щш", "Ёж"),
        ("Svool, тцо!", "Hello, мир!"),
        ("123 !?", "123 !?"),
        ("", ""),
    ],
)
def test_decrypt(text, expected):
    cipher = AtbashCipher()

    assert cipher.decrypt(text) == expected


@pytest.mark.parametrize("key", ["", "любой ключ", "123", "!?"])
def test_key(key):
    cipher = AtbashCipher()

    assert cipher.validate_key(key) is True
    assert cipher.encrypt("Hello", key) == "Svool"
    assert cipher.decrypt("Svool", key) == "Hello"


@pytest.mark.parametrize(
    "text",
    [
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
        "abcdefghijklmnopqrstuvwxyz",
        "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ",
        "абвгдеёжзийклмнопрстуфхцчшщъыьэюя",
        "Hello, мир! Ёж — 123.",
        "123 !?",
        "",
    ],
)
def test_symmetry(text):
    cipher = AtbashCipher()

    encrypted = cipher.encrypt(text)

    assert cipher.decrypt(encrypted) == text
    assert cipher.encrypt(encrypted) == text
