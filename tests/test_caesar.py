import pytest

from ciphers.base import InvalidKeyError
from ciphers.part1_substitution import CaesarCipher


@pytest.mark.parametrize(
    "text, key, expected",
    [
        ("Hello", "3", "Khoor"),
        ("abc", "-1", "zab"),
        ("xyz", "3", "abc"),
        ("Привет", "1", "Рсйгёу"),
        ("её", "1", "ёж"),
        ("Hello", "0", "Hello"),
        ("123 !?", "3", "123 !?"),
        ("", "3", ""),
    ],
)
def test_encrypt(text, key, expected):
    cipher = CaesarCipher()

    assert cipher.encrypt(text, key) == expected


@pytest.mark.parametrize(
    "text, key, expected",
    [
        ("Khoor", "3", "Hello"),
        ("zab", "-1", "abc"),
        ("abc", "3", "xyz"),
        ("Рсйгёу", "1", "Привет"),
        ("ёж", "1", "её"),
        ("Hello", "0", "Hello"),
        ("123 !?", "3", "123 !?"),
        ("", "3", ""),
    ],
)
def test_decrypt(text, key, expected):
    cipher = CaesarCipher()

    assert cipher.decrypt(text, key) == expected


@pytest.mark.parametrize("key", ["3", "-5", "0", "100"])
def test_valid_key(key):
    cipher = CaesarCipher()

    assert cipher.validate_key(key) is True


@pytest.mark.parametrize("key", ["abc", "", "2.5", " ", "3a"])
def test_invalid_key(key):
    cipher = CaesarCipher()

    with pytest.raises(InvalidKeyError):
        cipher.validate_key(key)

    with pytest.raises(InvalidKeyError):
        cipher.encrypt("Hello", key)

    with pytest.raises(InvalidKeyError):
        cipher.decrypt("Khoor", key)