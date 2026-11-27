import pytest

from ciphers.base import (
    BaseCipher,
    CipherError,
    InvalidKeyError,
    InvalidModeError,
)
from ciphers.part1_substitution import (
    AtbashCipher,
    CaesarCipher,
    PolybiusCipher,
)


class DummyCipher(BaseCipher):
    def validate_key(self, key: str) -> bool:
        if key != "1":
            raise InvalidKeyError('Ключ должен быть строкой "1"')
        return True

    def encrypt(self, text: str, key: str) -> str:
        self.validate_key(key)
        return text[::-1]

    def decrypt(self, text: str, key: str) -> str:
        self.validate_key(key)
        return text[::-1]


def test_file_encrypt():
    cipher = DummyCipher()
    result = cipher.process_file_bytes(b"Hello", "1")
    assert result == b"olleH"


def test_invalid_key():
    cipher = DummyCipher()

    with pytest.raises(InvalidKeyError):
        cipher.process_file_bytes(b"Hello", "2")


def test_file_decrypt():
    cipher = DummyCipher()

    result = cipher.process_file_bytes(b"olleH", "1", mode="decrypt")

    assert result == b"Hello"


def test_empty_file():
    cipher = DummyCipher()

    assert cipher.process_file_bytes(b"", "1", mode="encrypt") == b""
    assert cipher.process_file_bytes(b"", "1", mode="decrypt") == b""


def test_unicode_file():
    cipher = DummyCipher()
    original = "Привет, мир!".encode("utf-8")
    reversed_text = "!рим ,тевирП".encode("utf-8")

    assert cipher.process_file_bytes(original, "1") == reversed_text
    assert (
            cipher.process_file_bytes(reversed_text, "1", mode="decrypt")
            == original
    )


def test_invalid_encoding():
    cipher = DummyCipher()

    with pytest.raises(CipherError):
        cipher.process_file_bytes(b"\xff", "1")


def test_abstract_class():
    with pytest.raises(TypeError):
        BaseCipher()


@pytest.mark.parametrize(
    "mode", ["", "abc", "ENCRYPT", "encrpyt", "decrypt "]
)
def test_invalid_mode(mode):
    cipher = DummyCipher()

    with pytest.raises(InvalidModeError):
        cipher.process_file_bytes(b"Hello", "1", mode=mode)


def test_invalid_mode_priority():
    cipher = DummyCipher()

    with pytest.raises(InvalidModeError):
        cipher.process_file_bytes(b"\xff", "1", mode="invalid")


def test_encoding_error_cause():
    cipher = DummyCipher()

    with pytest.raises(CipherError) as exc_info:
        cipher.process_file_bytes(b"\xff", "1", mode="encrypt")

    assert isinstance(exc_info.value.__cause__, UnicodeDecodeError)


@pytest.mark.parametrize("cipher_class", [AtbashCipher, PolybiusCipher])
def test_keyless_file_round_trip(cipher_class):
    cipher = cipher_class()
    original = "ABC ЯЁ\r\n🙂".encode("utf-8")

    encrypted = cipher.process_file_bytes(original)

    assert cipher.process_file_bytes(encrypted, mode="decrypt") == original


def test_caesar_file_requires_key():
    with pytest.raises(InvalidKeyError):
        CaesarCipher().process_file_bytes(b"ABC")