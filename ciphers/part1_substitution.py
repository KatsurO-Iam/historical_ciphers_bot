
import string

from .base import BaseCipher, InvalidKeyError


class CaesarCipher(BaseCipher):
    """Реализует шифр Цезаря для русского и английского алфавитов.

    Шифрование выполняется циклическим сдвигом букв алфавита
    на заданное число позиций с сохранением регистра.
    Символы вне поддерживаемых алфавитов не изменяются.

    Attributes:
        name (str): Название шифра.
        description (str): Описание принципа работы шифра.
        requires_key (bool): Необходимость использования ключа.
        key_hint (str): Подсказка по формату ключа.
        RU_LOWER (str): Русский алфавит в нижнем регистре.
        RU_UPPER (str): Русский алфавит в верхнем регистре.
    """

    name = "Шифр Цезаря"
    description = "Моноалфавитный шифр со сдвигом на заданное число позиций."
    requires_key = True
    key_hint = "Целое число (например, 3 или -5)."

    RU_LOWER = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
    RU_UPPER = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"

    def validate_key(self, key: str) -> bool:
        """Проверяет корректность ключа шифра Цезаря.

        Args:
            key (str): Строковое представление целочисленного сдвига.

        Returns:
            bool: True, если ключ является корректным.

        Raises:
            InvalidKeyError: Если ключ пустой или не является
                строковым представлением целого числа.
        """
        if not key or not key.strip():
            raise InvalidKeyError(
                "Ключ шифра Цезаря не может быть пустым."
            )

        try:
            int(key.strip())
            return True
        except ValueError as exc:
            raise InvalidKeyError(
                "Ключ шифра Цезаря должен быть целым числом "
                "(например, 3, 7, -2)."
            ) from exc

    def _shift_char(self, char: str, shift: int) -> str:
        """Выполняет циклический сдвиг символа в его алфавите.

        Args:
            char (str): Символ исходного текста.
            shift (int): Количество позиций сдвига.

        Returns:
            str: Символ после сдвига с сохранением регистра.
                Если символ не принадлежит поддерживаемым
                алфавитам, возвращается исходный символ.
        """
        alphabets = (
            string.ascii_lowercase,
            string.ascii_uppercase,
            self.RU_LOWER,
            self.RU_UPPER,
        )

        for alphabet in alphabets:
            if char in alphabet:
                index = (alphabet.index(char) + shift) % len(alphabet)
                return alphabet[index]

        return char

    def encrypt(self, text: str, key: str) -> str:
        """Шифрует текст методом Цезаря.

        Args:
            text (str): Исходный текст.
            key (str): Строковое представление целочисленного сдвига.

        Returns:
            str: Зашифрованный текст.

        Raises:
            InvalidKeyError: Если передан некорректный ключ.
        """
        self.validate_key(key)
        shift = int(key.strip())
        return "".join(self._shift_char(ch, shift) for ch in text)

    def decrypt(self, text: str, key: str) -> str:
        """Расшифровывает текст методом обратного сдвига.

        Args:
            text (str): Зашифрованный текст.
            key (str): Ключ, использованный при шифровании.

        Returns:
            str: Расшифрованный текст.

        Raises:
            InvalidKeyError: Если передан некорректный ключ.
        """
        self.validate_key(key)
        shift = int(key.strip())
        return "".join(self._shift_char(ch, -shift) for ch in text)
