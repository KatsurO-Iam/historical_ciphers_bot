"""Исторические шифры подстановки для Python 3.10 и новее."""

import re
import string

from .base import BaseCipher, InvalidKeyError

_RU_LOWER = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
_SUPPORTED_LOWERCASE = string.ascii_lowercase + _RU_LOWER


class _AlphabetCipher(BaseCipher):
    RU_LOWER = _RU_LOWER
    RU_UPPER = RU_LOWER.upper()

    def _find_letter(self, char: str) -> tuple[str, int] | None:
        for alphabet in (
                string.ascii_lowercase,
                string.ascii_uppercase,
                self.RU_LOWER,
                self.RU_UPPER,
        ):
            index = alphabet.find(char)
            if index != -1:
                return alphabet, index
        return None


class _KeylessCipher(BaseCipher):
    requires_key = False

    def validate_key(self, key: str = "") -> bool:
        """Принимает любой ключ, поскольку шифр его не использует."""
        return True


class CaesarCipher(_AlphabetCipher):
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
        self._parse_key(key)
        return True

    @staticmethod
    def _parse_key(key: str) -> int:
        if not key or not key.strip():
            raise InvalidKeyError(
                "Ключ шифра Цезаря не может быть пустым."
            )

        try:
            return int(key.strip())
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
        letter = self._find_letter(char)
        if letter is None:
            return char

        alphabet, index = letter
        return alphabet[(index + shift) % len(alphabet)]

    def _shift_text(self, text: str, shift: int) -> str:
        return "".join(self._shift_char(char, shift) for char in text)

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
        return self._shift_text(text, self._parse_key(key))

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
        return self._shift_text(text, -self._parse_key(key))


class AtbashCipher(_AlphabetCipher, _KeylessCipher):
    """Шифр Атбаш для английского и русского алфавитов.

    Заменяет каждую букву зеркальной буквой её алфавита,
    сохраняя регистр. Остальные символы остаются без изменений.

    Attributes:
        name (str): Название шифра.
        description (str): Описание принципа шифрования.
        requires_key (bool): Признак необходимости ключа.
        key_hint (str): Подсказка о ключе.
        RU_LOWER (str): Русский алфавит в нижнем регистре.
        RU_UPPER (str): Русский алфавит в верхнем регистре.
    """

    name = "Шифр Атбаш"
    description = "Замена букв зеркальными буквами их алфавита."
    key_hint = "Ключ не требуется."

    def encrypt(self, text: str, key: str = "") -> str:
        """Шифрует текст зеркальной заменой букв.

        Args:
            text (str): Исходный текст.
            key (str): Неиспользуемый ключ. По умолчанию пустая строка.

        Returns:
            str: Зашифрованный текст с сохранением регистра.
        """
        result = []
        for char in text:
            letter = self._find_letter(char)
            if letter is None:
                result.append(char)
            else:
                alphabet, index = letter
                result.append(alphabet[-1 - index])
        return "".join(result)

    def decrypt(self, text: str, key: str = "") -> str:
        """Расшифровывает текст повторной зеркальной заменой букв.

        Args:
            text (str): Зашифрованный текст.
            key (str): Неиспользуемый ключ. По умолчанию пустая строка.

        Returns:
            str: Расшифрованный текст.
        """
        return self.encrypt(text, key)


class PolybiusCipher(_KeylessCipher):
    """Кодирует символы координатами английского и русского квадратов.

    Регистр букв из матриц не сохраняется, английская J объединяется с I.
    Координаты имеют вид Erc или Rrc, где E и R обозначают английскую
    и русскую матрицы, а r и c — строку и столбец с единицы.
    Символы вне матриц сохраняются в квадратных скобках.
    В русской матрице отсутствуют Ё/ё и Й/й, поэтому они сохраняют
    исходный регистр при шифровании и последующем дешифровании.
    Токены разделяются пробельными символами. Пробелы и переводы строк
    внутри экранированного токена считаются его содержимым.

    Пример: "A Ёй" шифруется как "E11 R62 [Ё] [й]".

    Attributes:
        name (str): Название шифра.
        description (str): Описание принципа шифрования.
        requires_key (bool): Необходимость ключа.
        key_hint (str): Подсказка о ключе.
        GRID_EN (tuple[str, ...]): Английская матрица 5×5.
        GRID_RU (tuple[str, ...]): Русская матрица 6×6.
    """

    name = "Квадрат Полибия"
    description = "Координатное шифрование"
    key_hint = "Ключ не требуется (используется классическая матрица)."

    GRID_EN = (
        "ABCDE",
        "FGHIK",
        "LMNOP",
        "QRSTU",
        "VWXYZ",
    )

    GRID_RU = (
        "АБВГДЕ",
        "ЖЗИКЛМ",
        "НОПРСТ",
        "УФХЦЧШ",
        "ЩЪЫЬЭЮ",
        "Я ,.!?",
    )

    def _find_coords(self, char: str) -> str | None:
        """Находит координаты символа после приведения к верхнему регистру.

        Английская J обрабатывается как I.

        Args:
            char (str): Символ для поиска в матрицах.

        Returns:
            str | None: Код с префиксом E или R и номерами строки
                и столбца, начиная с единицы. Если символ отсутствует
                в матрицах, возвращается None.
        """
        c = char.upper() if char in _SUPPORTED_LOWERCASE else char
        if c == "J":
            c = "I"

        for prefix, grid in (("E", self.GRID_EN), ("R", self.GRID_RU)):
            for row_index, row in enumerate(grid, start=1):
                for col_index, symbol in enumerate(row, start=1):
                    if c == symbol:
                        return f"{prefix}{row_index}{col_index}"

        return None

    def encrypt(self, text: str, key: str = "") -> str:
        """Преобразует текст в коды, разделённые пробелами.

        Args:
            text (str): Исходный текст.
            key (str): Неиспользуемый ключ.

        Returns:
            str: Координаты символов и неподдерживаемые символы
                в квадратных скобках.
        """
        result = []

        for char in text:
            coords = self._find_coords(char)
            result.append(coords if coords is not None else f"[{char}]")

        return " ".join(result)

    def decrypt(self, text: str, key: str = "") -> str:
        """Восстанавливает текст из координат.

        Args:
            text (str): Коды символов, разделённые пробельными символами.
            key (str): Неиспользуемый ключ.

        Returns:
            str: Расшифрованный текст. Буквы из матриц возвращаются
                в верхнем регистре, неизвестные токены сохраняются.
        """
        grids = {"E": self.GRID_EN, "R": self.GRID_RU}
        result = []

        for token in re.findall(r"(?:\[[\s\S]\]|\S)+", text):
            if (
                    token.startswith("[")
                    and token.endswith("]")
                    and len(token) == 3
            ):
                result.append(token[1:-1])
                continue

            if (
                    len(token) == 3
                    and token[0] in grids
                    and token[1] in "123456"
                    and token[2] in "123456"
            ):
                grid = grids[token[0]]
                row = int(token[1]) - 1
                col = int(token[2]) - 1

                if row < len(grid) and col < len(grid[row]):
                    result.append(grid[row][col])
                    continue

            result.append(token)

        return "".join(result)
