import re
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


class AtbashCipher(BaseCipher):
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
    requires_key = False
    key_hint = "Ключ не требуется."

    RU_LOWER = "абвгдеёжзийклмнопрстуфхцчшщъыьэюя"
    RU_UPPER = "АБВГДЕЁЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"

    def validate_key(self, key: str = "") -> bool:
        """Принимает любой ключ, поскольку шифр его не использует.

        Args:
            key (str): Неиспользуемый ключ. По умолчанию пустая строка.

        Returns:
            bool: Всегда True.
        """
        return True

    def encrypt(self, text: str, key: str = "") -> str:
        """Шифрует текст зеркальной заменой букв.

        Args:
            text (str): Исходный текст.
            key (str): Неиспользуемый ключ. По умолчанию пустая строка.

        Returns:
            str: Зашифрованный текст с сохранением регистра.
        """
        self.validate_key(key)

        alphabets = (
            string.ascii_lowercase,
            string.ascii_uppercase,
            self.RU_LOWER,
            self.RU_UPPER,
        )
        result = []

        for char in text:
            for alphabet in alphabets:
                if char in alphabet:
                    index = alphabet.index(char)
                    new_index = len(alphabet) - 1 - index
                    result.append(alphabet[new_index])
                    break
            else:
                result.append(char)

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


class PolybiusCipher(BaseCipher):
    """Кодирует символы координатами английского и русского квадратов.

    Регистр букв не сохраняется, английская J объединяется с I.
    Неподдерживаемые символы заключаются в квадратные скобки.

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
    requires_key = False
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

    def validate_key(self, key: str = "") -> bool:
        """Принимает любой ключ, поскольку он не используется.

        Args:
            key (str): Неиспользуемый ключ.

        Returns:
            bool: Всегда True.
        """
        return True

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
        c = char.upper()
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
        self.validate_key(key)
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
        self.validate_key(key)
        grids = {"E": self.GRID_EN, "R": self.GRID_RU}
        result = []

        for token in re.findall(r"\[[\s\S]\]|\S+", text):
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
