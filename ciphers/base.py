import abc


class CipherError(Exception):
    """Базовое исключение для ошибок шифрования и неверных ключей."""
    pass


class InvalidKeyError(CipherError):
    """Исключение, выбрасываемое при невалидном ключе для шифра."""
    pass


class InvalidModeError(CipherError):
    """Исключение при неверном режиме обработки файла."""
    pass


class BaseCipher(abc.ABC):
    """Абстрактный базовый класс для исторических шифров.

    Определяет единый интерфейс шифрования, дешифрования,
    проверки ключей и обработки текстовых файлов.

    Attributes:
        name (str): Название шифра.
        description (str): Описание принципа работы шифра.
        requires_key (bool): Необходимость использования ключа.
        key_hint (str): Подсказка по формату ключа.
    """
    name: str = "BaseCipher"
    description: str = ""
    requires_key: bool = True
    key_hint: str = ""

    @abc.abstractmethod
    def validate_key(self, key: str) -> bool:
        """Проверяет корректность ключа шифрования.

        Args:
            key (str): Ключ шифрования.

        Returns:
            bool: True, если ключ корректен.

        Raises:
            InvalidKeyError: Если ключ не соответствует требованиям шифра.
        """
        pass

    @abc.abstractmethod
    def encrypt(self, text: str, key: str) -> str:
        """Шифрует исходный текст.

        Args:
            text (str): Исходный текст.
            key (str): Ключ шифрования.

        Returns:
            str: Зашифрованный текст.

        Raises:
            InvalidKeyError: Если передан некорректный ключ.
        """
        pass

    @abc.abstractmethod
    def decrypt(self, text: str, key: str) -> str:
        """Расшифровывает зашифрованный текст.

        Args:
            text (str): Зашифрованный текст.
            key (str): Ключ дешифрования.

        Returns:
            str: Расшифрованный текст.

        Raises:
            InvalidKeyError: Если передан некорректный ключ.
        """
        pass

    def process_file_bytes(
            self, data: bytes, key: str = "", mode: str = "encrypt"
    ) -> bytes:
        """Шифрует или дешифрует содержимое текстового файла.

        Args:
            data (bytes): Содержимое файла в кодировке UTF-8.
            key (str): Ключ шифрования или дешифрования. Можно опустить
                для шифров, которые не используют ключ.
            mode (str): Режим encrypt или decrypt.
                По умолчанию используется encrypt.

        Returns:
            bytes: Обработанное содержимое файла в кодировке UTF-8.

        Raises:
            InvalidModeError: Если передан неподдерживаемый режим.
            CipherError: Если содержимое файла не является текстом UTF-8.
            InvalidKeyError: Если передан некорректный ключ.
        """
        if mode not in ("encrypt", "decrypt"):
            raise InvalidModeError(
                "Режим обработки должен быть 'encrypt' или 'decrypt'."
            )

        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise CipherError(
                "Исторические шифры поддерживают текстовые файлы "
                "в кодировке UTF-8."
            ) from exc

        if mode == "encrypt":
            result = self.encrypt(text, key)
        else:
            result = self.decrypt(text, key)

        return result.encode("utf-8")