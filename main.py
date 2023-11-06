import os
import base64

import inquirer
from termcolor import colored
from inquirer.themes import load_theme_from_dict as loadth
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


def get_action() -> str:
    """ Пользователь выбирает действие через меню"""

    # Тема
    theme = {
        'Question': {
            'brackets_color': 'bright_yellow'
        },
        'List': {
            'selection_color': 'bright_blue'
        },
    }

    # Варианты для выбора
    question = [
        inquirer.List(
            "action",
            message=colored('Выберете ваше действие', 'light_yellow'),
            choices=[
                '   1) Зашифровать приватные ключи',
                '   2) Дешифровать приватные ключи',
            ]
        )
    ]
    return inquirer.prompt(question, theme=loadth(theme))['action']


def get_cipher_suite(password, salt=None) -> Fernet:
    """ Создаем шифратор и дешефратор """

    # используем salt с паролем, если нету создаем
    if salt is None:
        salt = os.urandom(16)
        with open('salt.dat', 'wb') as f:
            f.write(salt)
    else:
        with open('salt.dat', 'rb') as f:
            salt = f.read()

    # создаем криптографический ключ с помощью PBKDF2HMAC
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )

    # переводим ключ в URL-safe base64.
    key = base64.urlsafe_b64encode(kdf.derive(password))

    # на основе ключа создаем Fernet для шифрования и дешифрования данных.
    suite = Fernet(key)
    return suite


def encrypted(suite: Fernet) -> None:
    """ Шифрование данных """

    # считываем приватные ключи
    with open('private_keys.txt', 'r') as file:
        private_keys: list = [keys.strip() for keys in file.readlines()]

    if len(private_keys) == 0:
        print('Вы не добавили ключи для шифрования в private_keys.txt!')
        return

    # шифруем и записываем ключи в файл
    with open('encrypted.txt', 'a') as encrypted_file:
        for key in private_keys:
            encrypted_text = suite.encrypt(key.encode()).decode()
            encrypted_file.write(f'{encrypted_text}\n')


def decrypted(suite: Fernet) -> None:
    """ Дешифрование данных"""

    # считываем зашифрованные приватные ключи
    with open('encrypted.txt', 'r') as file:
        encrypted_keys: list = [keys.strip() for keys in file.readlines()]

    if len(encrypted_keys) == 0:
        print('Вы не добавили ключи для расшифрования в encrypted.txt!')
        return

    # дешифруем и записываем ключи в файл
    with open('decrypted.txt', 'a') as decrypted_file:
        for key in encrypted_keys:
            try:
                decrypted_text = suite.decrypt(key).decode()
                decrypted_file.write(f'{decrypted_text}\n')
            except InvalidToken:
                print('Вы не верно ввели пароль либо salt.dat')
                return


if __name__ == "__main__":

    user_password = input('Введите ваш пароль: ').encode()

    if os.path.exists('salt.dat'):
        cipher_suite = get_cipher_suite(user_password, salt=True)
    else:
        cipher_suite = get_cipher_suite(user_password)

    user_choice = get_action()

    if user_choice == '   1) Зашифровать приватные ключи':
        encrypted(cipher_suite)
        print('Приватные ключи успешно зашифрованы!')
    elif user_choice == '   2) Дешифровать приватные ключи':
        decrypted(cipher_suite)
        print('Приватные ключи успешно дешифрованы!')
    else:
        print('Некорректный выбор. Программа завершена.')
