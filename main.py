import json
import pickle

from tqdm import tqdm
import os
import argparse
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_public_key, load_pem_private_key
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding as pat


def keys_generate(symmetric_key_path: str, public_key_path: str, private_key_path: str) -> None:
    '''Генерация ключей, длину ключа выбирает пользователь
       Функция принемает:
       symmetric_key_path - путь к симметричному ключу,
       public_key_path - путь к публичному ключу и
       private_key_path - путь к приватному ключу'''
    # Ввод длины ключа пользоваьелем
    print("Выберите длину ключа: ")
    n = 1
    i = {1: 0}
    for j in range(40, 129, 8):
        i[n] = j
        print(f'{n}. {j}')
        n += 1
    n = int(input(f'Ваш выбор: '))
    length_key = i[n]
    len_key_in_bytes = int(length_key / 8)
    # Генерация симметричного ключа
    symmetric_key = algorithms.CAST5(os.urandom(len_key_in_bytes)).key
    # Генерация ассиметричного ключа
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key = key
    public_key = key.public_key()
    # Сериализация приватного и публичного ключей
    with open(public_key_path, "wb") as pb_file:
        pb_file.write(public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                              format=serialization.PublicFormat.SubjectPublicKeyInfo))
    with open(private_key_path, "wb") as pr_file:
        pr_file.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                                format=serialization.PrivateFormat.TraditionalOpenSSL,
                                                encryption_algorithm=serialization.NoEncryption()))
    # Шифрование симметричного ключа с помощью RSA
    symmetric_key_encrypt = public_key.encrypt(symmetric_key,
                                               pat.OAEP(mgf=pat.MGF1(algorithm=hashes.SHA256()),
                                                        algorithm=hashes.SHA256(),
                                                        label=None))
    # Сериализация закодированного симметричного ключа
    with open(symmetric_key_path, "wb") as symm_file:
        symm_file.write(symmetric_key_encrypt)


def decrypt_symmetric_key(path_to_symmetric_key: str, path_to_private_key: str) -> bytes:
    '''Расшивровка симметричного ключа
       Функция принемает:
       path_to_symmetric_key - путь до зашифрованного симметричного ключаи
       path_to_private_key - путь до приватного RSA ключа
       Возвращает функция расшифрованный ключ симметричного шифрования'''
    with open(path_to_symmetric_key, "rb") as symmet_file:
        symmetric_enc_key = symmet_file.read()
    with open(path_to_private_key, "rb") as pr_file:
        private_key = load_pem_private_key(pr_file.read(), password=None)
    symmetric_dc_key = private_key.decrypt(symmetric_enc_key,
                                           pat.OAEP(mgf=pat.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(),
                                                    label=None))
    return symmetric_dc_key


def encryptor(file_to_encrypt: str, path_private_key: str, patch_to_symmetric_key: str,
              path_to_file_encrypt: str) -> None:
    '''Шифрует файл и сохраняет его по указанному пути
    Функция принемает:
    file_to_encrypt - путь до шифруемого файла,
    path_private_key - путь до приватного RSA ключа,
    patch_to_symmetric_key - путь до зашифрованного симметричного ключа,
    path_to_file_encrypt - путь к зашифрованному файлу'''
    from cryptography.hazmat.primitives import padding
    # Расшивровка симметричного ключа
    symmettric_key = decrypt_symmetric_key(patch_to_symmetric_key, path_private_key)
    with open(file_to_encrypt, "r", encoding="UTF-8") as enc_file:
        text = enc_file.read()
    # Паддинг исходного файла
    padder = padding.ANSIX923(128).padder()
    text = bytes(text, 'UTF-8')
    padded_text = padder.update(text) + padder.finalize()
    # Шифрование исходного файла
    iv = os.urandom(8)
    cipher = Cipher(algorithms.CAST5(symmettric_key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    enc_text = encryptor.update(padded_text) + encryptor.finalize()
    data = {'enc_text': enc_text, 'iv': iv}
    with open(path_to_file_encrypt, "wb") as file:
        pickle.dump(data, file)


def decryptor(path_to_encryptor_file: str, path_to_private_key: str, path_to_enc_symmetric_key: str,
              path_to_decr_file: str) -> None:
    '''Дешефрует принимаемый файл
    Функция принемает:
    path_to_encryptor_file - путь к дешифруемому файлу,
    path_private_key - путь до приватного RSA ключа,
    patch_to_symmetric_key - путь до зашифрованного симметричного ключа,
    path_to_decr_file - путь к расшифроваанному файлу'''
    # Расшивровка симметричного ключа
    symmettric_key = decrypt_symmetric_key(path_to_enc_symmetric_key, path_to_private_key)
    with open(path_to_encryptor_file, "rb") as enc_file:
        data = pickle.load(enc_file)
    iv = data['iv']
    dec_text = data['enc_text']
    cipher = Cipher(algorithms.CAST5(symmettric_key), modes.CBC(iv))
    decrypt = cipher.decryptor()
    dc_text = decrypt.update(dec_text) + decrypt.finalize()
    unpadder = padding.ANSIX923(128).unpadder()
    unpadded_dec_text = unpadder.update(dc_text) + unpadder.finalize()
    with open(path_to_decr_file, "w", encoding="UTF-8") as dec_file:
        dec_file.write(unpadded_dec_text.decode("UTF-8"))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='main.py')
    parser.add_argument('-set', type=str, help='Путь до файла с настройками', required=True, dest='settings_path')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-gen', help='Генерация ключей', default=None, dest='generate_keys')
    group.add_argument('-enc', help='Шифрование текста в файле', default=None, dest='encryptor')
    group.add_argument('-dec', help='Дешифрование текста в файле', default=None, dest='decryptor')
    args = parser.parse_args()
    data_from = os.path.realpath(args.settings_path)
    print(data_from)
    try:
        with open(data_from) as df:
            data = json.load(df)
    except:
        os.error("Settings path errors")
    if args.generate_keys is not None:
        with tqdm(total=100, desc="Generating keys: ") as progressbar:
            keys_generate(data['symmetric_key'], data['public_key'], data['private_key'])
            progressbar.update(100)
    if args.encryptor is not None:
        with tqdm(total=100, desc="Encrypting your file: ") as progressbar:
            encryptor(data['initial_file'], data['private_key'], data['symmetric_key'], data['encrypted_file'])
            progressbar.update(100)
    if args.decryptor is not None:
        with tqdm(total=100, desc='Decrypting your file: ') as progressbar:
            decryptor(data['encrypted_file'], data['private_key'], data['symmetric_key'], data['decrypted_file'])
            progressbar.update(100)
