import telebot
import re
from dotenv import load_dotenv
import os

load_dotenv()

# Створюємо бот з токеном
API_TOKEN = os.getenv('API_TOKEN')
bot = telebot.TeleBot(API_TOKEN)

hash_types = {
    'md5': {'length': 32, 'regex': r'^[a-f0-9]{32}$'},
    'sha1': {'length': 40, 'regex': r'^[a-f0-9]{40}$'},
    'sha224': {'length': 56, 'regex': r'^[a-f0-9]{56}$'},
    'sha256': {'length': 64, 'regex': r'^[a-f0-9]{64}$'},
    'sha384': {'length': 96, 'regex': r'^[a-f0-9]{96}$'},
    'sha512': {'length': 128, 'regex': r'^[a-f0-9]{128}$'},
    'ripemd160': {'length': 40, 'regex': r'^[a-f0-9]{40}$'},
    'whirlpool': {'length': 128, 'regex': r'^[a-f0-9]{128}$'},
    'blake2b': {'length': 128, 'regex': r'^[a-f0-9]{128}$'},
    'blake2s': {'length': 64, 'regex': r'^[a-f0-9]{64}$'},
    'tiger192': {'length': 48, 'regex': r'^[a-f0-9]{48}$'},
    'gost': {'length': 64, 'regex': r'^[a-f0-9]{64}$'},
    'sha3_224': {'length': 56, 'regex': r'^[a-f0-9]{56}$'},
    'sha3_256': {'length': 64, 'regex': r'^[a-f0-9]{64}$'},
    'sha3_384': {'length': 96, 'regex': r'^[a-f0-9]{96}$'},
    'sha3_512': {'length': 128, 'regex': r'^[a-f0-9]{128}$'},
    'shake_128': {'length': 64, 'regex': r'^[a-f0-9]{64}$'},
    'shake_256': {'length': 128, 'regex': r'^[a-f0-9]{128}$'},
    'keccak_224': {'length': 56, 'regex': r'^[a-f0-9]{56}$'},
    'keccak_256': {'length': 64, 'regex': r'^[a-f0-9]{64}$'},
    'keccak_384': {'length': 96, 'regex': r'^[a-f0-9]{96}$'},
    'keccak_512': {'length': 128, 'regex': r'^[a-f0-9]{128}$'},
    'bcrypt': {'length': 60, 'regex': r'^\$2[aby]?\$[0-9]{2}\$[./A-Za-z0-9]{53}$'},
    'argon2': {'length': 96, 'regex': r'^\$argon2(i|d|id)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$'},
    'ntlm': {'length': 32, 'regex': r'^[a-f0-9]{32}$'},
    'lm': {'length': 32, 'regex': r'^[a-f0-9]{32}$'},
    'crc32': {'length': 8, 'regex': r'^[a-f0-9]{8}$'},
    'adler32': {'length': 8, 'regex': r'^[a-f0-9]{8}$'},
    'ed2k': {'length': 32, 'regex': r'^[a-f0-9]{32}$'},
    'md4': {'length': 32, 'regex': r'^[a-f0-9]{32}$'}
}


# Функція для визначення можливих типів хешів
def identify_hash(hash_value):
    hash_value = hash_value.lower()
    possible_hashes = []
    for hash_name, props in hash_types.items():
        if re.match(props['regex'], hash_value):
            possible_hashes.append(hash_name.upper())
    return possible_hashes


@bot.message_handler(func=lambda message: True)
def handle_message(message):
    hash_value = message.text.strip()
    possible_hashes = identify_hash(hash_value)

    if possible_hashes:
        response = "Variants of hash functions are possible:\n" + "\n".join(possible_hashes)
    else:
        response = "Unable to determine the type of hash. It may be an unsupported or incorrect hash function."

    bot.reply_to(message, response)


bot.polling()

