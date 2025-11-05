import random
import binascii
import hashlib
import ascon

BYTES = 479
lens = [BYTES * 8] * 50

messages = []


def sha2(data: bytes):
    hashed_data = hashlib.sha256(data).hexdigest()
    return hashed_data


def sha3(data: bytes):
    hashed_data = hashlib.sha3_512(data).hexdigest()
    return hashed_data


def do_ascon(data: bytes):
    hashed_data = ascon.ascon_hash(data)
    return hashed_data.hex()


def flip(bit_str):
    if bit_str == '0':
        return '1'
    elif bit_str == '1':
        return '0'
    else:
        raise ValueError(f'Flip failed - {bit_str} is neither a 0 nor a 1')


for bitlen in lens:
    original = random.getrandbits(bitlen)
    bin_str = bin(original)[2:]
    pos = random.randint(0, len(bin_str) - 1)
    flipped_bin_str = bin_str[:pos] + str(1 - int(bin_str[pos])) + bin_str[pos + 1:]
    flipped = int(flipped_bin_str, 2)
    messages.append(original)
    messages.append(flipped)

    # random_hex = hex(random.getrandbits(bitlen))[2:]  # remove the '0x' at the start
    # bin_str = bin(int(random_hex, 16))[2:]
    # pos = random.randint(0, len(bin_str) - 1)
    # flipped_bin_str = bin_str[:pos] + str(1 - int(bin_str[pos])) + bin_str[pos + 1:]
    # flipped_hex = hex(int(flipped_bin_str, 2))[2:]
    # # we remove last byte to avoid unknown "ValueError: non-hexadecimal number found"


with open('hash.csv', 'w') as fout:
    fout.write("Message,SHA2,SHA3,Ascon\n")
    for message in messages:
        message_hex = hex(message)[2:]
        message_bytes = message.to_bytes(BYTES)
        sha2_hash = sha2(message_bytes)
        sha3_hash = sha3(message_bytes)
        ascon_hash = do_ascon(message_bytes)
        fout.write(f"{message_hex},{sha2_hash},{sha3_hash},{ascon_hash}\n")
