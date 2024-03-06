import math
import os
import sys

from ecElgamal import ReceiverEcElgamal, SenderEcElgamal
from helpers import *
from rabinSignature import RabinSignature


def Encryption(message, S, iv):
    w = WORD_SIZE

    message = bytesToBin(message)
    while len(message) % (4 * w) != 0:
        message = ''.join(['0', message])

    # Splits into Block for CBC
    message = [message[(block * 4 * w): ((block + 1) * 4 * w)] for block in range(int(len(message) / (4 * w)))]
    output = ''
    last = iv
    last = bytes(last, 'utf-8')
    last = bytesToBin(last).zfill(w * 4)

    for index, block in enumerate(message):
        last = XORstrings(last, block)
        last = encrypt_block(last, S, index)
        output = ''.join([output, last])

    output = binToBytes(output)
    return output


def encrypt_block(sentence, S, index):
    r = NUM_OF_ROUNDS
    w = WORD_SIZE
    modulo = 2 ** w
    lg_w = int(math.log(w, 2))

    A = int(''.join(['0b', sentence[0:w]]), 2)
    B = int(''.join(['0b', sentence[(w):(2 * w)]]), 2)
    C = int(''.join(['0b', sentence[(2 * w):(3 * w)]]), 2)
    D = int(''.join(['0b', sentence[(3 * w):(4 * w)]]), 2)
    org_txt_block = [A, B, C, D]

    B = (B + S[0]) % modulo
    D = (D + S[1]) % modulo
    for i in range(1, r + 1):
        func_b_out = (B * (2 * B + 1)) % modulo
        b_rol = ROL(func_b_out, lg_w, 32)
        func_d_out = (D * (2 * D + 1)) % modulo
        d_rol = ROL(func_d_out, lg_w, 32)
        b_rol_mod = b_rol % 32
        d_rol_mod = d_rol % 32
        A = (ROL(A ^ b_rol, d_rol_mod, 32) + S[2 * i]) % modulo
        C = (ROL(C ^ d_rol, b_rol_mod, 32) + S[2 * i + 1]) % modulo
        A, B, C, D = B, C, D, A
    A = (A + S[2 * r + 2]) % modulo
    C = (C + S[2 * r + 3]) % modulo
    cipher = [A, B, C, D]
    print(f"======================== CBC Block {index} ========================")
    print(f"Original String list: {org_txt_block}")
    print(f"Encrypted String list: {cipher}")
    print(f"=============================================================\n")

    output = ''
    output = ''.join([output, Expand(bin(A), w)[2:]])
    output = ''.join([output, Expand(bin(B), w)[2:]])
    output = ''.join([output, Expand(bin(C), w)[2:]])
    output = ''.join([output, Expand(bin(D), w)[2:]])
    return output


def main():
    print("^^^^^^ ENCRYPTION ^^^^^^")
    message = 'I love you Bob, are you?'
    # sentence = input("Enter Sentence (0-16 characters): ")
    if len(message) < 16:
        message = message + " " * (16 - len(message))
    print(f"Message to encrypt: {message}, Length: {len(message)}")

    key = "23"
    iv = "28"
    print(f"RC6 key: {key}, IV: {iv}\n")
    if len(key) < 16:
        key = key + " " * (16 - len(key))
    key = key[:16]

    # Starting Session ###
    print("Starting Session...")
    with open("status.txt", "w") as f:
        f.write("Start Session")

    print("Waiting for Ec Elgamal setup to be configured...")
    is_el_gamal_was_configured = False
    while not is_el_gamal_was_configured:
        try:
            if os.path.exists("initEcElgamal.txt"):
                with open("initEcElgamal.txt", "r") as f:
                    ec_elgamal_data = [f.readline().replace("\n", "") for _ in range(6)]
                    is_el_gamal_was_configured = len(ec_elgamal_data) == 6 and len(ec_elgamal_data[0]) > 0
        except FileNotFoundError:
            pass

    a, b, p, g, public_b, n = (int(ec_elgamal_data[0]),
                               int(ec_elgamal_data[1]),
                               int(ec_elgamal_data[2]),
                               tuple(map(int, ec_elgamal_data[3].split(','))),
                               tuple(map(int, ec_elgamal_data[4].split(','))),
                               int(ec_elgamal_data[5]))

    print("Ec Elgamal setup was configured!")
    print("Started Encryption...")
    sender_ec_elgamal = SenderEcElgamal(a, b, p, g, public_b, n)
    ec_elgamal_public, enc_key = sender_ec_elgamal.encrypt_key(int(key))
    _, enc_iv = sender_ec_elgamal.encrypt_key(int(iv))

    print("Sending Encrypted key")
    with open("encryptedKEY.txt", "w") as f:
        f.write("\n".join([f"{str(ec_elgamal_public.x)},{str(ec_elgamal_public.y)}",
                           f"{str(enc_key.x)},{str(enc_key.y)}",
                           f"{str(enc_iv.x)},{str(enc_iv.y)}"]))

    # Signature the message With RabinSignature
    signature_obj = RabinSignature(message)
    signature, U = signature_obj.sign_with_rabin()

    with open("signature.txt", "w") as f:
        f.write("\n".join([str(signature),
                           U.decode("utf-8"),
                           str(signature_obj.n)]))

    # Encryption With RC-6
    print("Encrypting With RC-6 in CBC mode:")
    message = message.encode('utf-8')
    S = generateKey(key)
    enc_sentence = Encryption(message, S, iv)
    print(f"Encrypted Message: {enc_sentence},\nLength: {len(enc_sentence)}")

    with open("encrypted.txt", "wb") as f:
        f.write(enc_sentence)

    # Notifying to decryption process to start
    with open("status.txt", "w") as f:
        f.write("Encryption Is Done")
    print("Encryption is Done")

    # Delete temp files for session
    temp_paths = ["initEcElgamal.txt"]
    for path in temp_paths:
        if os.path.exists(path):
            os.remove(path)


if __name__ == "__main__":
    main()
