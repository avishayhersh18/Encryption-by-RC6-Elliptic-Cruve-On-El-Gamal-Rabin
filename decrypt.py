import math
import os

from ecElgamal import ReceiverEcElgamal
from helpers import *
import sys

from rabinSignature import verify_rabin


def Decryption(message, S, iv):
    w = WORD_SIZE

    message = bytesToBin(message)
    while len(message) % (4 * w) != 0:
        message = ''.join(['0', message])

    # Splits into Block for CBC
    message = [message[(block * 4 * w): ((block + 1) * 4 * w)] for block in range(int(len(message) / (4 * w)))]
    output = ''
    last = iv.encode('utf-8')
    last = bytesToBin(last).zfill(w * 4)

    for index, block in enumerate(message):
        buf = block
        block = decrypt_block(block, S, index)
        block = XORstrings(block, last)
        output = ''.join([output, block])
        last = buf

    output = binToBytes(output)
    output = output.lstrip(b'\x00')
    return output


def decrypt_block(enc_sentence, S, index):
    r = NUM_OF_ROUNDS
    w = WORD_SIZE
    modulo = 2 ** w
    lg_w = int(math.log(w, 2))

    A = int(''.join(['0b', enc_sentence[0:w]]), 2)
    B = int(''.join(['0b', enc_sentence[(w):(2 * w)]]), 2)
    C = int(''.join(['0b', enc_sentence[(2 * w):(3 * w)]]), 2)
    D = int(''.join(['0b', enc_sentence[(3 * w):(4 * w)]]), 2)
    cipher = [A, B, C, D]

    C = (C - S[2 * r + 3]) % modulo
    A = (A - S[2 * r + 2]) % modulo
    for j in range(1, r + 1):
        i = r + 1 - j
        A, B, C, D = D, A, B, C
        func_d_out = (D * (2 * D + 1)) % modulo
        d_rol = ROL(func_d_out, lg_w, w)
        func_b_out = (B * (2 * B + 1)) % modulo
        b_rol = ROL(func_b_out, lg_w, w)
        b_rol_mod = b_rol % w
        d_rol_mod = d_rol % w
        C = (ROR((C - S[2 * i + 1]) % modulo, b_rol_mod, w) ^ d_rol)
        A = (ROR((A - S[2 * i]) % modulo, d_rol_mod, w) ^ b_rol)
    D = (D - S[1]) % modulo
    B = (B - S[0]) % modulo
    org_txt_block = [A, B, C, D]

    print(f"======================== CBC Block {index} ========================")
    print("Encrypted String list: ", cipher)
    print("Decrypted String list: ", org_txt_block)
    print(f"=============================================================\n")

    output = ''
    output = ''.join([output, Expand(bin(A), w)[2:]])
    output = ''.join([output, Expand(bin(B), w)[2:]])
    output = ''.join([output, Expand(bin(C), w)[2:]])
    output = ''.join([output, Expand(bin(D), w)[2:]])
    return output


def main():
    print("^^^^^^ DECRYPTION ^^^^^^")
    print("Waiting for message to receive...")
    is_connection_initiated = False
    while not is_connection_initiated:
        try:
            with open("status.txt", "r") as f:
                enc_sentence = f.readline()
                is_connection_initiated = enc_sentence == "Start Session"
        except FileNotFoundError:
            pass

    print("Started Ec Elgamal setup...")
    receiver_ec_elgamal = ReceiverEcElgamal(29, -1, 16)
    a, b, p, g, public_b, n = receiver_ec_elgamal.get_public_params()
    with open("initEcElgamal.txt", "w") as f:
        f.write("\n".join([str(a),
                           str(b),
                           str(p),
                           ",".join(map(str, g)),
                           ",".join(map(str, public_b)),
                           str(n)]))

    print("Finished Ec Elgamal setup, Waiting for Encrypted text...")
    is_ready_for_decryption = False
    while not is_ready_for_decryption:
        try:
            with open("status.txt", "r") as f:
                enc_sentence = f.readline()
                is_ready_for_decryption = enc_sentence == "Encryption Is Done"
        except FileNotFoundError:
            pass

    print("Started Decryption...")
    key_data = []
    try:
        with open("encryptedKEY.txt", "r") as f:
            key_data = [f.readline().replace("\n", "") for _ in range(3)]
    except FileNotFoundError:
        pass
    print("Received Encrypted key, Decrypting...")
    public_ec_elgamal, enc_key, enc_iv = (tuple(map(int, key_data[0].split(','))),
                                          tuple(map(int, key_data[1].split(','))),
                                          tuple(map(int, key_data[2].split(','))))
    rc6_key = receiver_ec_elgamal.receive_and_decrypt(public_ec_elgamal, enc_key)
    iv = receiver_ec_elgamal.receive_and_decrypt(public_ec_elgamal, enc_iv)
    rc6_key, iv = str(rc6_key), str(iv)
    print(f"RC6 key: {rc6_key}, IV: {iv}")

    if len(rc6_key) < 16:
        rc6_key = rc6_key + " " * (16 - len(rc6_key))
    rc6_key = rc6_key[:16]

    try:
        with open("encrypted.txt", "rb") as f:
            enc_sentence = f.readline()
            if not enc_sentence:
                print("Encrypted input not found in encrypted.txt")
                sys.exit(0)
    except FileNotFoundError:
        print("Encrypted input not found in encrypted.txt")
        sys.exit(0)
    print("Received Encrypted message, Decrypting...")
    print(f"Encrypted Message: {enc_sentence},\nLength: {len(enc_sentence)}")

    print("Decrypting With RC-6 in CBC mode:")
    S = generateKey(rc6_key)
    org_txt = Decryption(enc_sentence, S, iv)
    org_txt = org_txt.decode('utf-8')
    print(f"Decrypted Message: {org_txt},\nLength: {len(org_txt)}")

    signature_data = []
    try:
        with open("signature.txt", "r") as f:
            signature_data = [f.readline().replace("\n", "") for _ in range(3)]
    except FileNotFoundError:
        print("Encrypted input not found in signature.txt")
        sys.exit(0)
    if not signature_data:
        print("signature_data input not found in signature.txt")
        sys.exit(0)

    print("Received Signature, Verifying...")
    signature, U, n = (int(signature_data[0]),
                       signature_data[1].encode("utf-8"),
                       int(signature_data[2]))
    is_verified = verify_rabin(signature, U, n, org_txt)
    print(f"Signature Is {'' if is_verified else 'not '}Verified!")

    # Delete temp files for session
    temp_paths = ["status.txt", "encryptedKEY.txt", "signature.txt"]
    for path in temp_paths:
        if os.path.exists(path):
            os.remove(path)


if __name__ == "__main__":
    main()
