WORD_SIZE = 32
NUM_OF_ROUNDS = 12


def XORstrings(a, b):
    xor = int(a, 2) ^ int(b, 2)
    return bin(xor)[2:].zfill(len(a))


def Expand(bit_string, length):
    output = bit_string
    output = ''.join([output[:2], output[2:].zfill(length)])
    return output


def bytesToBin(bytes_string):
    output = bytes_string
    output = [Expand(bin(char), 8)[2:] for char in output]
    output = ''.join(output)
    return output


def binToBytes(bin_string):
    output = [int('0b' + bin_string[block * 8: (block + 1) * 8], 2) for block in
              range(int(len(bin_string) / 8))]
    output = bytes(output)
    return output


# Rotate right input x, by n bits
def ROR(x, n, bits=WORD_SIZE):
    mask = (2**n) - 1
    mask_bits = x & mask
    return (x >> n) | (mask_bits << (bits - n))


# Rotate left input x, by n bits
def ROL(x, n, bits=WORD_SIZE):
    return ROR(x, bits - n, bits)


# Convert input sentence into blocks of binary
# Creates 4 blocks of binary each of 32 bits.
def blockConverter(sentence):
    encoded = []
    res = ""
    for i in range(0, len(sentence)):
        if i % 4 == 0 and i != 0:
            encoded.append(res)
            res = ""
        temp = bin(ord(sentence[i]))[2:]
        if len(temp) < 8:
            temp = "0" * (8 - len(temp)) + temp
        res = res + temp
    encoded.append(res)
    return encoded


# Converts 4 blocks array of long int into string
def deBlocker(blocks):
    w = WORD_SIZE
    string = ""
    for block in blocks:
        temp = bin(block)[2:]
        if len(temp) < w:
            temp = "0" * (w - len(temp)) + temp
        for i in range(4):
            string = string + chr(int(temp[i * 8:(i + 1) * 8], 2))
    return string


# Generate key s[0... 2r+3] from given input string userkey
def generateKey(user_key):
    r = 12
    w = WORD_SIZE
    modulo = 2 ** w

    s = (2 * r + 4) * [0]
    s[0] = 0xB7E15163
    for i in range(1, 2 * r + 4):
        s[i] = (s[i - 1] + 0x9E3779B9) % (2 ** w)
    encoded = blockConverter(user_key)
    en_length = len(encoded)
    l = en_length * [0]
    for i in range(1, en_length + 1):
        l[en_length - i] = int(encoded[i - 1], 2)

    v = 3 * max(en_length, 2 * r + 4)
    A = B = i = j = 0

    for index in range(v):
        A = s[i] = ROL((s[i] + A + B) % modulo, 3, w)
        B = l[j] = ROL((l[j] + A + B) % modulo, (A + B) % w, w)
        i = (i + 1) % (2 * r + 4)
        j = (j + 1) % en_length
    return s
