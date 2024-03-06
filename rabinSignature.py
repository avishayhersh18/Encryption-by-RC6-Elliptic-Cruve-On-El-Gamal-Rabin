import hashlib

# security level 1 means  512 bits public key and hash length
SECURITY_LEVEL = 1


def gcd(a: int, b: int) -> int:
    if b > a:
        a, b = b, a
    while b > 0:
        a, b = b, a % b
    return a


def gen_prime_pair(seed) -> tuple:
    if isinstance(seed, str):
        seed = bytes.fromhex(seed)

    priv_range = 2 ** (256 * SECURITY_LEVEL)
    p = next_prime(hash_to_int(seed) % priv_range)
    q = next_prime(hash_to_int(seed + b'\x00') % priv_range)
    return p, q


def next_prime(p: int) -> int:
    while p % 4 != 3:
        p = p + 1
    return next_prime_3(p)


def next_prime_3(p: int) -> int:
    m_ = 3 * 5 * 7 * 11 * 13 * 17 * 19 * 23 * 29
    while gcd(p, m_) != 1:
        p = p + 4
    if pow(2, p - 1, p) != 1 or pow(3, p - 1, p) != 1 or pow(5, p - 1, p) != 1 or pow(17, p - 1, p) != 1:
        return next_prime_3(p + 4)
    return p


def hash512(x: bytes) -> bytes:
    hx = hashlib.sha256(x).digest()
    idx = len(hx) // 2
    return hashlib.sha256(hx[:idx]).digest() + hashlib.sha256(hx[idx:]).digest()


def hash_to_int(x: bytes) -> int:
    hx = hash512(x)
    for _ in range(SECURITY_LEVEL - 1):
        hx += hash512(hx)
    return int.from_bytes(hx, 'little')


def verify_rabin(signature, U, n, msg) -> bool:
    msg_bytes = msg.encode('utf-8')
    h_tag = hash_to_int(msg_bytes + U) % n
    h = (signature * signature) % n
    return h == h_tag


class RabinSignature:
    def __init__(self, msg):
        self._p = 19
        self._q = 13
        self.n = self._p * self._q
        self._msg = msg
        print(f"Rabin Signature:\n"
              f"p: {self._p}, q: {self._q}, n: {self.n}")

    def sign_with_rabin(self) -> tuple:
        """
        :return: rabin signature (S: int, padding: int)
        """
        msg_bytes = self._msg.encode('utf-8')
        p = self._p
        q = self._q
        n = self.n
        i = 0
        while True:
            h = hash_to_int(msg_bytes + b'\x00' * i) % n
            if (h % p == 0 or pow(h, (p - 1) // 2, p) == 1) and (h % q == 0 or pow(h, (q - 1) // 2, q) == 1):
                break
            i += 1
        # Using Rabin on Hash result
        lp = q * pow(h, (p + 1) // 4, p) * pow(q, p - 2, p)
        rp = p * pow(h, (q + 1) // 4, q) * pow(p, q - 2, q)
        s = (lp + rp) % n
        U = b'\x00' * i

        return s, U


if __name__ == '__main__':
    # signature, U = sign_rabin(p, q,msg)

    print(f"\nsignature -> (x: {signature},U: {U})")
    with open("signature.txt", "w") as f:
        f.write("\n".join([str(signature), U.decode("utf-8"), str(n)]))

    if 1 == verify_rabin(signature, U, msg):
        print("message is authentic")
    else:
        print("message is not authentic")
