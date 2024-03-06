from tinyec.ec import SubGroup, Curve, Point
import random


def is_quadratic_residue(n, p):
    """Check if n is a quadratic residue modulo p"""
    return pow(n, (p - 1) // 2, p) == 1

def count_points_on_curve(a, b, p):
    count = 0
    for x in range(p):
        # Calculate the right-hand side of the curve's equation
        rhs = (x**3 + a*x + b) % p
        # If rhs is a quadratic residue, then there are two points for this x (except when rhs is 0)
        if is_quadratic_residue(rhs, p) or rhs == 0:
            count += 2 if rhs != 0 else 1
    # Add one for the point at infinity
    return count + 1

def find_points_on_curve(a, b, p):
    """Find points on the curve y^2 = x^3 + ax + b mod p"""
    points = []
    for x in range(p):
        y_squared = (x**3 + a*x + b) % p
        if is_quadratic_residue(y_squared, p):
            for y in range(p):
                if (y * y) % p == y_squared:
                    points.append((x, y))
                    break
    return points


class ReceiverEcElgamal:
    def __init__(self, p, a, b):
        self.p = p
        self.a = a
        self.b = b
        self.n = count_points_on_curve(self.a, self.b, self.p)
        point_generator = self._select_generator()
        self.curve = Curve(a=self.a,
                           b=self.b,
                           field=SubGroup(p=self.p, g=point_generator, n=self.n, h=0),
                           name='curve')
        self.G = Point(self.curve, point_generator[0], point_generator[1])

        self.k_b = random.randint(1, self.p - 1)  # Bob's private key
        self.B = self.k_b * self.G  # Bob's public key

    def _select_generator(self):
        points = find_points_on_curve(self.a, self.b, self.p)
        if not points:
            raise ValueError("No points found on curve. Please check curve parameters.")
        return random.choice(points)  # Randomly select a generator point

    def get_public_params(self) -> tuple:
        return self.a, self.b, self.p, (self.G.x, self.G.y), (self.B.x, self.B.y), self.n

    def receive_and_decrypt(self, public_key: tuple, cipher_key: tuple):
        A = Point(self.curve, public_key[0], public_key[1])
        C_m = Point(self.curve, cipher_key[0], cipher_key[1])
        S_ba = self.k_b * A  # Compute the shared secret
        M_point = C_m - S_ba  # Decrypt the key
        return M_point.x


class SenderEcElgamal:
    def __init__(self, a, b, p, g: tuple, public_b: tuple, n):
        self.p = p
        self.curve = Curve(a=a,
                           b=b,
                           field=SubGroup(p=p, g=g, n=n, h=0),
                           name='curve')
        self.G = Point(self.curve, g[0], g[1])
        self.publicB = Point(self.curve, public_b[0], public_b[1])

        self.ka = random.randint(1, self.p - 1)  # Alice's private key
        self.A = self.ka * self.G  # Alice's public key

    def find_y(self, x):
        # Find the y-coordinate for the given x-coordinate on the curve
        for possible_y in range(self.p):
            if (possible_y**2) % self.p == (x**3 + self.curve.a * x + self.curve.b) % self.p:
                return possible_y
        raise ValueError(f"No y-coordinate found for x={x} on the curve")

    def encrypt_key(self, M):
        # M is the x-coordinate of the message(key) point
        y = self.find_y(M)  # Find the corresponding y-coordinate on the curve
        M_point = Point(self.curve, M, y)  # Create the new point with the x and y coordinates

        self.S_ab = self.ka * self.publicB  # Shared secret
        self.C_m = M_point + self.S_ab  # Encrypt the key by adding the shared secret
        return self.A, self.C_m


# Example usage
# bob = ReceiverEcElgamal()
# public_params = bob.get_public_params()
#
# alice = SenderEcElgamal(public_params)
# M = 23  # The message Alice wants to send
# A, C_m = alice.encrypt_key(M)
#
# # Bob receives (A, c_m) and decrypts the message
# decrypted_key = bob.receive_and_decrypt(A, C_m)
# print(f"Original Key: {M}, Decrypted Key: {decrypted_key}")
