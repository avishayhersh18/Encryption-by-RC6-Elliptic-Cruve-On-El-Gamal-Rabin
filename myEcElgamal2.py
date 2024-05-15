from tinyec.ec import SubGroup, Curve, Point, mod_inv, Inf
import hashlib
import binascii
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
    return count + 1 #1 for the (infinity,infinity)
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
    # print(points)
    return points


class Bob:
    def __init__(self, p, a, b):
        self.p = p
        self.a = a
        self.b = b
        order_of_cruves=count_points_on_curve(a,b,p)
        point_generator=self.select_generator()
        # print(point_generator)
        self.curve = Curve(a=a, b=b, field=SubGroup(p=p, g=point_generator, n=order_of_cruves, h=0), name='curve')
        # print(point_generator)
        point_generator = Point(self.curve,point_generator[0],point_generator[1])
        self.G =point_generator

        self.kb = random.randint(1, p-1)  # Bob's private key
        self.B = self.kb * self.G  # Bob's public key
        # print(self.B)

    def select_generator(self):
        points = find_points_on_curve(self.a, self.b, self.p)
        if not points:
            raise ValueError("No points found on curve. Please check curve parameters.")
        return random.choice(points)  # Randomly select a generator point

    def send_public_params(self):
        return (self.p, self.curve, self.G, self.B)

    def receive_and_decrypt(self, A, c_m):
        S_ba = self.kb * A  # Compute the shared secret
        M = c_m - S_ba  # Decrypt the message
        return M
class Alice:
    def __init__(self, public_params):
        self.p, self.curve, self.G, self.publicB = public_params
        self.ka = random.randint(1, self.p-1)  # Alice's private key
        self.A = self.ka * self.G  # Alice's public key

    def find_y(self, x):
        # Find the y-coordinate for the given x-coordinate on the curve
        for possible_y in range(self.p):
            if (possible_y**2) % self.p == (x**3 + self.curve.a * x + self.curve.b) % self.p:
                return possible_y
        raise ValueError(f"No y-coordinate found for x={x} on the curve")

    def encrypt_message(self, M):
        # M is the x-coordinate of the message point
        y = self.find_y(M)  # Find the corresponding y-coordinate on the curve
        M_new = Point(self.curve, M, y)  # Create the new point with the x and y coordinates

        self.Sab = self.ka * self.publicB  # Shared secret
        print("bBbb",self.Sab)
        self.c_m = M_new + self.Sab
        print("bBbb",self.c_m)# Encrypt the message by adding the shared secret
        return self.A, self.c_m


# Example usage
p = 29
a = -1
b = 16
bob = Bob(p, a, b)
public_params = bob.send_public_params()

alice = Alice(public_params)
M = 0 # The message Alice wants to send
M_New=(M,alice.find_y(M)) #need to get from RC6
A, c_m = alice.encrypt_message(M)

# Bob receives (A, c_m) and decrypts the message
decrypted_message = bob.receive_and_decrypt(A, c_m)
print(f"Original Message: {M_New}, Decrypted Message: {decrypted_message}")