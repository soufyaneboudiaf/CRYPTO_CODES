import random
from typing import Tuple, Optional


class EllipticCurve:
    def __init__(self, a: int, b: int, p: int):
        self.a = a
        self.b = b
        self.p = p
        self.points = {}
        self.validate_curve()
        self.generate_points()

    def validate_curve(self) -> None:
        discriminant = (4 * (self.a ** 3) + 27 * (self.b ** 2)) % self.p
        if discriminant == 0:
            raise ValueError(f"Invalid curve: discriminant is 0 (mod {self.p})")
        print(f"Curve validated: discriminant = {discriminant} (mod {self.p})")
        print(f"Curve equation: y² ≡ x³ + {self.a}x + {self.b} (mod {self.p})\n")

    def point_on_curve(self, x: int, y: int) -> bool:
        y_squared = (y * y) % self.p
        x_cubed = (x * x * x) % self.p
        rhs = (x_cubed + self.a * x + self.b) % self.p
        return y_squared == rhs

    def generate_points(self) -> None:
        self.points[None] = [None]
        point_count = 1
        for x in range(self.p):
            x_cubed = (x * x * x) % self.p
            rhs = (x_cubed + self.a * x + self.b) % self.p
            y_values = []
            for y in range(self.p):
                if (y * y) % self.p == rhs:
                    y_values.append(y)
            if y_values:
                self.points[x] = y_values
                point_count += len(y_values)

    def extended_gcd(self, a: int, b: int) -> Tuple[int, int, int]:
        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def mod_inverse(self, a: int, m: int) -> int:
        if a < 0:
            a = (a % m + m) % m
        g, x, _ = self.extended_gcd(a, m)
        if g != 1:
            raise ValueError(f"Modular inverse does not exist for {a} mod {m}")
        return x % m

    def point_addition(self, P: Optional[Tuple[int, int]], Q: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        if P is None:
            return Q
        if Q is None:
            return P
        P_x, P_y = P
        Q_x, Q_y = Q
        if P_x == Q_x:
            if P_y == Q_y:
                return self.point_doubling(P)
            else:
                return None
        numerator = (Q_y - P_y) % self.p
        denominator = (Q_x - P_x) % self.p
        slope = (numerator * self.mod_inverse(denominator, self.p)) % self.p
        x_r = (slope * slope - P_x - Q_x) % self.p
        y_r = (slope * (P_x - x_r) - P_y) % self.p
        return (x_r, y_r)

    def point_doubling(self, P: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        if P is None:
            return None
        P_x, P_y = P
        if P_y == 0:
            return None
        numerator = (3 * P_x * P_x + self.a) % self.p
        denominator = (2 * P_y) % self.p
        slope = (numerator * self.mod_inverse(denominator, self.p)) % self.p
        x_r = (slope * slope - 2 * P_x) % self.p
        y_r = (slope * (P_x - x_r) - P_y) % self.p
        return (x_r, y_r)

    def scalar_multiplication(self, k: int, P: Optional[Tuple[int, int]]) -> Optional[Tuple[int, int]]:
        if P is None or k == 0:
            return None
        if k == 1:
            return P
        if k < 0:
            result = self.scalar_multiplication(-k, P)
            if result is None:
                return None
            x, y = result
            return (x, (-y) % self.p)
        binary_k = bin(k)[2:]
        result = None
        addend = P
        for bit in reversed(binary_k):
            if bit == '1':
                result = self.point_addition(result, addend)
            addend = self.point_doubling(addend)
        return result


class ECDSA:
    def __init__(self, curve: EllipticCurve, G: Tuple[int, int], t: int):
        self.curve = curve
        self.G = G
        self.t = t

    def sign(self, private_key: int, message: int) -> Tuple[int, int]:
        while True:
            k = random.randint(1, self.t - 1)
            Q = self.curve.scalar_multiplication(k, self.G)
            if Q is None:
                continue
            r = Q[0] % self.t
            if r == 0:
                continue
            k_inv = self.curve.mod_inverse(k, self.t)
            s = (k_inv * (private_key * r + message)) % self.t
            if s == 0:
                continue
            return (r, s)

    def verify(self, public_key: Tuple[int, int], message: int, signature: Tuple[int, int]) -> bool:
        r, s = signature
        if r <= 0 or r >= self.t or s <= 0 or s >= self.t:
            return False
        s_inv = self.curve.mod_inverse(s, self.t)
        u1 = (s_inv * message) % self.t
        u2 = (s_inv * r) % self.t
        point1 = self.curve.scalar_multiplication(u1, self.G)
        point2 = self.curve.scalar_multiplication(u2, public_key)
        Q = self.curve.point_addition(point1, point2)
        if Q is None:
            return False
        v = Q[0] % self.t
        return v == r


def main():
    print("=" * 70)
    print("ECDSA Signature Scheme")
    print("=" * 70)
    print()

    a = 2
    b = 2
    p = 17

    print(f"Curve parameters: a={a}, b={b}, p={p}\n")

    curve = EllipticCurve(a, b, p)

    G = (0, 6)
    if curve.point_on_curve(G[0], G[1]):
        print(f"Generator point G = {G} is on the curve\n")
    else:
        print("Finding a valid generator point...")
        G = None
        for x in range(p):
            if x in curve.points and curve.points[x]:
                G = (x, curve.points[x][0])
                break
        if G is None:
            print("Error: Could not find a generator point")
            return
        print(f"Using generator point G = {G}\n")

    t = 19

    ecdsa = ECDSA(curve, G, t)

    print("=" * 70)
    print("Generate Key Pair")
    print("=" * 70)
    d = 5
    P = curve.scalar_multiplication(d, G)
    print(f"Private key d = {d}")
    print(f"Public key P = d*G = {d}*{G} = {P}\n")

    print("=" * 70)
    print("Sign a Message")
    print("=" * 70)
    m = 10
    print(f"Message m = {m}")
    signature = ecdsa.sign(d, m)
    r, s = signature
    print(f"Signature (r, s) = ({r}, {s})\n")

    print("=" * 70)
    print("Verify Signature with Correct Message")
    print("=" * 70)
    print(f"Message m = {m}")
    print(f"Public key P = {P}")
    print(f"Signature (r, s) = ({r}, {s})")
    is_valid = ecdsa.verify(P, m, signature)
    print(f"Verification result: {is_valid}")
    if is_valid:
        print("SUCCESS! Signature is valid.\n")
    else:
        print("FAILURE! Signature is invalid.\n")

    print("=" * 70)
    print("Verify Signature with Tampered Message")
    print("=" * 70)
    m_tampered = 11
    print(f"Tampered message m = {m_tampered}")
    print(f"Public key P = {P}")
    print(f"Signature (r, s) = ({r}, {s})")
    is_valid_tampered = ecdsa.verify(P, m_tampered, signature)
    print(f"Verification result: {is_valid_tampered}")
    if not is_valid_tampered:
        print("SUCCESS! Tampered message was rejected.\n")
    else:
        print("FAILURE! Tampered message was accepted.\n")

    print("=" * 70)
    print("ECDSA Implementation Complete")
    print("=" * 70)


if __name__ == "__main__":
    main()
