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
        print(f"Generated {point_count} points on the curve")
        for x in sorted([k for k in self.points.keys() if k is not None]):
            print(f"  x={x}: {self.points[x]}")
        print()

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


class ECDH:
    def __init__(self, curve: EllipticCurve, G: Tuple[int, int]):
        self.curve = curve
        self.G = G
        if not self.curve.point_on_curve(G[0], G[1]):
            raise ValueError(f"Generator point {G} is not on the curve")
        print(f"Generator point G = {G}")
        print(f"G is on the curve\n")

    def generate_keypair(self, private_key: Optional[int] = None) -> Tuple[int, Tuple[int, int]]:
        if private_key is None:
            private_key = random.randint(1, 1000)
        public_key = self.curve.scalar_multiplication(private_key, self.G)
        return private_key, public_key

    def compute_shared_secret(self, private_key: int, other_public_key: Tuple[int, int]) -> Optional[Tuple[int, int]]:
        shared_secret = self.curve.scalar_multiplication(private_key, other_public_key)
        return shared_secret


def main():
    print("=" * 70)
    print("ECDH Key Exchange Protocol")
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

    ecdh = ECDH(curve, G)

    print("=" * 70)
    print("Alice Generates Keypair")
    print("=" * 70)
    alice_private = 5
    alice_public = curve.scalar_multiplication(alice_private, G)
    print(f"Alice's private key: {alice_private}")
    print(f"Alice's public key: {alice_public}\n")

    print("=" * 70)
    print("Bob Generates Keypair")
    print("=" * 70)
    bob_private = 7
    bob_public = curve.scalar_multiplication(bob_private, G)
    print(f"Bob's private key: {bob_private}")
    print(f"Bob's public key: {bob_public}\n")

    print("=" * 70)
    print("Alice Computes Shared Secret")
    print("=" * 70)
    alice_shared_secret = curve.scalar_multiplication(alice_private, bob_public)
    print(f"Alice: S = {alice_private} * {bob_public}")
    print(f"Alice's shared secret: {alice_shared_secret}\n")

    print("=" * 70)
    print("Bob Computes Shared Secret")
    print("=" * 70)
    bob_shared_secret = curve.scalar_multiplication(bob_private, alice_public)
    print(f"Bob: S = {bob_private} * {alice_public}")
    print(f"Bob's shared secret: {bob_shared_secret}\n")

    print("=" * 70)
    print("Verification")
    print("=" * 70)
    if alice_shared_secret == bob_shared_secret:
        print("SUCCESS! Both shared secrets match!")
        print(f"Shared Secret S = {alice_shared_secret}")
    else:
        print("FAILURE! Shared secrets do not match!")
        print(f"Alice's secret: {alice_shared_secret}")
        print(f"Bob's secret: {bob_shared_secret}")
    print()


if __name__ == "__main__":
    main()
