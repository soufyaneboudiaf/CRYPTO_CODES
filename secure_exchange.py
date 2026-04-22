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

    def point_on_curve(self, x: int, y: int) -> bool:
        y_squared = (y * y) % self.p
        x_cubed = (x * x * x) % self.p
        rhs = (x_cubed + self.a * x + self.b) % self.p
        return y_squared == rhs

    def generate_points(self) -> None:
        self.points[None] = [None]
        for x in range(self.p):
            x_cubed = (x * x * x) % self.p
            rhs = (x_cubed + self.a * x + self.b) % self.p
            y_values = []
            for y in range(self.p):
                if (y * y) % self.p == rhs:
                    y_values.append(y)
            if y_values:
                self.points[x] = y_values

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

    def generate_keypair(self, private_key: Optional[int] = None) -> Tuple[int, Tuple[int, int]]:
        if private_key is None:
            private_key = random.randint(1, 1000)
        public_key = self.curve.scalar_multiplication(private_key, self.G)
        return private_key, public_key

    def compute_shared_secret(self, private_key: int, other_public_key: Tuple[int, int]) -> Optional[Tuple[int, int]]:
        shared_secret = self.curve.scalar_multiplication(private_key, other_public_key)
        return shared_secret


class SHA256:
    K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

    @staticmethod
    def rotr(x: int, n: int) -> int:
        return ((x >> n) | (x << (32 - n))) & 0xffffffff

    @staticmethod
    def shr(x: int, n: int) -> int:
        return x >> n

    @staticmethod
    def pad_message(message: bytes) -> bytes:
        msg_len = len(message)
        msg_bit_len = msg_len * 8
        message += b'\x80'
        while (len(message) % 64) != 56:
            message += b'\x00'
        message += msg_bit_len.to_bytes(8, 'big')
        return message

    @staticmethod
    def compress(H: list, block: bytes) -> None:
        W = []
        for i in range(16):
            W.append(int.from_bytes(block[i*4:(i+1)*4], 'big'))
        for i in range(16, 64):
            s0 = SHA256.rotr(W[i-15], 7) ^ SHA256.rotr(W[i-15], 18) ^ SHA256.shr(W[i-15], 3)
            s1 = SHA256.rotr(W[i-2], 17) ^ SHA256.rotr(W[i-2], 19) ^ SHA256.shr(W[i-2], 10)
            W.append((W[i-16] + s0 + W[i-7] + s1) & 0xffffffff)

        a, b, c, d, e, f, g, h = H

        for i in range(64):
            S1 = SHA256.rotr(e, 6) ^ SHA256.rotr(e, 11) ^ SHA256.rotr(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + S1 + ch + SHA256.K[i] + W[i]) & 0xffffffff
            S0 = SHA256.rotr(a, 2) ^ SHA256.rotr(a, 13) ^ SHA256.rotr(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (S0 + maj) & 0xffffffff

            h = g
            g = f
            f = e
            e = (d + temp1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (temp1 + temp2) & 0xffffffff

        H[0] = (H[0] + a) & 0xffffffff
        H[1] = (H[1] + b) & 0xffffffff
        H[2] = (H[2] + c) & 0xffffffff
        H[3] = (H[3] + d) & 0xffffffff
        H[4] = (H[4] + e) & 0xffffffff
        H[5] = (H[5] + f) & 0xffffffff
        H[6] = (H[6] + g) & 0xffffffff
        H[7] = (H[7] + h) & 0xffffffff

    @staticmethod
    def digest(message: bytes) -> bytes:
        H = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
        padded = SHA256.pad_message(message)
        for i in range(0, len(padded), 64):
            SHA256.compress(H, padded[i:i+64])
        result = b''
        for h in H:
            result += h.to_bytes(4, 'big')
        return result


class KDF:
    @staticmethod
    def derive(shared_secret_x: int) -> bytes:
        x_bytes = shared_secret_x.to_bytes(32, 'big')
        return SHA256.digest(x_bytes)


class StreamCipher:
    sbox = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5e, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xd7, 0x4b, 0x55, 0xcf, 0x34, 0xc2, 0x34, 0x7f, 0x35, 0x2a, 0x23, 0x40, 0x11, 0xa5, 0x82, 0xcc, 0x4d, 0x02, 0x24, 0x92, 0xf1, 0x1a, 0xf6, 0x43, 0xc7, 0x3c, 0xab, 0x2a, 0xb0, 0xfe, 0xa5, 0x41, 0x6b, 0x22, 0x27, 0x10, 0x5a, 0x8a, 0xca, 0x02, 0x65, 0x4f, 0xf4, 0x5a, 0xbe, 0xb3, 0x8e, 0x4d, 0x55, 0x5d, 0x53, 0x20, 0xcf, 0xa6, 0x04, 0xa1, 0x59, 0x0a, 0x05, 0x68, 0x11, 0x8c, 0x31, 0x4c, 0x88, 0x16, 0xef, 0x62, 0x03, 0x60, 0x55, 0xb8, 0xed, 0x1b, 0x27, 0xd4, 0x69, 0xfb, 0x0e, 0x25, 0x92, 0x02, 0x58, 0xfc, 0x04, 0x6d, 0x65, 0x2a, 0xea, 0x9c, 0xaa, 0xf4, 0x3f, 0x09, 0x67, 0x6c, 0xb2, 0x76, 0x0e, 0x62, 0xb1, 0xde, 0xfe, 0x9e, 0x06, 0x48, 0xb4, 0x13, 0x47, 0x87, 0x0e, 0x4b, 0x0b, 0x35, 0x34, 0x51, 0x94, 0x65, 0x1e, 0x70, 0xc1, 0x2c, 0xed, 0x20, 0xfe, 0xb4, 0x06, 0x5b, 0xd7, 0x34, 0x79, 0x25, 0x22, 0x92, 0x20, 0x88, 0x44, 0x44, 0x0f, 0x89, 0x45, 0x4f, 0xde, 0x94, 0x59, 0x94, 0x64, 0xe6, 0x21, 0xa0, 0xce, 0xcb, 0x2f, 0x74, 0x33]
    inv_sbox = [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]

    @staticmethod
    def gmul(a: int, b: int) -> int:
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a = (a << 1) & 0xff
            if hi_bit_set:
                a ^= 0x1b
            b >>= 1
        return p

    @staticmethod
    def key_expansion(key: bytes) -> bytes:
        rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]
        w = []
        for i in range(4):
            w.append(int.from_bytes(key[4*i:4*i+4], 'big'))
        for i in range(4, 44):
            temp = w[i-1]
            if i % 4 == 0:
                temp = (StreamCipher.sbox[(temp >> 8) & 0xff] << 24) | (StreamCipher.sbox[(temp >> 16) & 0xff] << 16) | (StreamCipher.sbox[(temp >> 24) & 0xff] << 8) | StreamCipher.sbox[temp & 0xff]
                temp ^= (rcon[i // 4 - 1] << 24)
            w.append(w[i-4] ^ temp)
        result = b''
        for word in w:
            result += word.to_bytes(4, 'big')
        return result

    @staticmethod
    def sub_bytes(state: bytearray) -> None:
        for i in range(16):
            state[i] = StreamCipher.sbox[state[i]]

    @staticmethod
    def inv_sub_bytes(state: bytearray) -> None:
        for i in range(16):
            state[i] = StreamCipher.inv_sbox[state[i]]

    @staticmethod
    def shift_rows(state: bytearray) -> None:
        state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

    @staticmethod
    def inv_shift_rows(state: bytearray) -> None:
        state[1], state[5], state[9], state[13] = state[13], state[1], state[5], state[9]
        state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
        state[3], state[7], state[11], state[15] = state[7], state[11], state[15], state[3]

    @staticmethod
    def mix_columns(state: bytearray) -> None:
        for col in range(4):
            r0 = state[col]
            r1 = state[4 + col]
            r2 = state[8 + col]
            r3 = state[12 + col]
            state[col] = StreamCipher.gmul(r0, 2) ^ StreamCipher.gmul(r1, 3) ^ r2 ^ r3
            state[4 + col] = r0 ^ StreamCipher.gmul(r1, 2) ^ StreamCipher.gmul(r2, 3) ^ r3
            state[8 + col] = r0 ^ r1 ^ StreamCipher.gmul(r2, 2) ^ StreamCipher.gmul(r3, 3)
            state[12 + col] = StreamCipher.gmul(r0, 3) ^ r1 ^ r2 ^ StreamCipher.gmul(r3, 2)

    @staticmethod
    def inv_mix_columns(state: bytearray) -> None:
        for col in range(4):
            r0 = state[col]
            r1 = state[4 + col]
            r2 = state[8 + col]
            r3 = state[12 + col]
            state[col] = StreamCipher.gmul(r0, 0x0e) ^ StreamCipher.gmul(r1, 0x0b) ^ StreamCipher.gmul(r2, 0x0d) ^ StreamCipher.gmul(r3, 0x09)
            state[4 + col] = StreamCipher.gmul(r0, 0x09) ^ StreamCipher.gmul(r1, 0x0e) ^ StreamCipher.gmul(r2, 0x0b) ^ StreamCipher.gmul(r3, 0x0d)
            state[8 + col] = StreamCipher.gmul(r0, 0x0d) ^ StreamCipher.gmul(r1, 0x09) ^ StreamCipher.gmul(r2, 0x0e) ^ StreamCipher.gmul(r3, 0x0b)
            state[12 + col] = StreamCipher.gmul(r0, 0x0b) ^ StreamCipher.gmul(r1, 0x0d) ^ StreamCipher.gmul(r2, 0x09) ^ StreamCipher.gmul(r3, 0x0e)

    @staticmethod
    def encrypt(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
        plaintext = StreamCipher.pkcs7_pad(plaintext)
        keystream = b''
        counter = 0
        while len(keystream) < len(plaintext):
            block_input = counter.to_bytes(8, 'big') + iv[:8]
            keystream += SHA256.digest(key + block_input)
            counter += 1
        return bytes(a ^ b for a, b in zip(plaintext, keystream[:len(plaintext)]))

    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
        keystream = b''
        counter = 0
        while len(keystream) < len(ciphertext):
            block_input = counter.to_bytes(8, 'big') + iv[:8]
            keystream += SHA256.digest(key + block_input)
            counter += 1
        plaintext = bytes(a ^ b for a, b in zip(ciphertext, keystream[:len(ciphertext)]))
        return StreamCipher.pkcs7_unpad(plaintext)

    @staticmethod
    def add_round_key_bytes(state: bytearray, round_key: bytes) -> None:
        for i in range(16):
            state[i] ^= round_key[i]

    @staticmethod
    def pkcs7_pad(data: bytes) -> bytes:
        pad_len = 16 - (len(data) % 16)
        return data + bytes([pad_len] * pad_len)

    @staticmethod
    def pkcs7_unpad(data: bytes) -> bytes:
        pad_len = data[-1]
        return data[:-pad_len]


class HMAC:
    @staticmethod
    def compute(key: bytes, message: bytes) -> bytes:
        if len(key) > 64:
            key = SHA256.digest(key)
        if len(key) < 64:
            key = key + b'\x00' * (64 - len(key))
        opad = bytes(x ^ 0x5c for x in key)
        ipad = bytes(x ^ 0x36 for x in key)
        inner = SHA256.digest(ipad + message)
        return SHA256.digest(opad + inner)

    @staticmethod
    def verify(key: bytes, message: bytes, tag: bytes) -> bool:
        computed_tag = HMAC.compute(key, message)
        return computed_tag == tag


def main():
    print("=" * 70)
    print("Secure Message Exchange Protocol")
    print("=" * 70)
    print()

    print("=" * 70)
    print("Step 1: ECDH Key Exchange")
    print("=" * 70)
    a = 2
    b = 2
    p = 17
    G = (0, 6)

    curve = EllipticCurve(a, b, p)
    ecdh = ECDH(curve, G)

    alice_private, alice_public = ecdh.generate_keypair(5)
    bob_private, bob_public = ecdh.generate_keypair(7)

    print(f"Alice's public key: {alice_public}")
    print(f"Bob's public key: {bob_public}")

    alice_shared = ecdh.compute_shared_secret(alice_private, bob_public)
    bob_shared = ecdh.compute_shared_secret(bob_private, alice_public)

    print(f"Alice's shared secret: {alice_shared}")
    print(f"Bob's shared secret: {bob_shared}")

    if alice_shared == bob_shared:
        print("✓ Shared secrets match\n")
    else:
        print("✗ Shared secrets do not match\n")
        return

    print("=" * 70)
    print("Step 2: Derive Symmetric Key using KDF")
    print("=" * 70)
    shared_secret_x = alice_shared[0]
    alice_key = KDF.derive(shared_secret_x)
    bob_key = KDF.derive(shared_secret_x)

    print(f"Alice's derived key: {alice_key.hex()}")
    print(f"Bob's derived key: {bob_key.hex()}")

    if alice_key == bob_key:
        print("✓ Derived keys match\n")
    else:
        print("✗ Derived keys do not match\n")
        return

    print("=" * 70)
    print("Step 3: Alice Encrypts Message with StreamCipher CBC")
    print("=" * 70)
    message = b"Hello Bob, this is a secret!"
    print(f"Alice's message: {message.decode()}")

    iv = bytes(range(16))
    ciphertext = StreamCipher.encrypt(message, alice_key[:16], iv)
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"IV: {iv.hex()}\n")

    print("=" * 70)
    print("Step 4: Alice Computes HMAC Tag")
    print("=" * 70)
    tag = HMAC.compute(alice_key, ciphertext)
    print(f"HMAC tag: {tag.hex()}\n")

    print("=" * 70)
    print("Step 5: Bob Receives and Verifies HMAC Tag")
    print("=" * 70)
    is_valid = HMAC.verify(bob_key, ciphertext, tag)
    print(f"HMAC verification: {is_valid}")
    if is_valid:
        print("✓ HMAC tag is valid\n")
    else:
        print("✗ HMAC tag is invalid\n")
        return

    print("=" * 70)
    print("Step 6: Bob Decrypts Ciphertext with StreamCipher CBC")
    print("=" * 70)
    recovered_message = StreamCipher.decrypt(ciphertext, bob_key[:16], iv)
    print(f"Recovered message: {recovered_message.decode()}\n")

    print("=" * 70)
    print("Step 7: Verify Message Integrity")
    print("=" * 70)
    if recovered_message == message:
        print("✓ Message successfully recovered and verified!")
        print("Secure exchange complete!\n")
    else:
        print("✗ Message does not match!")
        print(f"Original: {message}")
        print(f"Recovered: {recovered_message}\n")


if __name__ == "__main__":
    main()
