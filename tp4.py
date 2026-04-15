"""
TP4 - Chiffrement Asymétrique
Module : Cryptographie Avancée - 2CS-CS - ESTIN 2025/2026
=============================================================
Implémentation Python de :
  - TP4-1 : RSA (Chiffrement, Déchiffrement, Signature, Vérification)
  - TP4-2 : ElGamal (Chiffrement, Déchiffrement, Signature, Vérification)
  - Exponentiation modulaire rapide (Square-and-Multiply)
"""

import random
import math
import hashlib

# =============================================================
# UTILITAIRES DE BASE
# =============================================================

def modular_exponentiation(base, exp, mod):
    """
    Exponentiation modulaire rapide : base^exp mod mod
    Algorithme Square-and-Multiply (binary method).
    Complexité : O(log exp) multiplications modulaires.
    """
    result = 1
    base = base % mod
    while exp > 0:
        if exp % 2 == 1:          # si le bit courant est 1
            result = (result * base) % mod
        exp = exp >> 1            # décalage à droite (diviser par 2)
        base = (base * base) % mod
    return result


def extended_gcd(a, b):
    """
    Algorithme d'Euclide étendu.
    Retourne (gcd, x, y) tel que a*x + b*y = gcd(a,b)
    """
    if a == 0:
        return b, 0, 1
    gcd, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd, x, y


def mod_inverse(a, m):
    """Inverse modulaire de a modulo m (a^-1 mod m)."""
    gcd, x, _ = extended_gcd(a % m, m)
    if gcd != 1:
        raise ValueError(f"L'inverse modulaire n'existe pas : gcd({a},{m}) = {gcd}")
    return x % m


def is_prime_miller_rabin(n, k=10):
    """
    Test de primalité de Miller-Rabin (probabiliste).
    k : nombre de tours (plus k est grand, plus le test est fiable).
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    # Écrire n-1 comme 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = modular_exponentiation(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = modular_exponentiation(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits=128):
    """Génère un nombre premier aléatoire de 'bits' bits."""
    while True:
        p = random.getrandbits(bits)
        p |= (1 << bits - 1) | 1   # forcer le MSB et l'impair
        if is_prime_miller_rabin(p):
            return p


def generate_safe_prime(bits=128):
    """
    Génère un premier sûr p = 2q+1 où q est aussi premier.
    Avantage : g=2 est toujours un bon générateur → rapide.
    """
    while True:
        q = generate_prime(bits - 1)
        p = 2 * q + 1
        if is_prime_miller_rabin(p):
            return p, q


def find_primitive_root(p):
    """
    Pour un premier sûr p = 2q+1, on cherche g tel que
    g^2 != 1 mod p  ET  g^q != 1 mod p.
    Les petits entiers (2, 3, 5...) conviennent presque toujours.
    """
    q = (p - 1) // 2
    for g in range(2, min(1000, p)):
        if (modular_exponentiation(g, 2, p) != 1 and
                modular_exponentiation(g, q, p) != 1):
            return g
    return 2  # fallback


def prime_factors(n):
    """Retourne l'ensemble des facteurs premiers distincts de n."""
    factors = set()
    d = 2
    while d * d <= n:
        while n % d == 0:
            factors.add(d)
            n //= d
        d += 1
    if n > 1:
        factors.add(n)
    return factors


def hash_message(message):
    """Hache un message avec SHA-256, retourne un entier."""
    if isinstance(message, str):
        message = message.encode()
    return int(hashlib.sha256(message).hexdigest(), 16)


# =============================================================
# TP4-1 : RSA
# =============================================================

class RSA:
    """
    Implémentation complète de RSA :
      - Génération de clés
      - Chiffrement / Déchiffrement
      - Signature / Vérification
    """

    def __init__(self, bits=128):
        self.bits = bits
        self.public_key  = None   # (n, e)
        self.private_key = None   # (d, n)

    def generate_keys(self):
        """Génère la paire de clés RSA."""
        print(f"  [RSA] Génération des clés ({self.bits} bits)...")

        # Étape 1 : Choisir deux grands premiers p et q distincts
        p = generate_prime(self.bits // 2)
        q = generate_prime(self.bits // 2)
        while q == p:
            q = generate_prime(self.bits // 2)

        # Étape 2 : Calculer n et phi(n)
        n   = p * q
        phi = (p - 1) * (q - 1)

        # Étape 3 : Choisir e tel que 1 < e < phi et gcd(e,phi) = 1
        e = 65537  # valeur standard (premier de Fermat F4)
        if math.gcd(e, phi) != 1:
            # Fallback : chercher un e valide
            e = random.randrange(2, phi)
            while math.gcd(e, phi) != 1:
                e = random.randrange(2, phi)

        # Étape 4 : Calculer d = e^-1 mod phi
        d = mod_inverse(e, phi)

        self.public_key  = (n, e)
        self.private_key = (d, n)

        print(f"  [RSA] Clé publique  (n, e) générée ✓")
        print(f"  [RSA] Clé privée    (d, n) générée ✓")
        return self.public_key, self.private_key

    def encrypt(self, message_int, public_key):
        """
        Chiffrement RSA : c = m^e mod n
        message_int : entier représentant le message
        public_key  : (n, e)
        """
        n, e = public_key
        if message_int >= n:
            raise ValueError("Le message doit être < n")
        c = modular_exponentiation(message_int, e, n)
        return c

    def decrypt(self, ciphertext, private_key):
        """
        Déchiffrement RSA : m = c^d mod n
        ciphertext  : entier chiffré
        private_key : (d, n)
        """
        d, n = private_key
        m = modular_exponentiation(ciphertext, d, n)
        return m

    def sign(self, message, private_key):
        """
        Signature RSA : s = H(m)^d mod n
        Signe le hachage du message avec la clé privée.
        """
        d, n = private_key
        h = hash_message(message) % n
        s = modular_exponentiation(h, d, n)
        return s

    def verify(self, message, signature, public_key):
        """
        Vérification de signature RSA : H(m) == s^e mod n
        """
        n, e = public_key
        h_expected = hash_message(message) % n
        h_recovered = modular_exponentiation(signature, e, n)
        return h_expected == h_recovered


# =============================================================
# TP4-2 : ElGamal
# =============================================================

class ElGamal:
    """
    Implémentation complète d'ElGamal :
      - Génération de clés
      - Chiffrement / Déchiffrement
      - Signature / Vérification (schéma ElGamal)
    """

    def __init__(self, bits=64):
        self.bits = bits
        self.public_key  = None   # (p, g, y)  où y = g^x mod p
        self.private_key = None   # (p, g, x)

    def generate_keys(self):
        """Génère la paire de clés ElGamal."""
        print(f"  [ElGamal] Génération des clés ({self.bits} bits)...")

        # Étape 1 : Générer un premier sûr p = 2q+1 (q aussi premier)
        # → garantit que trouver g est instantané
        p, q = generate_safe_prime(self.bits)

        # Étape 2 : Trouver un générateur g (racine primitive mod p)
        # → trivial pour un premier sûr
        g = find_primitive_root(p)

        # Étape 3 : Choisir la clé privée x, 1 < x < p-1
        x = random.randrange(2, p - 1)

        # Étape 4 : Calculer y = g^x mod p
        y = modular_exponentiation(g, x, p)

        self.public_key  = (p, g, y)
        self.private_key = (p, g, x)

        print(f"  [ElGamal] Clé publique  (p, g, y) générée ✓")
        print(f"  [ElGamal] Clé privée    (p, g, x) générée ✓")
        return self.public_key, self.private_key

    def encrypt(self, message_int, public_key):
        """
        Chiffrement ElGamal :
          Choisir k aléatoire, 1 < k < p-1, gcd(k, p-1) = 1
          c1 = g^k mod p
          c2 = m * y^k mod p
        Retourne (c1, c2)
        """
        p, g, y = public_key
        if message_int >= p:
            raise ValueError("Le message doit être < p")

        # Choisir k aléatoire coprime avec p-1
        k = random.randrange(2, p - 1)
        while math.gcd(k, p - 1) != 1:
            k = random.randrange(2, p - 1)

        c1 = modular_exponentiation(g, k, p)
        c2 = (message_int * modular_exponentiation(y, k, p)) % p
        return (c1, c2)

    def decrypt(self, ciphertext, private_key):
        """
        Déchiffrement ElGamal :
          s  = c1^x mod p
          m  = c2 * s^-1 mod p
        """
        p, g, x = private_key
        c1, c2 = ciphertext
        s     = modular_exponentiation(c1, x, p)
        s_inv = mod_inverse(s, p)
        m     = (c2 * s_inv) % p
        return m

    def sign(self, message, private_key):
        """
        Signature ElGamal :
          h  = H(m) mod p
          Choisir k aléatoire, gcd(k, p-1) = 1
          r  = g^k mod p
          s  = k^-1 * (h - x*r) mod (p-1)
        Retourne (r, s)
        """
        p, g, x = private_key
        h = hash_message(message) % (p - 1)

        # Choisir k tel que gcd(k, p-1) = 1
        k = random.randrange(2, p - 1)
        while math.gcd(k, p - 1) != 1:
            k = random.randrange(2, p - 1)

        r     = modular_exponentiation(g, k, p)
        k_inv = mod_inverse(k, p - 1)
        s     = (k_inv * (h - x * r)) % (p - 1)
        return (r, s)

    def verify(self, message, signature, public_key):
        """
        Vérification de signature ElGamal :
          h  = H(m) mod p
          v1 = g^h mod p
          v2 = y^r * r^s mod p
          Valide si v1 == v2
        """
        p, g, y = public_key
        r, s    = signature
        if not (0 < r < p):
            return False
        h  = hash_message(message) % (p - 1)
        v1 = modular_exponentiation(g, h, p)
        v2 = (modular_exponentiation(y, r, p) * modular_exponentiation(r, s, p)) % p
        return v1 == v2


# =============================================================
# DÉMONSTRATIONS
# =============================================================

def separator(title):
    print("\n" + "=" * 62)
    print(f"  {title}")
    print("=" * 62)


def demo_modular_exp():
    separator("EXPONENTIATION MODULAIRE RAPIDE (Square-and-Multiply)")
    examples = [
        (2, 10, 1000),
        (3, 644, 645),
        (7, 256, 13),
    ]
    for base, exp, mod in examples:
        result  = modular_exponentiation(base, exp, mod)
        builtin = pow(base, exp, mod)   # vérification avec Python
        match   = "✓" if result == builtin else "✗"
        print(f"  {base}^{exp} mod {mod} = {result}   [Python built-in: {builtin}] {match}")


def demo_rsa():
    separator("TP4-1 : RSA — Chiffrement / Déchiffrement / Signature")

    # --- Génération des clés pour Alice et Bob ---
    print("\n── Génération des clés ──")
    alice = RSA(bits=128)
    bob   = RSA(bits=128)
    alice_pub, alice_priv = alice.generate_keys()
    bob_pub,   bob_priv   = bob.generate_keys()

    # --- Chiffrement : Bob envoie un message chiffré à Alice ---
    print("\n── Chiffrement (Bob → Alice) ──")
    message_int = 42  # message numérique simple pour la démo
    print(f"  Message original (entier) : {message_int}")

    # Bob chiffre avec la clé PUBLIQUE d'Alice
    ciphertext = bob.encrypt(message_int, alice_pub)
    print(f"  Chiffré par Bob (clé pub Alice) : {str(ciphertext)[:60]}...")

    # Alice déchiffre avec sa clé PRIVÉE
    decrypted = alice.decrypt(ciphertext, alice_priv)
    print(f"  Déchiffré par Alice (clé priv) : {decrypted}")
    print(f"  Résultat : {'✓ SUCCÈS' if decrypted == message_int else '✗ ÉCHEC'}")

    # --- Signature : Alice signe un document pour Bob ---
    print("\n── Signature Numérique (Alice signe, Bob vérifie) ──")
    document = "Contrat de collaboration ESTIN 2026"
    print(f"  Document : \"{document}\"")

    # Alice signe avec sa clé PRIVÉE
    signature = alice.sign(document, alice_priv)
    print(f"  Signature (Alice, clé priv) : {str(signature)[:60]}...")

    # Bob vérifie avec la clé PUBLIQUE d'Alice
    valid = bob.verify(document, signature, alice_pub)
    print(f"  Vérification (Bob, clé pub Alice) : {'✓ VALIDE' if valid else '✗ INVALIDE'}")

    # Test avec un document falsifié
    fake_doc = "Contrat falsifié !!!"
    valid_fake = bob.verify(fake_doc, signature, alice_pub)
    print(f"  Vérification doc falsifié : {'✓ VALIDE' if valid_fake else '✗ INVALIDE (correct !)'}")

    # --- Schéma complet : A signe ET chiffre pour B ---
    print("\n── Schéma complet : Alice signe ET chiffre pour Bob ──")
    msg      = "Message confidentiel signé"
    msg_int  = int(hashlib.sha256(msg.encode()).hexdigest(), 16) % alice_pub[0]

    # Alice : (1) signe avec sa clé privée, (2) chiffre avec clé publique de Bob
    sig  = alice.sign(msg, alice_priv)
    ciph = alice.encrypt(msg_int, bob_pub)
    print(f"  Alice signe  (dA, nA)  ✓")
    print(f"  Alice chiffre (nB, eB) ✓")

    # Bob : (1) déchiffre avec sa clé privée, (2) vérifie avec clé publique d'Alice
    dec   = bob.decrypt(ciph, bob_priv)
    check = bob.verify(msg, sig, alice_pub)
    print(f"  Bob déchiffre (dB, nB) ✓  →  m récupéré = {dec == msg_int}")
    print(f"  Bob vérifie   (nA, eA) ✓  →  signature = {'VALIDE ✓' if check else 'INVALIDE ✗'}")


def demo_elgamal():
    separator("TP4-2 : ElGamal — Chiffrement / Déchiffrement / Signature")

    print("\n── Génération des clés ──")
    eg = ElGamal(bits=128)
    pub, priv = eg.generate_keys()
    p, g, y = pub

    # --- Chiffrement / Déchiffrement ---
    print("\n── Chiffrement / Déchiffrement ──")
    message_int = 12345
    print(f"  Message original : {message_int}")

    ciphertext = eg.encrypt(message_int, pub)
    print(f"  Chiffré (c1, c2) : ({str(ciphertext[0])[:30]}..., {str(ciphertext[1])[:30]}...)")

    decrypted = eg.decrypt(ciphertext, priv)
    print(f"  Déchiffré : {decrypted}")
    print(f"  Résultat  : {'✓ SUCCÈS' if decrypted == message_int else '✗ ÉCHEC'}")

    # --- Signature / Vérification ---
    print("\n── Signature / Vérification ──")
    document = "Document officiel ESTIN - TP4 Cryptographie"
    print(f"  Document : \"{document}\"")

    sig = eg.sign(document, priv)
    print(f"  Signature (r, s) générée ✓")

    valid = eg.verify(document, sig, pub)
    print(f"  Vérification : {'✓ VALIDE' if valid else '✗ INVALIDE'}")

    # Test falsification
    fake = "Document falsifié"
    valid_fake = eg.verify(fake, sig, pub)
    print(f"  Vérification doc falsifié : {'✓ VALIDE' if valid_fake else '✗ INVALIDE (correct !)'}")

    # --- Exponentiation modulaire (rappel) ---
    print("\n── Exponentiation modulaire dans ElGamal ──")
    print(f"  y = g^x mod p")
    print(f"  g   = {str(g)[:40]}...")
    print(f"  p   = {str(p)[:40]}...")
    print(f"  y   = {str(y)[:40]}...")
    print(f"  Calculé avec modular_exponentiation() ✓")


# =============================================================
# MAIN
# =============================================================

if __name__ == "__main__":
    print("╔══════════════════════════════════════════════════════════╗")
    print("║     TP4 - Cryptographie Avancée - ESTIN 2025/2026       ║")
    print("║     Chiffrement Asymétrique : RSA & ElGamal              ║")
    print("╚══════════════════════════════════════════════════════════╝")

    demo_modular_exp()
    demo_rsa()
    demo_elgamal()

    print("\n" + "=" * 62)
    print("  Fin du TP4 — Toutes les démonstrations complétées ✓")
    print("=" * 62)