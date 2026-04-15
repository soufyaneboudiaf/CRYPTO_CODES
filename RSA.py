# Fonction de chiffrement RSA
def chiffrer(msg, e, n):
    return pow(msg, e, n)


# Fonction de déchiffrement RSA
def dechiffrer(c, d, n):
    return pow(c, d, n)


# Fonction de signature RSA
def signer(msg, d, n):
    return pow(msg, d, n)


# Fonction de vérification de signature
def verifier(signature, e, n):
    return pow(signature, e, n)


# =========================
# Exemple d'utilisation
# =========================

# Clés de Alice
nA = 3233
eA = 17
dA = 2753

# Clés de Bob
nB = 2773
eB = 17
dB = 157

# Message (doit être un nombre < n)
MSG = 123

# 1. Alice signe le message
signature = signer(MSG, dA, nA)

# 2. Alice chiffre le message pour Bob
message_chiffre = chiffrer(MSG, eB, nB)

print("Message chiffré :", message_chiffre)
print("Signature :", signature)

# 3. Bob déchiffre le message
message_dechiffre = dechiffrer(message_chiffre, dB, nB)

# 4. Bob vérifie la signature
message_verifie = verifier(signature, eA, nA)

print("Message déchiffré :", message_dechiffre)
print("Message vérifié :", message_verifie)