P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
P8 = [6, 3, 7, 4, 8, 5, 10, 9]
IP = [2, 6, 3, 1, 4, 8, 5, 7]
IP_INV = [4, 1, 3, 5, 7, 2, 8, 6]
EP = [4, 1, 2, 3, 2, 3, 4, 1]
P4 = [2, 4, 3, 1]

S0 = [
	[1, 0, 3, 2],
	[3, 2, 1, 0],
	[0, 2, 1, 3],
	[3, 1, 3, 2],
]

S1 = [
	[0, 1, 2, 3],
	[2, 0, 1, 3],
	[3, 0, 1, 0],
	[2, 1, 0, 3],
]


def _permute_str(bits, table):
	return "".join(bits[index - 1] for index in table)


def _left_shift_str(bits, count):
	"""Perform a circular left shift of a bit-string by count positions."""
	return bits[count:] + bits[:count]


def _xor_str(a, b):
	"""Compute bitwise XOR between two equal-length binary strings."""
	return "".join("1" if x != y else "0" for x, y in zip(a, b))


def _sbox_lookup(sbox, bits4):
	"""Map a 4-bit input through an S-box and return its 2-bit output."""
	# In Mini-DES S-box access:
	# - row is formed by first and last bits
	# - column is formed by middle two bits
	row = int(bits4[0] + bits4[3], 2)
	col = int(bits4[1] + bits4[2], 2)
	# Convert selected S-box value to a 2-bit binary string.
	return format(sbox[row][col], "02b")


def generate_minides_keys(key10):
	"""Generate Mini-DES subkeys K1 and K2 from a 10-bit master key."""
	# Validate key format (must be exactly 10 bits).
	if len(key10) != 10 or any(ch not in "01" for ch in key10):
		raise ValueError("Mini-DES key must be a 10-bit binary string")

	# Apply P10, then split into two 5-bit halves.
	p10 = _permute_str(key10, P10)
	left = p10[:5]
	right = p10[5:]

	# Left-shift each half by 1 and apply P8 to get K1.
	left_ls1 = _left_shift_str(left, 1)
	right_ls1 = _left_shift_str(right, 1)
	k1 = _permute_str(left_ls1 + right_ls1, P8)

	# From the shifted state, left-shift each half by 2 more and apply P8 to get K2.
	left_ls2 = _left_shift_str(left_ls1, 2)
	right_ls2 = _left_shift_str(right_ls1, 2)
	k2 = _permute_str(left_ls2 + right_ls2, P8)

	# Return both round keys in order of encryption rounds.
	return k1, k2


def _f_function(right4, subkey8):
	"""Apply Mini-DES round function F on the 4-bit right half using one subkey."""
	# Expand/permutate 4 bits to 8 bits.
	expanded = _permute_str(right4, EP)
	# Mix with round key.
	mixed = _xor_str(expanded, subkey8)
	# Split into two 4-bit parts for S0 and S1.
	left4 = mixed[:4]
	right4_mixed = mixed[4:]
	# Substitute each half through its S-box.
	s0_out = _sbox_lookup(S0, left4)
	s1_out = _sbox_lookup(S1, right4_mixed)
	# Combine and apply P4 to produce final 4-bit output.
	return _permute_str(s0_out + s1_out, P4)


def _fk(bits8, subkey8):
	"""Apply one Feistel transformation fk to an 8-bit block with one subkey."""
	# Split into left and right 4-bit halves.
	left = bits8[:4]
	right = bits8[4:]
	# Compute F on the right half.
	f_out = _f_function(right, subkey8)
	# XOR F output with left half; right half remains unchanged in fk output.
	left_new = _xor_str(left, f_out)
	return left_new + right


def minides_encrypt(plaintext8, key10):
	"""Encrypt one 8-bit plaintext block using Mini-DES with a 10-bit key."""
	# Validate plaintext format.
	if len(plaintext8) != 8 or any(ch not in "01" for ch in plaintext8):
		raise ValueError("Mini-DES plaintext must be an 8-bit binary string")

	# Key schedule.
	k1, k2 = generate_minides_keys(key10)
	# Initial permutation.
	ip = _permute_str(plaintext8, IP)
	# Round 1 with K1.
	round1 = _fk(ip, k1)
	# Swap halves between rounds.
	swapped = round1[4:] + round1[:4]
	# Round 2 with K2.
	round2 = _fk(swapped, k2)
	# Final inverse permutation gives ciphertext.
	ciphertext = _permute_str(round2, IP_INV)
	return ciphertext


def minides_decrypt(ciphertext8, key10):
	"""Decrypt one 8-bit ciphertext block using Mini-DES with a 10-bit key."""
	# Validate ciphertext format.
	if len(ciphertext8) != 8 or any(ch not in "01" for ch in ciphertext8):
		raise ValueError("Mini-DES ciphertext must be an 8-bit binary string")

	# Same subkeys as encryption.
	k1, k2 = generate_minides_keys(key10)
	# Initial permutation on ciphertext.
	ip = _permute_str(ciphertext8, IP)
	# Decryption uses reversed key order: K2 then K1.
	round1 = _fk(ip, k2)
	# Swap halves between rounds.
	swapped = round1[4:] + round1[:4]
	# Second round with K1.
	round2 = _fk(swapped, k1)
	# Inverse initial permutation returns plaintext.
	plaintext = _permute_str(round2, IP_INV)
	return plaintext


def main(plaintext8, key10):
	# Compute subkeys and all intermediate states .
	k1, k2 = generate_minides_keys(key10)
	ip = _permute_str(plaintext8, IP)
	r1 = _fk(ip, k1)
	sw = r1[4:] + r1[:4]
	r2 = _fk(sw, k2)
	cipher = _permute_str(r2, IP_INV)
	# Verify by decrypting the computed ciphertext.
	recovered = minides_decrypt(cipher, key10)

	print("\n=== Mini-DES (2 rounds) ===")
	print(f"K (10 bits)   : {key10}")
	print(f"P (8 bits)    : {plaintext8}")
	print(f"K1            : {k1}")
	print(f"K2            : {k2}")
	print(f"IP(P)         : {ip}")
	print(f"After round 1 : {r1}")
	print(f"After SW      : {sw}")
	print(f"After round 2 : {r2}")
	print(f"C             : {cipher}")
	print(f"Decrypt(C)    : {recovered}")


if __name__ == "__main__":
	minides_key = "1010000010"
	minides_plaintext = "01110010"
	main(minides_plaintext, minides_key)
