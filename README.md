# SHA-512 Hash Function (Python)

A from-scratch Python implementation of the SHA-512 cryptographic hash function, following **FIPS PUB 180-4** specifications.

---

## Overview

SHA-512, part of the SHA-2 family, generates a 512-bit (64-byte) hash, used in secure applications like digital signatures and password hashing. This educational implementation demonstrates the algorithm's core steps.

---

## How SHA-512 Works

SHA-512 processes an input message to produce a 512-bit hash:

1. **Padding**: Append a `1` bit, `0` bits, and the 128-bit message length to make the length congruent to 896 modulo 1024.
2. **Initialization**: Use eight 64-bit hash values (from square roots of primes 2, 3, 5, 7, 11, 13, 17, 19) and eighty round constants (from cube roots of primes 2 to 409).
3. **Block Processing**:
   - Divide the padded message into 1024-bit blocks.
   - For each block, create an 80-word message schedule using bitwise operations (`σ0`, `σ1`).
   - Run 80 rounds of compression with functions like `Ch`, `Maj`, `Σ0`, `Σ1`, updating eight working variables.
   - Update hash values after each block.
4. **Final Hash**: Concatenate the eight 64-bit hash values into a 128-character hexadecimal string.

Details: [Breaking Down SHA-512](https://infosecwriteups.com/breaking-down-sha-512-algorithm-1fdb9cc9413a), [Explaining SHA-512](https://medium.com/@zaid960928/cryptography-explaining-sha-512-ad896365a0c1).

---

## File
- `main.py`: Full SHA-512 implementation with test cases.

---

## Prerequisites
- Python 3.x
- Libraries: `struct`, `binascii`, `hashlib` (for comparison)

---

## Usage
1. Clone or download the repository.
2. Run:
   ```bash
   python main.py
