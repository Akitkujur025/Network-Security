# SHA-512 Hash Function (Python Implementation)

This project provides a comprehensive, from-scratch implementation of the **SHA-512** cryptographic hash function in Python, adhering to the specifications outlined in **FIPS PUB 180-4** by NIST. The code is designed for educational purposes, offering a clear and detailed breakdown of the SHA-512 algorithm.

---

## 🔍 Overview

SHA-512, a member of the SHA-2 family, produces a **512-bit (64-byte)** hash value, represented as a 128-character hexadecimal string. It is widely used in security-critical applications such as digital signatures, certificate generation, and password hashing due to its robustness and collision resistance.

This implementation follows the algorithm's structure as described in:
- [Breaking Down SHA-512 Algorithm](https://infosecwriteups.com/breaking-down-sha-512-algorithm-1fdb9cc9413a)
- [Cryptography: Explaining SHA-512](https://medium.com/@zaid960928/cryptography-explaining-sha-512-ad896365a0c1)

---

## ⚙️ How SHA-512 Works

The SHA-512 algorithm transforms an input message of arbitrary length into a fixed 512-bit hash through a series of well-defined steps. Below is a detailed explanation of the process, drawing from the referenced articles:

### 1. Preprocessing
- **Padding the Message**: The input message is padded to ensure its bit length is congruent to 896 modulo 1024, allowing space for the message length in the final block. Padding involves appending a `1` bit, enough `0` bits, and the 128-bit length of the original message.
- **Parsing the Message**: The padded message is divided into 1024-bit blocks.

### 2. Setting Initial Hash Values
- SHA-512 uses eight 64-bit initial hash values derived from the square roots of prime numbers:
     `H0 = 0x6a09e667f3bcc908`
     `H1 = 0xbb67ae8584caa73b`
     `H2 = 0x3c6ef372fe94f82b`
     `H3 = 0xa54ff53a5f1d36f1`
     `H4 = 0x510e527fade682d1`
     `H5 = 0x9b05688c2b3e6c1f`
     `H6 = 0x1f83d9abfb41bd6b`
     `H7 = 0x5be0cd19137e2179`
- Eighty 64-bit round constants are derived from cube roots of primes.

### 3. Processing Message Blocks

- **Message Schedule (W[0..79])**: First 16 words come directly from the block; the remaining 64 are computed using σ0 and σ1 functions.
- **Compression Function**:
- Initialize working variables (a-h).
- For each of 80 rounds:
  ```
  T1 = h + Σ1(e) + Ch(e, f, g) + K[t] + W[t]
  T2 = Σ0(a) + Maj(a, b, c)
  ```
  Update working variables accordingly.
- **Updating Hash Values**: Add the working variables back into the current hash values.

### 4. Producing the Final Hash
- Concatenate H0-H7 to form the 512-bit digest, typically represented as a 128-character hexadecimal string.

---

## 📁 File Structure
- `main.py`: Contains the complete SHA-512 implementation and test cases.

---

## 🛠️ Prerequisites
- **Python 3.x**
- Standard libraries: `struct`, `binascii`, `hashlib`

No external dependencies required.

---

## 🚀 Usage
1. Clone or download the repository.
2. Navigate to the project directory.
3. Run:
 ```bash
 python main.py
```
---
##🧪 Sample Output
```
This is the data to hash using SHA-512.
```
```bash
Input: 'This is the data to hash using SHA-512.'
SHA-512 Hash: 2b6e9377d962ec2f2a8ca414858773cffc21d6ac3c128ce4e091c669c25699d2ce7c8d815f6e20cd0938f5c774f4b0d81eb58d60bc881b8c5e81bb20b57376aa
Hash Length: 128 characters

SHA-512 Hash (hashlib): 2b6e9377d962ec2f2a8ca414858773cffc21d6ac3c128ce4e091c669c25699d2ce7c8d815f6e20cd0938f5c774f4b0d81eb58d60bc881b8c5e81bb20b57376aa
Results Match: True

```
