# SHA-512 Hash Function (Python Implementation)

This project offers a comprehensive, from-scratch implementation of the SHA-512 cryptographic hash function in Python, adhering to the specifications outlined in **FIPS PUB 180-4**.

---

## 🔍 Overview

SHA-512 is a member of the SHA-2 family, producing a 512-bit hash value. It's widely used in applications requiring high security, such as digital signatures, certificate generation, and password hashing.

---

## ⚙️ How SHA-512 Works

Drawing from Aditya Anand's article, "Breaking Down: SHA-512 Algorithm," the SHA-512 algorithm operates through the following steps:

### 1. **Preprocessing**

- **Padding the Message**: The original message is padded to ensure its length is congruent to 896 modulo 1024. This involves appending a single '1' bit, followed by a series of '0' bits, and finally adding a 128-bit representation of the original message length.&#8203;:contentReference[oaicite:2]{index=2}

- **Parsing the Message**: :contentReference[oaicite:3]{index=3}&#8203;:contentReference[oaicite:4]{index=4}

### 2. **Setting Initial Hash Values**

- :contentReference[oaicite:5]{index=5}&#8203;:contentReference[oaicite:6]{index=6}

### 3. **Processing Message Blocks**

For each 1024-bit block:

- **Message Schedule (W[0..79])**: :contentReference[oaicite:7]{index=7}&#8203;:contentReference[oaicite:8]{index=8}

- **Compression Function**: :contentReference[oaicite:9]{index=9}&#8203;:contentReference[oaicite:10]{index=10}

  - :contentReference[oaicite:11]{index=11}&#8203;:contentReference[oaicite:12]{index=12}

    - **Ch(x, y, z)**: Chooses bits from y or z, depending on x.

    - **Maj(x, y, z)**: Majority function; picks the majority bit among x, y, and z.

    - **Σ0(x) and Σ1(x)**: Functions involving right rotations and shifts.

  - :contentReference[oaicite:13]{index=13}&#8203;:contentReference[oaicite:14]{index=14}

- **Updating Hash Values**: :contentReference[oaicite:15]{index=15}&#8203;:contentReference[oaicite:16]{index=16}

### 4. **Producing the Final Hash**

- :contentReference[oaicite:17]{index=17}&#8203;:contentReference[oaicite:18]{index=18}

---

## 📁 File Structure

- `main.py` – :contentReference[oaicite:19]{index=19}&#8203;:contentReference[oaicite:20]{index=20}

---

## 🧪 Sample Output

For input:

```plaintext
"This is the data to hash using SHA-512."
