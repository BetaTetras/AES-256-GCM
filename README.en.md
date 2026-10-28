# AES-256-GCM + PBKDF2 in C

🇫🇷 [Version française](README.fr.md)

A C library for password-based encryption of files or in-memory data, written entirely by hand: AES-256, GCM mode (CTR + GHASH), SHA-256, HMAC-SHA256 and PBKDF2. It uses no external library: only the C standard library and a few operating-system functions (randomness, file permissions and file replacement).

A single call encrypts a file in place, or an in-memory buffer, with a password; decryption checks the integrity of the data before returning anything.

> [!WARNING]
> **Educational project, not audited.** The code has not undergone any security review. To protect real data, use a proven library such as libsodium or OpenSSL.

---

## Table of contents

- [Features](#features)
- [Quick start](#quick-start)
  - [1. The header](#1-the-header)
  - [2. Example: a small command-line tool](#2-example-a-small-command-line-tool)
  - [3. Build and run](#3-build-and-run)
- [API](#api)
  - [File encryption (main API)](#file-encryption-main-api)
  - [In-memory encryption](#in-memory-encryption)
  - [Cryptographic primitives](#cryptographic-primitives)
- [Encrypted data format](#encrypted-data-format)
- [Internals](#internals)
  - [Code organization](#code-organization)
  - [Parameters](#parameters)
- [Compliance and tests](#compliance-and-tests)
  - [Compatibility](#compatibility)
- [Performance](#performance)
- [Known limitations](#known-limitations)
- [License](#license)
- [References](#references)

---

## Features

- **AES-256** compliant with FIPS-197 (14 rounds, key expansion into 60 words).
- **AES-256-GCM authenticated encryption** compliant with NIST SP 800-38D: counter-mode (CTR) encryption and a 16-byte authentication tag. The encrypted data can be read by any other GCM implementation (see [Compatibility](#compatibility)).
- **PBKDF2-HMAC-SHA256 key derivation** with **600,000 iterations** (OWASP recommendation): the 32-byte key is derived from the password and a random salt. The iteration count is **stored in the file**: it can be increased in a future version without making existing files unreadable.
- **Random salt and nonce** drawn from the system's random generator (`/dev/urandom`, or `BCryptGenRandom` on Windows) for every encryption: encrypting the same data twice with the same password gives two different results.
- **File or in-memory encryption**: `AES_GCM_Encrypt` / `AES_GCM_Decrypt` work on a buffer, without writing anything to disk, and produce exactly the same format as an encrypted file.
- **No padding**: the ciphertext is exactly the size of the original data (+ 49 bytes of header and tag).
- **Files processed in 16-byte blocks**: memory usage stays constant, whatever the file size.
- **Safe writing**: the result is written to `<file>.tmp` and then renamed. Every write is checked: on a wrong password, a tampered file or a full disk, the `.tmp` is deleted and the original stays intact. On Linux, macOS and BSD, the file keeps its permissions (a `600` file stays `600`); on Windows, it gets those of its folder. A file that is too large, or whose size cannot be read, is refused without being modified.
- **Memory hygiene**: the key and its copies (AES round keys), as well as the intermediate values of PBKDF2, HMAC and SHA-256, are erased before every return, with a `volatile` write that the compiler cannot remove. Allocated buffers are erased before being freed. The tag is compared in constant time.

---

## Quick start

### 1. The header

The code fits in a single source file, `AES.c`. The header `AES.h` contains the public prototypes (comments translated here):

```c
#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

/* File encryption (main API) */
int AES_GCM_Encrypt_File(char* path, char* password);
int AES_GCM_Decrypt_File(char* path, char* password);

/* In-memory encryption (same format as encrypted files)
 * *dest must be NULL: the function allocates it, the caller frees it with free.
 * Decrypt adds a '\0' after the text (not counted in *size_dest). */
int AES_GCM_Encrypt(uint8_t** dest, size_t* size_dest, uint8_t* src, size_t size_src, char* password);
int AES_GCM_Decrypt(uint8_t** dest, size_t* size_dest, uint8_t* src, size_t size_src, char* password);

/* Primitives */
void AES_Encrypt_State(uint8_t state[4][4], uint8_t const cle[32]);
void AES_Decrypt_State(uint8_t state[4][4], uint8_t const cle[32]);
int  AES_SHA256(uint8_t* dest, uint8_t* mess, size_t size);
int  AES_HMAC(uint8_t* dest, uint8_t* key, size_t size_key, uint8_t* mess, size_t size_mess);
int  PBKDF2(uint8_t* dest, char* password, size_t size_password,
            uint8_t* salt, size_t size_salt, size_t tour);

#endif
```

### 2. Example: a small command-line tool

```c
#include <stdio.h>
#include <string.h>
#include "AES.h"

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <encrypt|decrypt> <file> <password>\n", argv[0]);
        return 1;
    }

    int r;
    if (strcmp(argv[1], "encrypt") == 0) {
        r = AES_GCM_Encrypt_File(argv[2], argv[3]);
    } else {
        r = AES_GCM_Decrypt_File(argv[2], argv[3]);
    }

    if (r == 0)      puts("OK");
    else if (r == 2) puts("Wrong password or tampered file");
    else if (r == 3) puts("File encrypted with another version (unknown format)");
    else             puts("Error (file not found, read/write, disk full, memory)");
    return r;
}
```

> For the sake of the example, the password is passed as an argument. In a real program, it is better to type it at the keyboard: a command-line argument remains visible in the shell history and in the process list.

### 3. Build and run

**Linux, macOS, BSD:**

```bash
gcc -std=c11 -Wall -Wextra -O2 -o aescli main.c AES.c

./aescli encrypt note.txt "my password"
./aescli decrypt note.txt "my password"
```

**Windows (MinGW-w64, for example with MSYS2):** add `-lbcrypt`, the Windows library that provides `BCryptGenRandom`:

```bat
gcc -std=c11 -Wall -Wextra -O2 -o aescli.exe main.c AES.c -lbcrypt

aescli.exe encrypt note.txt "my password"
aescli.exe decrypt note.txt "my password"
```

**Platforms:**

- **Linux, macOS, BSD**: any POSIX system providing `/dev/urandom`.
- **Windows**: with MinGW-w64. The code compiles without warnings (`-Wall -Wextra -pedantic`), but has **not yet been tested on a Windows machine**. Visual Studio (MSVC) has not been tried.

The differences between systems are isolated in `#ifdef _WIN32` blocks of `AES.c`: source of randomness, reading the file size (`ftell` / `_ftelli64`, because a `long` is only 32 bits on Windows), replacing the file (`rename` / `MoveFileExA`) and copying permissions (Linux, macOS, BSD only).

---

## API

### File encryption (main API)

```c
int AES_GCM_Encrypt_File(char* path, char* password);
int AES_GCM_Decrypt_File(char* path, char* password);
```

| Parameter  | Description |
|------------|-------------|
| `path`     | Path of the file. It is **replaced** by its encrypted (or decrypted) version. |
| `password` | Password, a C string terminated by `\0`. |

| Return code | `AES_GCM_Encrypt_File` | `AES_GCM_Decrypt_File` |
|:-----------:|------------------------|------------------------|
| `0` | Success | Success |
| `1` | Error: random generator unavailable, file not found, unreadable size or file too large (see [Known limitations](#known-limitations)), open, read, write (disk full), allocation, rename. The original is intact. | Error: file not found, file smaller than 49 bytes or too large, iteration count of 0, open, write (disk full), allocation, rename. The original is intact. |
| `2` | — | **Authentication failure**: wrong password *or* modified file. The file is not touched. |
| `3` | — | **Unknown version**: the first byte is not `7`, for example a file encrypted with V6 or an earlier version (see [Compatibility](#compatibility)). The file is not touched. |

A wrong password and a tampered file both give `2`: the two cases are indistinguishable by design.

Decryption takes two passes: the first computes and checks the tag without writing anything; the second decrypts into `<file>.tmp`, checks the tag again, then renames.

### In-memory encryption

```c
int AES_GCM_Encrypt(uint8_t** dest, size_t* size_dest, uint8_t* src, size_t size_src, char* password);
int AES_GCM_Decrypt(uint8_t** dest, size_t* size_dest, uint8_t* src, size_t size_src, char* password);
```

| Parameter | Description |
|-----------|-------------|
| `dest` | Address of a pointer that must be `NULL`. The function allocates the result and stores its address there; the caller frees it with `free`. |
| `size_dest` | Receives the size of the result: `size_src + 49` for `AES_GCM_Encrypt`, `size_src - 49` for `AES_GCM_Decrypt`. |
| `src`, `size_src` | Input data: the plaintext (`AES_GCM_Encrypt`) or the encrypted data (`AES_GCM_Decrypt`). |
| `password` | Password, a C string terminated by `\0`. |

| Return code | `AES_GCM_Encrypt` | `AES_GCM_Decrypt` |
|:-----------:|-------------------|-------------------|
| `0` | Success | Success |
| `1` | Error: `NULL` parameter, `*dest` not `NULL`, data too large (see [Known limitations](#known-limitations)), random generator unavailable, allocation | Error: `NULL` parameter, `*dest` not `NULL`, smaller than 49 bytes or too large, iteration count of 0, allocation |
| `2` | — | **Authentication failure**: wrong password *or* modified data. `*dest` stays `NULL`. |
| `3` | — | **Unknown version**: the first byte is not `7`. `*dest` stays `NULL`. |

- The result of `AES_GCM_Encrypt` has exactly the format of an encrypted file: it can be written as is to a file and read back with `AES_GCM_Decrypt_File`, and vice versa.
- `AES_GCM_Decrypt` adds a `'\0'` after the text (not counted in `*size_dest`): decrypted text, JSON for example, can be used directly as a C string.
- The decrypted text is sensitive: erase it before freeing it, with a `volatile` write loop (a plain `memset` just before `free` may be removed by the compiler).

```c
const char* json = "{\"site\":\"example\",\"pwd\":\"secret\"}";
uint8_t* cipher = NULL;  size_t cipher_size = 0;
uint8_t* plain  = NULL;  size_t plain_size  = 0;

if (AES_GCM_Encrypt(&cipher, &cipher_size, (uint8_t*)json, strlen(json), "my password") != 0) {
    puts("Encryption error");
    return 1;
}

int r = AES_GCM_Decrypt(&plain, &plain_size, cipher, cipher_size, "my password");
if (r == 0)      printf("%s\n", (char*)plain);   /* '\0' added by AES_GCM_Decrypt */
else if (r == 2) puts("Wrong password or tampered data");
else if (r == 3) puts("Data encrypted with another version");

free(cipher);
free(plain);   /* erase plain first if it contains secrets */
```

### Cryptographic primitives

These functions can be used on their own. The `AES_` prefix of `AES_SHA256` and `AES_HMAC` avoids a name clash with OpenSSL's `SHA256` and `HMAC` functions.

| Function | Role | Output | Return |
|----------|------|--------|--------|
| `AES_Encrypt_State(state, cle)` | Encrypts **one** 16-byte block in place with a 32-byte key. | `state` modified | — |
| `AES_Decrypt_State(state, cle)` | Decrypts a 16-byte block in place. | `state` modified | — |
| `AES_SHA256(dest, mess, size)` | SHA-256 digest of `size` bytes. | `dest`: 32 bytes | `0` success, `1` allocation |
| `AES_HMAC(dest, key, size_key, mess, size_mess)` | HMAC-SHA256 (key of any size). | `dest`: 32 bytes | `0` / `1` |
| `PBKDF2(dest, password, size_password, salt, size_salt, tour)` | PBKDF2-HMAC-SHA256 with `tour` iterations (≥ 1). | `dest`: **32 bytes** (fixed size) | `0` / `1` |

**Layout of an AES block.** As in FIPS-197, the `state[row][column]` matrix is filled **column by column**: byte `i` of the block goes into `state[i % 4][i / 4]`.

```
bytes 00 01 02 … 0f   →   0x00 0x04 0x08 0x0c
                          0x01 0x05 0x09 0x0d
                          0x02 0x06 0x0a 0x0e
                          0x03 0x07 0x0b 0x0f
```

```c
/* Load 16 bytes into a state, encrypt, read back */
uint8_t state[4][4];
for (int i = 0; i < 16; i++) state[i % 4][i / 4] = block[i];
AES_Encrypt_State(state, key);
for (int i = 0; i < 16; i++) block[i] = state[i % 4][i / 4];
```

---

## Encrypted data format

The format is the same for a file and for an in-memory buffer. For original data of **N** bytes, the result is **N + 49** bytes:

```
[Version - 1 B][Iteration count - 4 B][Salt - 16 B][Nonce - 12 B][Ciphertext - N B][Tag - 16 B]
```

| Position (bytes) | Size | Content |
|------------------|:----:|---------|
| `0`              | 1  | Format version: `7` |
| `1` – `4`        | 4  | PBKDF2 iteration count, 32-bit unsigned integer, most significant byte first (600,000 = `00 09 27 C0`) |
| `5` – `20`       | 16 | PBKDF2 salt, random |
| `21` – `32`      | 12 | Nonce, random |
| `33` – `32+N`    | N  | Ciphertext (same size as the original) |
| `33+N` – `48+N`  | 16 | Authentication tag |

Encryption writes the value of `PBKDF2_TOURS`; decryption uses the iteration count read from the file. Increasing `PBKDF2_TOURS` in a future version will therefore not make already-encrypted files unreadable.

The version and the iteration count are not part of the tag, but they cannot be modified without being detected: another version is refused (code `3`), and another iteration count gives another key, hence a wrong tag (code `2`).

---

## Internals

```
password ─────┐
              ├──►  PBKDF2-HMAC-SHA256 (iterations from the header, 600,000 when encrypting)  ──►  key K (32 bytes)
salt (16 B) ──┘

H         = AES-256(K, 0¹²⁸)                          GHASH hash key
Block i   = nonce ‖ counter (i + 2)                   32-bit counter, most significant byte first
Cipher i  = Plain i ⊕ AES-256(K, Block i)             CTR mode; last block truncated
S         = GHASH_H(cipher blocks ‖ length block)     length block = 0⁶⁴ ‖ size in bits (64 bits)
Tag       = S ⊕ AES-256(K, nonce ‖ 00 00 00 01)
```

- The **length block** prevents blocks from being added or removed without changing the tag.
- The **mask** `AES(K, nonce ‖ 1)` binds the tag to the nonce and hides the value of GHASH, hence of H.
- The **multiplication in GF(2¹²⁸)** follows the GCM convention: bits stored in reverse order, right shift and reduction by `0xE1` on the first byte (SP 800-38D, § 6.3).
- The **tag comparison** always goes through all 16 bytes and accumulates the differences (`diff |= a ^ b`) without branching: its duration does not depend on the number of correct bytes.
- **PBKDF2**: at each iteration, HMAC hashes `key ⊕ ipad` and `key ⊕ opad`, two blocks that depend only on the password. Their SHA-256 compression is therefore computed once at the start: each iteration then needs only 2 compressions instead of 4.

### Code organization

| Module | Functions |
|--------|-----------|
| AES – rounds | `addRoundKey`, `SubBytes` / `InvSubBytes`, `ShiftRows` / `InvShiftRows` (via `push` / `pop`), `MixColumns` / `InvMixColumns` (via `xtime` / `mul` in GF(2⁸)) |
| AES – keys | `Explode` (key → 8 words), `GenerateKey` (60 words), `RotWord`, `SubWord` |
| AES – blocks | `AES_Encrypt_State`, `AES_Decrypt_State` |
| GCM | `ConterBlockGenerator` (counter block), `gf128_multiply` (multiplication in GF(2¹²⁸)), `AES_GCM_Encrypt_File`, `AES_GCM_Decrypt_File`, `AES_GCM_Encrypt`, `AES_GCM_Decrypt` |
| SHA-256 | `padding`, `compressing`, `ROTR`, `choose`, `majority`, `SIG0`, `SIG1`, `sig0`, `sig1`, `AES_SHA256` |
| Key derivation | `AES_HMAC`, `PBKDF2` |
| Utility | `uint8_tToZero` (memory erasure that the compiler cannot remove) |

### Parameters

| Parameter | Value | Where |
|-----------|-------|-------|
| Format version | 7 (first byte of the header) | `#define VERSION` |
| PBKDF2 iterations when encrypting | 600,000, written to the header | `#define PBKDF2_TOURS` |
| PBKDF2 iterations when decrypting | the value read from the header (1 to 4,294,967,295) | `AES_GCM_Decrypt*` |
| Salt size | 16 bytes | `AES_GCM_*` |
| Nonce size | 12 bytes (96 bits) | `AES_GCM_*` |
| Tag size | 16 bytes (128 bits) | `AES_GCM_*` |
| Maximum data size | 68,719,476,704 bytes (≈ 64 GiB) | `#define GCM_TAILLE_MAX` |
| Additional authenticated data (AAD) | not supported | — |

---

## Compliance and tests

Each component has been tested against the official test vectors:

| Component | Test vector | Result |
|-----------|-------------|:------:|
| AES-256, encryption and decryption | FIPS-197, appendix C.3 | ✅ |
| SHA-256 | FIPS 180-4: `"abc"`, empty string, 448-bit message (2 blocks) | ✅ |
| HMAC-SHA256 | RFC 4231, cases 1, 2 and 6 (131-byte key) | ✅ |
| PBKDF2-HMAC-SHA256 | `"password"` / `"salt"`, 1 and 4,096 iterations | ✅ |
| GCM ciphertext (CTR stream) | NIST GCM, test case 14 | ✅ |
| GF(2¹²⁸) multiplication (GHASH) | NIST GCM, test case 2 | ✅ |
| Counter blocks beyond 2³¹ (up to 4,294,967,295) | Comparison with AES-ECB (Python `cryptography`) | ✅ |
| Complete file (header, salt, nonce, ciphertext, tag) | Python (`hashlib` + `AESGCM` from `cryptography`) reads the header and decrypts files of 0 to 100,000 bytes; files built by Python, with 600,000 and 1,000 iterations, are decrypted | ✅ |
| In-memory encrypted data | Same comparison with Python, from 0 to 1,000 bytes, with 600,000 and 1,000 iterations | ✅ |

File tests (encryption → decryption round trip):

| Scenario | Result |
|----------|:------:|
| Files of 0, 1, 15, 16, 17, 1,000 and 100,000 bytes: content restored identically, size + 49 bytes, header `07 00 09 27 C0` | ✅ |
| Wrong password → code `2`, file intact, no `.tmp` | ✅ |
| Each byte of an encrypted file modified one at a time: version → code `3`, all others (iteration count included) → code `2`, file never modified | ✅ |
| File encrypted with V6 → code `3`, intact; version byte set to `8` → code `3` | ✅ |
| Iteration count of 0 → code `1`, intact | ✅ |
| File smaller than 49 bytes, empty file, missing file → code `1` | ✅ |
| Full disk (simulated with `ulimit -f`) during encryption or decryption → code `1`, original intact, no `.tmp` | ✅ |
| File in mode `600` → still `600` after encryption and decryption | ✅ |
| Unreadable size (`ftell` returns `-1`, simulated with a named pipe) → code `1`, nothing is modified | ✅ |
| File one byte larger than the maximum size (68,719,476,705 bytes, sparse file) → code `1`, intact, no `.tmp`; the maximum size (68,719,476,704 bytes) is accepted | ✅ |
| Encrypted file larger than the maximum size + 49 bytes → code `1` on decryption, intact; the maximum size + 49 bytes is accepted | ✅ |
| Read-only folder → code `1`, original intact | ✅ |

In-memory tests:

| Scenario | Result |
|----------|:------:|
| Round trip of 0, 17 and 1,000 bytes: identical content, trailing `'\0'`, size + 49 bytes | ✅ |
| Wrong password → code `2`, `*dest` stays `NULL` | ✅ |
| Modified bytes (version, iteration count, salt, nonce, ciphertext, tag): version → code `3`, the others → code `2` | ✅ |
| Data encrypted with V6 → code `3`; iteration count of 0 → code `1` | ✅ |
| Smaller than 49 bytes, `NULL` parameter or `*dest` already set → code `1` | ✅ |
| Declared size larger than the maximum size (with a small buffer) → code `1` before any read, `*dest` stays `NULL` | ✅ |
| Data encrypted in memory, written to a file, then read back by `AES_GCM_Decrypt_File`, and vice versa | ✅ |
| No copy of the key on the stack after `AES_GCM_Encrypt` (checked at `-O0` and `-O2`) | ✅ |
| After `AES_HMAC`, neither the key XOR `ipad` nor the inner hash remains on the stack or in freed memory | ✅ |

All scenarios pass under `valgrind` with no errors and no memory leaks.

**Windows:** `AES.c` and the example above compile with MinGW-w64 (x86_64) without warnings (`-Wall -Wextra -pedantic`). The tests above have not yet been run on Windows.

### Compatibility

After the header, the format follows the AES-256-GCM standard: with the PBKDF2 key (same password, same salt, same iteration count, read from the header), any compliant GCM implementation can decrypt the data, and vice versa.

**Files encrypted with V5 or V6:** they have no header (version and iteration count). V7 refuses them (code `3`, file intact), and V6 refuses V7 files (code `2`, file intact). To keep them: decrypt them with V6, then encrypt them again with V7.

> [!NOTE]
> The first byte of a V5 or V6 file is the start of its salt, hence random: one file in 256 starts with byte `7`. V7 then reads it as a V7 file, with an iteration count taken from the following bytes of the salt (often several billion): decryption may take hours before answering `2`. Decrypting such files with V6 avoids this case.

**Files encrypted with V4 or earlier:** also refused (code `3`, with the same one-in-256 case): decrypt them with the version that created them.

---

## Performance

Indicative measurements (`gcc -O2`, Raspberry Pi 4 Model B at 1.8 GHz, Linux; median of 3 runs for V7):

| Operation | V7 | V6 | V5 |
|-----------|----|----|----|
| PBKDF2 key derivation (600,000 iterations), on every encryption or decryption | ≈ 1.4 s | ≈ 1.4 s | ≈ 2.9 s |
| Encrypting a 4 MiB file | ≈ 3.9 s | ≈ 3.8 s | ≈ 5.3 s |
| Decrypting a 4 MiB file (two passes) | ≈ 5.7 s | ≈ 5.5 s | ≈ 7.0 s |

The V6 speed-up comes only from PBKDF2 (see [Internals](#internals)): data processing itself has not changed (≈ 2.5 s to encrypt 4 MiB, ≈ 4.3 s to decrypt it, excluding PBKDF2). V7 only changes the header (5 bytes) and adds the erasure of HMAC and SHA-256 intermediate values: it performs the same computations as V6, and measurement differences stay below 0.2 s.

The duration of key derivation is proportional to the iteration count read from the file: twice as many iterations, twice the time.

The code favours readability over speed:

- `AES_Encrypt_State` recomputes the key expansion (60 words) **for every block**, then erases it;
- `gf128_multiply` processes the 128 bits one at a time.

---

## Known limitations

**Security**

- The iteration count read from a file is not capped (by choice): a modified file can request up to 4,294,967,295 iterations, i.e. ≈ 2 h 45 of computation on a Raspberry Pi 4 before being refused (code `2`). Nothing is read or written during that time, and the file stays intact.
- PBKDF2, `AES_HMAC` and `AES_SHA256` erase their intermediate values, but two traces may remain: the SHA-256 working variables (`W` and `a` to `h` in `compressing`) stay on the stack, because erasing them would slow down PBKDF2, which calls `compressing` 1.2 million times; and a copy may remain in the processor's registers after a `memcpy`, which C cannot erase. The password itself remains the caller's responsibility.
- No additional authenticated data (AAD).

**Robustness**

- An existing `<file>.tmp` is overwritten without warning.
- Maximum data size: 68,719,476,704 bytes (≈ 64 GiB), for a file as well as in memory, on Linux as well as on Windows. This is the limit of GCM itself (NIST SP 800-38D): the counter is only 32 bits, and beyond that the same masks would be reused. The four `AES_GCM_*` functions refuse a larger size (code `1`) without modifying anything. Going further would require splitting the data into several GCM messages (a new file format).
- No file of this size has been encrypted in full during the tests (≈ 11 h 30 of encryption and ≈ 19 h 30 of decryption on a Raspberry Pi 4, extrapolated from the 4 MiB measurements): the limits were checked on sparse files, and the counter blocks beyond 2³¹ compared with Python.
- The internal functions (`padding`, `compressing`, `push`, `pop`, `mul`…) are global and have generic names: possible clash with another library linked into the same program. Declaring them `static` would solve the problem.

**Windows** (expected behaviour, not yet tested on a Windows machine)

- A read-only file is refused (code `1`, intact): Windows refuses to replace it.
- The result gets the permissions of the folder, not those of the original file.
- Paths go through the "ANSI" API (`fopen`, `MoveFileExA`): a file name containing characters missing from the Windows code page cannot be opened.

---

## License

MIT, see [LICENSE](LICENSE).

---

## References

- [FIPS 197 — Advanced Encryption Standard (AES)](https://csrc.nist.gov/pubs/fips/197/final)
- [NIST SP 800-38D — Galois/Counter Mode (GCM)](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [FIPS 180-4 — Secure Hash Standard (SHA-256)](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [RFC 2104 — HMAC](https://www.rfc-editor.org/rfc/rfc2104)
- [RFC 4231 — HMAC-SHA256 test vectors](https://www.rfc-editor.org/rfc/rfc4231)
- [RFC 8018 — PKCS #5: PBKDF2](https://www.rfc-editor.org/rfc/rfc8018)
- [OWASP — Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
