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
  - [Return codes](#return-codes)
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
- **Wrong password recognised**: a key fingerprint (HMAC-SHA256) stored in the header tells a wrong password (code `14`) apart from modified data (code `2`). The wrong password is refused right after PBKDF2, without reading the data: ≈ 1.4 s, whatever the file size.
- **Random salt and nonce** drawn from the system's random generator (`/dev/urandom`, or `BCryptGenRandom` on Windows) for every encryption: encrypting the same data twice with the same password gives two different results.
- **File or in-memory encryption**: `AES_GCM_Encrypt` / `AES_GCM_Decrypt` work on a buffer, without writing anything to disk, and produce exactly the same format as an encrypted file.
- **No padding**: the ciphertext is exactly the size of the original data (+ 81 bytes of header and tag).
- **Files processed in 16-byte blocks**: memory usage stays constant, whatever the file size.
- **Safe writing**: the result is written to `<file>.tmp` and then renamed. Every write is checked: on a wrong password, a tampered file or a full disk, the `.tmp` is deleted and the original stays intact. On Linux, macOS and BSD, the file keeps its permissions (a `600` file stays `600`); on Windows, it gets those of its folder. A file that is too large, or whose size cannot be read, is refused without being modified.
- **Memory hygiene**: the key and its copies (AES round keys), as well as the intermediate values of PBKDF2, HMAC and SHA-256, are erased before every return, with a `volatile` write that the compiler cannot remove. Allocated buffers are erased before being freed. The tag and the key fingerprint are compared in constant time.

---

## Quick start

### 1. The header

The code fits in a single source file, `AES.c`. The header `AES.h` contains the public prototypes (comments translated here):

```c
#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

/* Return codes of all the int functions below.
 * 0 = success: a plain if(AES_GCM_Encrypt_File(...)) catches every error. */
#define AES_OK                0   /* everything went well */
#define AES_ERR_PARAM         1   /* bad argument: NULL pointer, *dest not NULL, PBKDF2 with tour == 0 */
#define AES_ERR_AUTH          2   /* wrong tag: the password is right, but the data (nonce, ciphertext, tag) was modified */
#define AES_ERR_VERSION       3   /* encrypted by another version of the program */
#define AES_ERR_MEMOIRE       4   /* malloc/calloc failed */
#define AES_ERR_ALEA          5   /* /dev/urandom or BCryptGenRandom failed */
#define AES_ERR_OUVERTURE     6   /* cannot open the file (missing, permissions) */
#define AES_ERR_TAILLE        7   /* unreadable size (pipe) or larger than GCM_TAILLE_MAX */
#define AES_ERR_FORMAT        8   /* not valid encrypted data: too small, too large, or 0 iterations in the header */
#define AES_ERR_LECTURE       9   /* fread read less than expected (or fseek failed) */
#define AES_ERR_CREATION     10   /* cannot create the .tmp (read-only folder) */
#define AES_ERR_DROITS       11   /* stat/chmod of the .tmp failed (not on Windows) */
#define AES_ERR_ECRITURE     12   /* fwrite/fclose failed (disk full...) */
#define AES_ERR_REMPLACEMENT 13   /* rename/MoveFileExA failed */
#define AES_ERR_MDP          14   /* wrong password (or salt, iterations or fingerprint modified in the header) */

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

    if (r == AES_OK)               puts("OK");
    else if (r == AES_ERR_MDP)     puts("Wrong password");
    else if (r == AES_ERR_AUTH)    puts("Tampered file");
    else if (r == AES_ERR_VERSION) puts("File encrypted with another version (unknown format)");
    else                           printf("Error %d (see the return codes)\n", r);
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

Return: `0` on success, otherwise an error code (see [Return codes](#return-codes)). On error, the original file is intact and no `.tmp` is left behind.

Decryption takes two passes: the first computes and checks the tag without writing anything; the second decrypts into `<file>.tmp`, checks the tag again, then renames.

### In-memory encryption

```c
int AES_GCM_Encrypt(uint8_t** dest, size_t* size_dest, uint8_t* src, size_t size_src, char* password);
int AES_GCM_Decrypt(uint8_t** dest, size_t* size_dest, uint8_t* src, size_t size_src, char* password);
```

| Parameter | Description |
|-----------|-------------|
| `dest` | Address of a pointer that must be `NULL`. The function allocates the result and stores its address there; the caller frees it with `free`. |
| `size_dest` | Receives the size of the result: `size_src + 81` for `AES_GCM_Encrypt`, `size_src - 81` for `AES_GCM_Decrypt`. |
| `src`, `size_src` | Input data: the plaintext (`AES_GCM_Encrypt`) or the encrypted data (`AES_GCM_Decrypt`). |
| `password` | Password, a C string terminated by `\0`. |

Return: `0` on success, otherwise an error code (see [Return codes](#return-codes)). On error, `*dest` stays `NULL`.

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
if (r == AES_OK)               printf("%s\n", (char*)plain);   /* '\0' added by AES_GCM_Decrypt */
else if (r == AES_ERR_MDP)     puts("Wrong password");
else if (r == AES_ERR_AUTH)    puts("Tampered data");
else if (r == AES_ERR_VERSION) puts("Data encrypted with another version");

free(cipher);
free(plain);   /* erase plain first if it contains secrets */
```

### Return codes

All the functions that return an `int` use the same codes, defined in `AES.h`. `0` (`AES_OK`) means success: a plain `if (r != AES_OK)` catches any error, and comparing with the names below tells which one.

The names are in French, like the rest of the code: `MEMOIRE` = memory, `ALEA` = randomness, `OUVERTURE` = opening, `TAILLE` = size, `LECTURE` = reading, `DROITS` = permissions, `ECRITURE` = writing.

| Code | Name | Meaning | Returned by |
|:----:|------|---------|-------------|
| `0` | `AES_OK` | Success | all |
| `1` | `AES_ERR_PARAM` | Bad argument: `NULL` pointer, `*dest` not `NULL`, `PBKDF2` called with `tour` = 0 | `AES_GCM_Encrypt`, `AES_GCM_Decrypt`, `AES_HMAC`, `PBKDF2` |
| `2` | `AES_ERR_AUTH` | **Modified data**: the password is right, but the tag is wrong (nonce, ciphertext or tag modified) | both decryption functions |
| `3` | `AES_ERR_VERSION` | **Unknown version**: the first byte is not `8`, for example data encrypted with V7 or earlier (see [Compatibility](#compatibility)) | both decryption functions |
| `4` | `AES_ERR_MEMOIRE` | Allocation failed (`calloc`) | all |
| `5` | `AES_ERR_ALEA` | Random generator unavailable (`/dev/urandom` or `BCryptGenRandom`) | both encryption functions |
| `6` | `AES_ERR_OUVERTURE` | File not found or not readable (`fopen` failed) | both file functions |
| `7` | `AES_ERR_TAILLE` | Unreadable size (named pipe, folder) or data larger than the maximum size (see [Known limitations](#known-limitations)) | both encryption functions; `AES_GCM_Decrypt_File` for an unreadable size |
| `8` | `AES_ERR_FORMAT` | Not valid encrypted data: fewer than 81 bytes, more than the maximum size + 81 bytes, or 0 iterations in the header | both decryption functions |
| `9` | `AES_ERR_LECTURE` | Read interrupted (`fread` or `fseek` failed, file shortened during the operation) | both file functions |
| `10` | `AES_ERR_CREATION` | Cannot create `<file>.tmp` (read-only folder, for example) | both file functions |
| `11` | `AES_ERR_DROITS` | Cannot copy the access rights to the `.tmp` (`stat` or `chmod` failed; Linux, macOS, BSD only) | both file functions |
| `12` | `AES_ERR_ECRITURE` | Write failed (`fwrite` or `fclose` failed, disk full) | both file functions |
| `13` | `AES_ERR_REMPLACEMENT` | Cannot replace the original with the `.tmp` (`rename` or `MoveFileExA` failed) | both file functions |
| `14` | `AES_ERR_MDP` | **Wrong password**: the key fingerprint does not match the one in the header. Also returned if the salt, the iteration count or the fingerprint were modified in the header | both decryption functions |

On error, nothing is modified: for files, the original is intact and no `.tmp` is left behind; in memory, `*dest` stays `NULL`.

**Wrong password (`14`) or modified data (`2`)?** Decryption makes two checks, in this order:

1. Right after PBKDF2, it recomputes the **key fingerprint** and compares it with the one in the header. If they differ, the key is wrong: code `14`. No data is read.
2. Only then does it compute the **tag** over the data. If it is wrong while the key is right, the data was modified: code `2`.

A modified salt or iteration count gives another key, hence another fingerprint: this case also answers `14`. Code `14` therefore means "wrong password, or modified header". Code `2` only appears with the right password.

```c
int r = AES_GCM_Decrypt_File("note.txt", "my password");
if (r == AES_OK)                 puts("OK");
else if (r == AES_ERR_MDP)       puts("Wrong password");
else if (r == AES_ERR_AUTH)      puts("Tampered file");
else if (r == AES_ERR_OUVERTURE) puts("File not found");
else                             printf("Error %d\n", r);
```

### Cryptographic primitives

These functions can be used on their own. The `AES_` prefix of `AES_SHA256` and `AES_HMAC` avoids a name clash with OpenSSL's `SHA256` and `HMAC` functions.

| Function | Role | Output | Return |
|----------|------|--------|--------|
| `AES_Encrypt_State(state, cle)` | Encrypts **one** 16-byte block in place with a 32-byte key. | `state` modified | — |
| `AES_Decrypt_State(state, cle)` | Decrypts a 16-byte block in place. | `state` modified | — |
| `AES_SHA256(dest, mess, size)` | SHA-256 digest of `size` bytes. | `dest`: 32 bytes | `0`, or `4` (allocation) |
| `AES_HMAC(dest, key, size_key, mess, size_mess)` | HMAC-SHA256 (key of any size). | `dest`: 32 bytes | `0`, `1` (`dest` is `NULL`) or `4` (allocation) |
| `PBKDF2(dest, password, size_password, salt, size_salt, tour)` | PBKDF2-HMAC-SHA256 with `tour` iterations (≥ 1). | `dest`: **32 bytes** (fixed size) | `0`, `1` (`dest` is `NULL` or `tour` = 0) or `4` (allocation) |

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

The format is the same for a file and for an in-memory buffer. For original data of **N** bytes, the result is **N + 81** bytes:

```
[Version - 1 B][Iteration count - 4 B][Salt - 16 B][Nonce - 12 B][Fingerprint - 32 B][Ciphertext - N B][Tag - 16 B]
```

| Position (bytes) | Size | Content |
|------------------|:----:|---------|
| `0`              | 1  | Format version: `8` |
| `1` – `4`        | 4  | PBKDF2 iteration count, 32-bit unsigned integer, most significant byte first (600,000 = `00 09 27 C0`) |
| `5` – `20`       | 16 | PBKDF2 salt, random |
| `21` – `32`      | 12 | Nonce, random |
| `33` – `64`      | 32 | Key fingerprint: HMAC-SHA256(K, `"Say thx to Tetras"`) |
| `65` – `64+N`    | N  | Ciphertext (same size as the original) |
| `65+N` – `80+N`  | 16 | Authentication tag |

Encryption writes the value of `PBKDF2_TOURS`; decryption uses the iteration count read from the file. Increasing `PBKDF2_TOURS` in a future version will therefore not make already-encrypted files unreadable.

The header is not part of the tag, but it cannot be modified without being detected: another version is refused (code `3`); another iteration count or another salt gives another key, hence another fingerprint (code `14`), just like a modified fingerprint; another nonce changes the tag mask (code `2`).

**The fingerprint does not help guess the password.** Testing a password still requires going through PBKDF2 and its 600,000 iterations, exactly as with the tag. It reveals nothing about the key either, since HMAC is one-way. It only allows a wrong password to be refused without reading the data.

---

## Internals

```
password ─────┐
              ├──►  PBKDF2-HMAC-SHA256 (iterations from the header, 600,000 when encrypting)  ──►  key K (32 bytes)
salt (16 B) ──┘

Fingerprint = HMAC-SHA256(K, "Say thx to Tetras")     compared with the header's, before reading the data
H         = AES-256(K, 0¹²⁸)                          GHASH hash key
Block i   = nonce ‖ counter (i + 2)                   32-bit counter, most significant byte first
Cipher i  = Plain i ⊕ AES-256(K, Block i)             CTR mode; last block truncated
S         = GHASH_H(cipher blocks ‖ length block)     length block = 0⁶⁴ ‖ size in bits (64 bits)
Tag       = S ⊕ AES-256(K, nonce ‖ 00 00 00 01)
```

- The **length block** prevents blocks from being added or removed without changing the tag.
- The **mask** `AES(K, nonce ‖ 1)` binds the tag to the nonce and hides the value of GHASH, hence of H.
- The **multiplication in GF(2¹²⁸)** follows the GCM convention: bits stored in reverse order, right shift and reduction by `0xE1` on the first byte (SP 800-38D, § 6.3).
- The **tag comparison** always goes through all 16 bytes and accumulates the differences (`diff |= a ^ b`) without branching: its duration does not depend on the number of correct bytes. The fingerprint (32 bytes) is compared the same way.
- The **expanded AES key** (the 60 words of the 15 round keys) is computed once per GCM function, then used for every block by `AES_Encrypt_Rondes`, and erased before every return.
- **`gf128_multiply`** stores the 16 bytes in two `uint64_t`: one XOR or shift then handles 8 bytes at once.
- **PBKDF2**: at each iteration, HMAC hashes `key ⊕ ipad` and `key ⊕ opad`, two blocks that depend only on the password. Their SHA-256 compression is therefore computed once at the start: each iteration then needs only 2 compressions instead of 4.

### Code organization

| Module | Functions |
|--------|-----------|
| AES – rounds | `addRoundKey`, `SubBytes` / `InvSubBytes`, `ShiftRows` / `InvShiftRows` (via `push` / `pop`), `MixColumns` / `InvMixColumns` (via `xtime` / `mul` in GF(2⁸)) |
| AES – keys | `Explode` (key → 8 words), `GenerateKey` (60 words), `RotWord`, `SubWord` |
| AES – blocks | `AES_Encrypt_Rondes` (14 rounds with an already expanded key), `AES_Encrypt_State` (expansion + rounds + erasure), `AES_Decrypt_State` |
| GCM | `ConterBlockGenerator` (counter block), `gf128_multiply` (multiplication in GF(2¹²⁸)), `AES_GCM_Encrypt_File`, `AES_GCM_Decrypt_File`, `AES_GCM_Encrypt`, `AES_GCM_Decrypt` |
| SHA-256 | `padding`, `compressing`, `ROTR`, `choose`, `majority`, `SIG0`, `SIG1`, `sig0`, `sig1`, `AES_SHA256` |
| Key derivation | `AES_HMAC`, `PBKDF2` |
| Utility | `uint8_tToZero` (memory erasure that the compiler cannot remove), `uint8TOuint64` / `uint64TOuint8` (8 bytes ↔ one `uint64_t`, most significant byte first) |

### Parameters

| Parameter | Value | Where |
|-----------|-------|-------|
| Format version | 8 (first byte of the header) | `#define VERSION` |
| Fingerprint message | `"Say thx to Tetras"` (17 ASCII bytes, without the `'\0'`) | `#define VERIF_MESSAGE` |
| Fingerprint size | 32 bytes (HMAC-SHA256) | `AES_GCM_*` |
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
| Complete file (header, salt, nonce, fingerprint, ciphertext, tag) | Python (`hashlib`, `hmac` and `AESGCM` from `cryptography`) reads the header, recomputes the fingerprint and decrypts files of 0 to 100,000 bytes; files built by Python, with 600,000 and 1,000 iterations, are decrypted | ✅ |
| In-memory encrypted data | Same comparison with Python, from 0 to 1,000 bytes, with 600,000 and 1,000 iterations | ✅ |
| `gf128_multiply` on two `uint64_t` | 1,000,000 random multiplications compared with the former byte-by-byte version: 0 differences | ✅ |
| `AES_Encrypt_Rondes` (key expanded once) | FIPS-197 C.3, and 100,000 blocks compared with `AES_Encrypt_State`: 0 differences | ✅ |

File tests (encryption → decryption round trip):

| Scenario | Result |
|----------|:------:|
| Files of 0, 1, 15, 16, 17, 1,000 and 100,000 bytes: content restored identically, size + 81 bytes, header `08 00 09 27 C0` | ✅ |
| Wrong password → code `14` in ≈ 1.4 s (4 MiB file as well as 40 MiB), file intact, no `.tmp` | ✅ |
| Each byte of an encrypted file modified one at a time: version → code `3`; iteration count, salt and fingerprint → code `14`; nonce, ciphertext and tag → code `2`; file never modified, no `.tmp` (the most significant byte of the iteration count is not tested: it would require 16 million iterations, same case as the others) | ✅ |
| File encrypted with V7 (81 bytes or more) → code `3`, intact; version byte set to `9` → code `3` | ✅ |
| Iteration count of 0 → code `8`, intact | ✅ |
| File smaller than 81 bytes, empty file → code `8`; missing file → code `6` | ✅ |
| Full disk (simulated with `ulimit -f`) during encryption or decryption → code `12`, original intact, no `.tmp` | ✅ |
| File in mode `600` → still `600` after encryption and decryption | ✅ |
| Unreadable size (`ftell` returns `-1`, simulated with a named pipe) or a folder instead of a file → code `7`, nothing is modified | ✅ |
| File one byte larger than the maximum size (68,719,476,705 bytes, sparse file) → code `7`, intact, no `.tmp`; the maximum size (68,719,476,704 bytes) is accepted | ✅ |
| Encrypted file larger than the maximum size + 81 bytes → code `8` on decryption, intact; the maximum size + 81 bytes is accepted | ✅ |
| Read-only folder → code `10`, original intact | ✅ |
| Simulated failures: each system call (`calloc`, `fopen`, `fread`, `fwrite`, `fclose`, `fseek`, `stat`, `chmod`, `rename`) made to fail one at a time, 65 cases → the expected code, original intact, no `.tmp` (a failed `fclose` on a file that was only read does not change the result) | ✅ |
| No copy of the key or of the expanded key on the stack after `AES_GCM_Encrypt_File` and `AES_GCM_Decrypt_File`, including after a wrong password (checked at `-O0` and `-O2`, with a control copy without erasure that does leave copies) | ✅ |

In-memory tests:

| Scenario | Result |
|----------|:------:|
| Round trip of 0, 1, 15, 16, 17, 1,000 and 100,000 bytes: identical content, trailing `'\0'`, size + 81 bytes | ✅ |
| Wrong password → code `14`, `*dest` stays `NULL` | ✅ |
| Each byte modified one at a time: version → code `3`; iteration count, salt and fingerprint → code `14`; nonce, ciphertext and tag → code `2` | ✅ |
| Data in V7 format → code `3`; iteration count of 0 → code `8` | ✅ |
| Smaller than 81 bytes → code `8`; `NULL` parameter or `*dest` already set → code `1` | ✅ |
| Declared size larger than the maximum size (with a small buffer) → code `7` on encryption, `8` on decryption, before any read, `*dest` stays `NULL` | ✅ |
| Simulated failures: each `calloc` and each access to `/dev/urandom` made to fail one at a time, 20 cases → code `4` or `5`, `*dest` stays `NULL` | ✅ |
| Data encrypted in memory, written to a file, then read back by `AES_GCM_Decrypt_File`, and vice versa | ✅ |
| No copy of the key or of the expanded key on the stack after `AES_GCM_Encrypt` and `AES_GCM_Decrypt`, including after a wrong password (checked at `-O0` and `-O2`) | ✅ |
| After `AES_HMAC`, neither the key XOR `ipad` nor the inner hash remains on the stack or in freed memory | ✅ |

All scenarios pass under `valgrind` with no errors and no memory leaks.

**Windows:** `AES.c` and the example above compile with MinGW-w64 (x86_64) without warnings (`-Wall -Wextra -pedantic`). The tests above have not yet been run on Windows.

### Compatibility

After the header, the format follows the AES-256-GCM standard: with the PBKDF2 key (same password, same salt, same iteration count, read from the header), any compliant GCM implementation can decrypt the data, and vice versa.

**Files encrypted with V7:** V8 adds the key fingerprint (32 bytes) to the header, so the format changes. V8 refuses V7 files (code `3`, file intact), and V7 refuses V8 files (code `3` as well, file intact). To keep them: decrypt them with V7, then encrypt them again with V8.

> [!NOTE]
> V8 checks the size before the version: a V7 file smaller than 81 bytes (less than 32 bytes of text) is refused with code `8` instead of `3`. The file stays intact in both cases.

**Files encrypted with V5 or V6:** they have no header (version and iteration count). V8 refuses them (code `3`, or `8` if they are smaller than 81 bytes; file intact), and V6 refuses V8 files (code `2`, file intact). To keep them: decrypt them with V6, then encrypt them again with V8.

> [!NOTE]
> The first byte of a V5 or V6 file is the start of its salt, hence random: one file in 256 starts with byte `8`. V8 then reads it as a V8 file, with an iteration count taken from the following bytes of the salt (often several billion): decryption may take hours before answering `14`. Decrypting such files with V6 avoids this case.

**Files encrypted with V4 or earlier:** also refused (code `3` or `8`, with the same one-in-256 case): decrypt them with the version that created them.

---

## Performance

Indicative measurements (`gcc -O2`, Raspberry Pi 4 Model B at 1.8 GHz, Linux; median of 3 runs for V7 and V8):

| Operation | V8 | V7 | V6 | V5 |
|-----------|----|----|----|----|
| PBKDF2 key derivation (600,000 iterations), on every encryption or decryption | ≈ 1.4 s | ≈ 1.4 s | ≈ 1.4 s | ≈ 2.9 s |
| Encrypting a 4 MiB file | ≈ 2.1 s | ≈ 3.9 s | ≈ 3.8 s | ≈ 5.3 s |
| Decrypting a 4 MiB file (two passes) | ≈ 2.3 s | ≈ 5.7 s | ≈ 5.5 s | ≈ 7.0 s |
| Data only, excluding PBKDF2 | encryption ≈ 5.7 MiB/s, decryption ≈ 4.5 MiB/s | encryption ≈ 1.6 MiB/s, decryption ≈ 0.9 MiB/s | — | — |
| Rejecting a wrong password, 4 MiB file | ≈ 1.4 s | ≈ 3.1 s | — | — |
| Rejecting a wrong password, 40 MiB file | ≈ 1.4 s | ≈ 18.8 s | — | — |

V8 processes data 3.5 times faster on encryption and 5 times faster on decryption (excluding PBKDF2), thanks to two changes that do not alter the result:

- `gf128_multiply` (the tag computation) works on two 64-bit numbers instead of 16 bytes: one XOR or shift handles 8 bytes at once. It is ≈ 9 times faster (0.18 s instead of 1.7 s for 4 MiB). Decryption benefits twice, since it computes the tag in each of its two passes;
- the AES key expansion (the 60 round-key words) is done once per function, instead of once per 16-byte block.

PBKDF2 has not changed: it now accounts for two thirds of the time for 4 MiB.

A wrong password is now refused right after PBKDF2, thanks to the key fingerprint stored in the header. V7 first had to read all the data to compute the tag.

The V6 speed-up comes only from PBKDF2 (see [Internals](#internals)): data processing itself has not changed (≈ 2.5 s to encrypt 4 MiB, ≈ 4.3 s to decrypt it, excluding PBKDF2). V7 only changes the header (5 bytes) and adds the erasure of HMAC and SHA-256 intermediate values: it performs the same computations as V6, and measurement differences stay below 0.2 s.

The duration of key derivation is proportional to the iteration count read from the file: twice as many iterations, twice the time.

The code stays simple rather than as fast as possible:

- `gf128_multiply` still walks through the 128 bits one at a time (on two `uint64_t`), without precomputed tables or the processor's multiplication instruction;
- AES is computed byte by byte (`SubBytes`, `ShiftRows`, `MixColumns`), without precomputed tables or the processor's AES instructions.

---

## Known limitations

**Security**

- The iteration count read from a file is not capped (by choice): a modified file can request up to 4,294,967,295 iterations, i.e. ≈ 2 h 45 of computation on a Raspberry Pi 4 before being refused (code `14`). Nothing is read or written during that time, and the file stays intact.
- Code `14` does not tell a wrong password apart from a modified header (salt, iteration count or fingerprint): in both cases, the computed key does not match the fingerprint. Code `2`, on the other hand, is certain: it only happens with the right password.
- PBKDF2, `AES_HMAC` and `AES_SHA256` erase their intermediate values, but two traces may remain: the SHA-256 working variables (`W` and `a` to `h` in `compressing`) stay on the stack, because erasing them would slow down PBKDF2, which calls `compressing` 1.2 million times; and a copy may remain in the processor's registers after a `memcpy`, which C cannot erase. The password itself remains the caller's responsibility.
- No additional authenticated data (AAD).

**Robustness**

- An existing `<file>.tmp` is overwritten without warning.
- Maximum data size: 68,719,476,704 bytes (≈ 64 GiB), for a file as well as in memory, on Linux as well as on Windows. This is the limit of GCM itself (NIST SP 800-38D): the counter is only 32 bits, and beyond that the same masks would be reused. The four `AES_GCM_*` functions refuse a larger size (code `7` on encryption, `8` on decryption) without modifying anything. Going further would require splitting the data into several GCM messages (a new file format).
- No file of this size has been encrypted in full during the tests (≈ 3 h 15 of encryption and ≈ 4 h of decryption on a Raspberry Pi 4 with V8, extrapolated from the 4 MiB measurements): the limits were checked on sparse files, and the counter blocks beyond 2³¹ compared with Python.
- The internal functions (`padding`, `compressing`, `push`, `pop`, `mul`…) are global and have generic names: possible clash with another library linked into the same program. Declaring them `static` would solve the problem.

**Windows** (expected behaviour, not yet tested on a Windows machine)

- A read-only file is refused (code `13`, intact): Windows refuses to replace it.
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
