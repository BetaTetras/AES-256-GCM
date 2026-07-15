#ifndef AES256_H
#define AES256_H
#include <stdint.h>

/* ============================================================
 *  AES-256 Library Header
 *  Implémentation d'AES-256 (ECB mode)
 * ============================================================ */

#define MA_CLE {0x00, 0x01, 0x02, 0x03, \
                0x04, 0x05, 0x06, 0x07, \
                0x08, 0x09, 0x0a, 0x0b, \
                0x0c, 0x0d, 0x0e, 0x0f, \
                0x10, 0x11, 0x12, 0x13, \
                0x14, 0x15, 0x16, 0x17, \
                0x18, 0x19, 0x1a, 0x1b, \
                0x1c, 0x1d, 0x1e, 0x1f}

typedef uint8_t word[4];

extern const uint8_t SBOX[256];
extern const uint8_t INV_SBOX[256];
extern const uint8_t RCON[11];


void initStateDebugAlpha(uint8_t state[4][4]);
void initStateDebugBeta(uint8_t state[4][4]);

void printState(uint8_t state[4][4]);
void printWord(word w, int index);
void debugGenerateKey(word finaleW[60]);

void addRoundKey(uint8_t state[4][4], word rondKey[4]);

void SubBytes(uint8_t state[4][4]);
void InvSubBytes(uint8_t state[4][4]);

void ShiftRows(uint8_t state[4][4]);
void InvShiftRows(uint8_t state[4][4]);

void MixColumns(uint8_t state[4][4]);
void InvMixColumns(uint8_t state[4][4]);
void push(uint8_t ligne[4], int x);
void pop(uint8_t ligne[4], int x);

void RotWord(uint8_t ligne[4]);
void SubWord(uint8_t ligne[4]);
uint8_t xtime(uint8_t octet);
uint8_t mul(uint8_t a, uint8_t b);
void Explode(uint8_t cle[32], word w[8]);
void GenerateKey(word finaleW[60], word initialW[8]);


void AES_Encrypt_state(uint8_t state[4][4], uint8_t cle[32]);
void AES_Decrypt_state(uint8_t state[4][4], uint8_t cle[32]);

void fileBinaryTrancription(uint8_t (*dest)[4][4], char* path);

#endif /* AES256_H */