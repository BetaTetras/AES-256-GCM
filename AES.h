#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

/* Chiffrement de fichiers (API principale) */
int AES_GCM_Encrypt_File(char* path, char* password);
int AES_GCM_Decrypt_File(char* path, char* password);

/* Primitives */
void AES_Encrypt_State(uint8_t state[4][4], uint8_t const cle[32]);
void AES_Decrypt_State(uint8_t state[4][4], uint8_t const cle[32]);
int  SHA256(uint8_t* dest, uint8_t* mess, size_t size);
int  HMAC(uint8_t* dest, uint8_t* key, size_t size_key, uint8_t* mess, size_t size_mess);
int  PBKDF2(uint8_t* dest, char* password, size_t size_password,
            uint8_t* salt, size_t size_salt, size_t tour);

#endif
