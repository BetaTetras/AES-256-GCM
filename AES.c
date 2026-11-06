#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <string.h>
#ifdef _WIN32
#include <windows.h>
#include <bcrypt.h>
#else
#include <sys/stat.h>
#endif
#include "AES.h"

typedef uint8_t word[4];

static const uint8_t SBOX[256] = {
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
};

static const uint8_t INV_SBOX[256] = {
    0x52,0x09,0x6a,0xd5,0x30,0x36,0xa5,0x38,0xbf,0x40,0xa3,0x9e,0x81,0xf3,0xd7,0xfb,
    0x7c,0xe3,0x39,0x82,0x9b,0x2f,0xff,0x87,0x34,0x8e,0x43,0x44,0xc4,0xde,0xe9,0xcb,
    0x54,0x7b,0x94,0x32,0xa6,0xc2,0x23,0x3d,0xee,0x4c,0x95,0x0b,0x42,0xfa,0xc3,0x4e,
    0x08,0x2e,0xa1,0x66,0x28,0xd9,0x24,0xb2,0x76,0x5b,0xa2,0x49,0x6d,0x8b,0xd1,0x25,
    0x72,0xf8,0xf6,0x64,0x86,0x68,0x98,0x16,0xd4,0xa4,0x5c,0xcc,0x5d,0x65,0xb6,0x92,
    0x6c,0x70,0x48,0x50,0xfd,0xed,0xb9,0xda,0x5e,0x15,0x46,0x57,0xa7,0x8d,0x9d,0x84,
    0x90,0xd8,0xab,0x00,0x8c,0xbc,0xd3,0x0a,0xf7,0xe4,0x58,0x05,0xb8,0xb3,0x45,0x06,
    0xd0,0x2c,0x1e,0x8f,0xca,0x3f,0x0f,0x02,0xc1,0xaf,0xbd,0x03,0x01,0x13,0x8a,0x6b,
    0x3a,0x91,0x11,0x41,0x4f,0x67,0xdc,0xea,0x97,0xf2,0xcf,0xce,0xf0,0xb4,0xe6,0x73,
    0x96,0xac,0x74,0x22,0xe7,0xad,0x35,0x85,0xe2,0xf9,0x37,0xe8,0x1c,0x75,0xdf,0x6e,
    0x47,0xf1,0x1a,0x71,0x1d,0x29,0xc5,0x89,0x6f,0xb7,0x62,0x0e,0xaa,0x18,0xbe,0x1b,
    0xfc,0x56,0x3e,0x4b,0xc6,0xd2,0x79,0x20,0x9a,0xdb,0xc0,0xfe,0x78,0xcd,0x5a,0xf4,
    0x1f,0xdd,0xa8,0x33,0x88,0x07,0xc7,0x31,0xb1,0x12,0x10,0x59,0x27,0x80,0xec,0x5f,
    0x60,0x51,0x7f,0xa9,0x19,0xb5,0x4a,0x0d,0x2d,0xe5,0x7a,0x9f,0x93,0xc9,0x9c,0xef,
    0xa0,0xe0,0x3b,0x4d,0xae,0x2a,0xf5,0xb0,0xc8,0xeb,0xbb,0x3c,0x83,0x53,0x99,0x61,
    0x17,0x2b,0x04,0x7e,0xba,0x77,0xd6,0x26,0xe1,0x69,0x14,0x63,0x55,0x21,0x0c,0x7d,
};

static const uint8_t RCON[11] = {
    0x00, // non utilisé
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1b, 0x36
};

// SHA-256
#define HASH_CONST {0x6a09e667,0xbb67ae85 ,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}
#define PBKDF2_TOURS 600000

#define VERSION 8

/* GCM : taille maximale d'un message (NIST SP 800-38D), 68 719 476 704 octets (~64 Go).
 * Le compteur de ConterBlockGenerator ne fait que 4 octets (0 à 4 294 967 295) :
 *   - 0 n'est jamais utilisé, 1 sert au masque de la signature,
 *   - 2 à 4 294 967 295 servent aux données : 4 294 967 294 morceaux de 16 octets.
 * Au-delà, le compteur repartirait à 0 et les mêmes masques resserviraient :
 * chiffré1 XOR chiffré2 = clair1 XOR clair2, et la signature deviendrait falsifiable.
 */
#define GCM_TAILLE_MAX ((uint64_t)(UINT32_MAX - 1) * 16)

#define VERIF_MESSAGE "Say thx to Tetras"

static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

void addRoundKey(uint8_t state[4][4], word rondKey[4]);

void SubBytes(uint8_t state[4][4]);
void InvSubBytes(uint8_t state[4][4]);

void ShiftRows(uint8_t state[4][4]);
void InvShiftRows(uint8_t state[4][4]);
void push(uint8_t ligne[4],int x);
void pop(uint8_t ligne[4], int x);

uint8_t xtime(uint8_t a);
uint8_t mul(uint8_t a, uint8_t b);
void MixColumns(uint8_t state[4][4]);
void InvMixColumns(uint8_t state[4][4]);

void RotWord(uint8_t ligne[4]);
void SubWord(uint8_t ligne[4]);
void Explode(const uint8_t cle[32],word w[8]);
void GenerateKey(word finaleW[60],word initialW[8]);

void AES_Encrypt_Rondes(uint8_t state[4][4], word GenratedKey[60]);
void AES_Encrypt_State(uint8_t state[4][4], uint8_t const cle[32]);
void AES_Decrypt_State(uint8_t state[4][4], uint8_t const cle[32]);

// SHA-256
int padding(uint8_t** dest,uint8_t* mess,size_t* size);
void compressing(uint32_t H[8], uint8_t* mess);
uint32_t ROTR(uint32_t num, size_t numberOfPush);
uint32_t choose(uint32_t x, uint32_t y, uint32_t z);
uint32_t majority(uint32_t x, uint32_t y, uint32_t z);
uint32_t SIG0(uint32_t x);
uint32_t SIG1(uint32_t x);
uint32_t sig0(uint32_t x);
uint32_t sig1(uint32_t x);
int AES_SHA256(uint8_t* dest, uint8_t* mess, size_t size);
int AES_HMAC(uint8_t* dest,uint8_t* key,size_t size_key,uint8_t* mess,size_t size_mess);
int PBKDF2(uint8_t* dest,char* password,size_t size_password,uint8_t* salt,size_t size_salt,size_t tour);

void ConterBlockGenerator(uint8_t state[4][4], uint8_t nonce[12],uint32_t compteur);
void gf128_multiply(uint8_t res[16],const uint8_t a[16],const uint8_t b[16]);
uint64_t uint8TOuint64(const uint8_t octets[8]);
void uint64TOuint8(uint8_t octets[8],const uint64_t nombre);

int AES_GCM_Encrypt(uint8_t** dest,size_t* size_dest,uint8_t* src,size_t size_src,char* password);
int AES_GCM_Decrypt(uint8_t** dest,size_t* size_dest,uint8_t* src,size_t size_src,char* password);

int AES_GCM_Encrypt_File(char* path,char* password);
int AES_GCM_Decrypt_File(char* path,char* password);

void uint8_tToZero(uint8_t* p_uint8_t,size_t size);

/* STATE (Etat)
 * Le state est la matrice de donnée de 4*4 octet qui contien
 * les 16 bytes de donnée a chiffrée.
 * Exemple :
 * 0x00 0x04 0x08 0x0c
 * 0x01 0x05 0x09 0x0d
 * 0x02 0x06 0x0a 0x0e
 * 0x03 0x07 0x0b 0x0f
*/

/* WORD (Mot)
 * Un Word (Mot) contien 4 octet. C'est l'unitée utilisée de base
 * de la clé AED, Il joue le rôle segment de cette même clé.
 * Grace a cette unitée on peut en générée des suplémentaire
 * Exemple :
 * 0x01 0x02 0x03 0x04 = W[0]
*/

//////////////////////////////////////////////////////////

// Effectue une addition XOR entre l'état et une clé de ronde
void addRoundKey(uint8_t state[4][4], word rondKey[4]){
    for(int i=0;i<4;i++){      // i = ligne
        for(int y=0;y<4;y++){  // y = colonne
            state[i][y] = state[i][y] ^ rondKey[y][i];
        }
    }
}

//////////////////////////////////////////////////////////

// Remplace chaque octet par sa valeur dans la S-BOX (table de substitution)
void SubBytes(uint8_t state[4][4]){
    for(int i=0;i<4;i++){
        for(int y=0;y<4;y++){
            state[i][y] = SBOX[state[i][y]];
        }
    }
}

void InvSubBytes(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++){
        for (int y = 0; y < 4; y++){
            state[i][y] = INV_SBOX[state[i][y]];
        }
    }
}

//////////////////////////////////////////////////////////

// Décale les éléments de chaque ligne vers la gauche (rotation).
void ShiftRows(uint8_t state[4][4]){
    for(int i=0;i<4;i++){   
        push(state[i],i);
    }
}

void InvShiftRows(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++)
        pop(state[i], i);
}

// Effectue x rotations circulaires vers la gauche sur une ligne.
void push(uint8_t ligne[4],int x){
    uint8_t buffeur;
    for(int i=0;i<x;i++){
        buffeur = ligne[0];
        for(int y=1;y<4;y++){
            ligne[y-1] = ligne[y];
        }
        ligne[3] = buffeur;
    }
}

// Effectue x rotations circulaires vers la droite sur une ligne.
void pop(uint8_t ligne[4], int x) {
    uint8_t buffeur;
    for (int i = 0; i < x; i++) {
        buffeur = ligne[3];
        for (int y = 3; y > 0; y--)
            ligne[y] = ligne[y-1];
        ligne[0] = buffeur;
    }
}
//////////////////////////////////////////////////////////

// Multiplie par 2 dans le corps de Galois GF(2^8).
uint8_t xtime(uint8_t octet){
    if(octet & 0x80){
        return (octet << 1) ^ 0x1b;
    }else{
        return octet << 1;
    }
}

// Multiplie deux octets dans GF(2^8) en utilisant des xtime répétées.
uint8_t mul(uint8_t a, uint8_t b) {
    uint8_t result = 0;
    for (int i = 0; i < 8; i++) {
        if (b & 1) result ^= a;
        a = xtime(a);
        b >>= 1;
    }
    return result;
}

// Effectue une transformation linéaire sur chaque colonne de la matrice d'état. 
void MixColumns(uint8_t state[4][4]){
    for (int i = 0; i < 4; i++){
        uint8_t a0 = state[0][i];
        uint8_t a1 = state[1][i];
        uint8_t a2 = state[2][i];
        uint8_t a3 = state[3][i];

        state[0][i] = xtime(a0) ^ xtime(a1) ^ a1 ^ a2 ^ a3;
        state[1][i] = a0 ^ xtime(a1) ^ xtime(a2) ^ a2 ^ a3;
        state[2][i] = a0 ^ a1 ^ xtime(a2) ^ xtime(a3) ^ a3;
        state[3][i] = xtime(a0) ^ a0 ^ a1 ^ a2 ^ xtime(a3);
    }
}

void InvMixColumns(uint8_t state[4][4]) {
    for (int i = 0; i < 4; i++) {
        uint8_t a0 = state[0][i];
        uint8_t a1 = state[1][i];
        uint8_t a2 = state[2][i];
        uint8_t a3 = state[3][i];

        state[0][i] = mul(0x0e,a0) ^ mul(0x0b,a1) ^ mul(0x0d,a2) ^ mul(0x09,a3);
        state[1][i] = mul(0x09,a0) ^ mul(0x0e,a1) ^ mul(0x0b,a2) ^ mul(0x0d,a3);
        state[2][i] = mul(0x0d,a0) ^ mul(0x09,a1) ^ mul(0x0e,a2) ^ mul(0x0b,a3);
        state[3][i] = mul(0x0b,a0) ^ mul(0x0d,a1) ^ mul(0x09,a2) ^ mul(0x0e,a3);
    }
}

//////////////////////////////////////////////////////////

// Remplace chaque octet d'un mot par son équivalent dans la S-BOX.
void SubWord(uint8_t ligne[4]){
    for(int i=0;i<4;i++){
        ligne[i] = SBOX[ligne[i]];
    }
} 

// Effectue une rotation circulaire d'un mot vers la gauche.
void RotWord(uint8_t ligne[4]){
    push(ligne,1);
}


void Explode(const uint8_t cle[32],word w[8]){
    int indexWord = -1;
    int indexOctet = -1;
    for(int i=0;i<32;i++){
        if(i % 4 == 0){
            indexWord ++;
            indexOctet=0;
        }
        w[indexWord][indexOctet] = cle[i];
        indexOctet ++;
    }
}


void GenerateKey(word finaleW[60],word initialW[8]){
    for(int i=0;i<8;i++){
        for(int y=0;y<4;y++){
            finaleW[i][y] = initialW[i][y];
        }
    }

    for(int i=8;i<60;i++){
        if(i % 8 == 0){
            word buffeurW;
            for(int y=0;y<4;y++){
                buffeurW[y] = finaleW[i-1][y];
            }
            RotWord(buffeurW);
            SubWord(buffeurW);
            buffeurW[0] = buffeurW[0] ^ RCON[i/8];
            for(int x=0;x<4;x++){
                finaleW[i][x] = buffeurW[x] ^ finaleW[i-8][x];
            }
        }else if(i % 8 == 4){
            word buffeurW;
            for(int y=0;y<4;y++){
                buffeurW[y] = finaleW[i-1][y];
            }
            SubWord(buffeurW);
            for(int x=0;x<4;x++){
                finaleW[i][x] = buffeurW[x] ^ finaleW[i-8][x];
            }
        }else{
            for(int y=0;y<4;y++){
                finaleW[i][y] = finaleW[i-1][y] ^ finaleW[i-8][y];
            }
        }
    }
}

//////////////////////////////////////////////////////////

/* Les 14 rondes d'AES-256 avec une clé DÉJÀ étendue (les 60 mots de GenerateKey).
 * Pas d'expansion ni d'effacement ici : c'est l'appelant qui fabrique
 * GenratedKey une seule fois, s'en sert pour tous ses blocs, puis l'efface.
 * C'est ce que font les fonctions GCM : la clé est la même pour tout le fichier,
 * refaire l'expansion à chaque bloc de 16 octets coûtait 28 % du temps d'AES.
 */
void AES_Encrypt_Rondes(uint8_t state[4][4], word GenratedKey[60]){
    addRoundKey(state, GenratedKey);
    for(int i=1;i<=13;i++){
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        addRoundKey(state, GenratedKey + i*4);
    }
    SubBytes(state);
    ShiftRows(state);
    addRoundKey(state, GenratedKey + 56);
}

/* Version publique (AES.h) : prend la clé de 32 octets et fait elle-même
 * l'expansion, puis l'efface. Pratique pour chiffrer un bloc seul ; pour
 * beaucoup de blocs avec la même clé, AES_Encrypt_Rondes évite de refaire
 * l'expansion à chaque fois.
 */
void AES_Encrypt_State(uint8_t state[4][4], uint8_t const cle[32]){
    word ExplodedKey[8];
    Explode(cle,ExplodedKey);
    word GenratedKey[60];
    GenerateKey(GenratedKey,ExplodedKey);

    AES_Encrypt_Rondes(state, GenratedKey);

    // Efface les copies de la clé (GenratedKey commence par la clé)
    uint8_tToZero((uint8_t*)ExplodedKey, sizeof(ExplodedKey));
    uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
}

void AES_Decrypt_State(uint8_t state[4][4], uint8_t const cle[32]) {
    word ExplodedKey[8];
    Explode(cle, ExplodedKey);
    word GeneratedKey[60];
    GenerateKey(GeneratedKey, ExplodedKey);

    // Dernière sous-clé en premier (W[56..59])
    addRoundKey(state, GeneratedKey + 56);

    for (int i = 13; i >= 1; i--) {
        InvShiftRows(state);
        InvSubBytes(state);
        addRoundKey(state, GeneratedKey + i*4);
        InvMixColumns(state);
    }

    // Ronde initiale (sans InvMixColumns)
    InvShiftRows(state);
    InvSubBytes(state);
    addRoundKey(state, GeneratedKey);  // W[0..3]

    // Efface les copies de la clé (GeneratedKey commence par la clé)
    uint8_tToZero((uint8_t*)ExplodedKey, sizeof(ExplodedKey));
    uint8_tToZero((uint8_t*)GeneratedKey, sizeof(GeneratedKey));
}

//////////////////////////////////////////////////////////

void ConterBlockGenerator(uint8_t state[4][4], uint8_t nonce[12],uint32_t compteur){
    uint8_t buffer[16];
    memcpy(buffer, nonce, 12);

    /* Pour transformée un nombre (compteur) en 4 octet pour la suite du code
     * il faut extraire les 4 octet que constitue le compteur (un uint32_t).
     * 
     * Pourquoi faire un décallage de x octete ( >> 24 ) :
     *  Compteur original:
     *   [0x12] [0x34] [0x56] [0x78]
     *      ^
     *   Cet octet, je veux l'extraire
     *
     *   Décale >> 24:
     *   [0x12] [0x34] [0x56] [0x78]  →  [0x00] [0x00] [0x00] [0x12]
     *                                                           ^
     *                                               Maintenant c'est à la porte !
     * Pourquoi & 0xff : 
     * Rappelle : & = et , 0xff = 255 = 11111111
     *  Masque & 0xff:
     *   [0x00] [0x00] [0x00] [0x12]  →  [0x12]
     *                                      ^
     *                                  Je gardes juste ça
     *
    */
    buffer[12] = ((uint32_t) compteur >> 24) & 0xff;
    buffer[13] = ((uint32_t) compteur >> 16) & 0xff;
    buffer[14] = ((uint32_t) compteur >> 8) & 0xff;
    buffer[15] = ((uint32_t) compteur >> 0) & 0xff;

    int index = 0;
    for(int colonne = 0; colonne < 4; colonne++){
        for(int ligne = 0; ligne < 4; ligne++){
            state[ligne][colonne] = buffer[index++];
        }
    }
}

void gf128_multiply(uint8_t res[16],const uint8_t a[16],const uint8_t b[16]){
    // 1. On charge uint_8 a[16] et uint_8 b[16] dans des uint_64 pout eviter des boucle
    uint64_t ah = uint8TOuint64(a);
    uint64_t al = uint8TOuint64(a + 8);

    uint64_t bh = uint8TOuint64(b);
    uint64_t bl = uint8TOuint64(b + 8);

    // 2. on défini rh et rl (r = res)
    uint64_t rh = 0;
    uint64_t rl = 0;

    // 3. La boucle de la mort
    for(int i=0;i<128;i++){
        // a. Lire le bit n°i de b
        int bit;
        if(i<64){
            bit = (bh >> (63 - i)) & 1;
        }else{
            bit = (bl >> (127 - i)) & 1;
        }

        // b. Si le bit vaut 1, ajouter a au résultat
        if(bit){
            rh ^= ah;
            rl ^= al;
        }

        // c. Lire le bit qui va sortir, avant de décaler
        uint64_t lsb = al & 1;

        // d. Décaler a d'un bit vers la droite
        al = (al >> 1) | (ah << 63);
        ah = ah >> 1;

        // e. Si un bit est sorti, le replier
        if(lsb){
            ah ^= ((uint64_t)0xE1 << 56);
        }
    }
    uint64TOuint8(res,rh);
    uint64TOuint8(res+8,rl);
    return;
}

uint64_t uint8TOuint64(const uint8_t octets[8]){
    uint64_t nombre = 0;
    for(int i=0;i<8;i++){
        nombre = (nombre << 8) | octets[i];
    }

    return nombre;
}

void uint64TOuint8(uint8_t octets[8],const uint64_t nombre){
    for(int i = 0; i < 8; i++){
        octets[i] = (nombre >> (56 - 8 * i)) & 0xff;
    }
}

int AES_GCM_Encrypt_File(char* path,char* password){
    // GENERATION DE LA NONCE ET DU SEL
    uint8_t nonce[12];
    uint8_t salt[16];
    #ifdef _WIN32
        /* Windows n'a pas de /dev/urandom : c'est BCryptGenRandom qui donne
        * le hasard du système. Il renvoie 0 quand tout s'est bien passé. */
        if(BCryptGenRandom(NULL, nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0){
            return AES_ERR_ALEA;
        }
        if(BCryptGenRandom(NULL, salt, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0){
            return AES_ERR_ALEA;
        }
    #else
        FILE *f = fopen("/dev/urandom", "rb");
        if(f == NULL){
            return AES_ERR_ALEA;
        }

        if(fread(nonce, sizeof(uint8_t), 12, f) != 12){
            fclose(f);
            return AES_ERR_ALEA;
        }
        if(fread(salt,sizeof(uint8_t), 16, f) != 16){
            fclose(f);
            return AES_ERR_ALEA;
        }
        fclose(f);
    #endif

    // CREATION DE LA CLE AVEC PBKDF2
    uint8_t key[32];
    word GenratedKey[60];
    size_t size_password = strlen(password);
    /* On garde le code de PBKDF2 (AES_ERR_MEMOIRE ou AES_ERR_PARAM) et on le
     * renvoie tel quel : l'appelant sait ce qui a raté, au lieu d'un code général.
     * != AES_OK et pas == 1 : sinon un code 4 passerait sans être vu. */
    int code = PBKDF2(key,password,size_password,salt,16,PBKDF2_TOURS);
    if(code != AES_OK){
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return code;
    }

    uint8_t verif[32];
    code = AES_HMAC(verif, key, 32, (uint8_t*)VERIF_MESSAGE, sizeof(VERIF_MESSAGE) - 1);
    if(code != AES_OK){
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return code;
    }

    word ExplodedKey[8];
    Explode(key, ExplodedKey);
    GenerateKey(GenratedKey, ExplodedKey);
    uint8_tToZero((uint8_t*)ExplodedKey, sizeof(ExplodedKey));

    // LECTURE DU FICHIER BRUT (sans padding)
    FILE* file_in = fopen(path, "rb");
    if(!file_in){
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_OUVERTURE;
    }
    #ifdef _WIN32
        /* Sous Windows, un long ne fait que 32 bits : ftell ne sait pas dépasser
        * 2 Go et renvoie -1. _fseeki64/_ftelli64 font la même chose avec un
        * long long (8 octets), comme le long de Linux. */
        int seek = _fseeki64(file_in, 0, SEEK_END);
        long long filesize = _ftelli64(file_in);
    #else
        int seek = fseek(file_in, 0, SEEK_END);
        long long filesize = ftell(file_in);
    #endif

    /* ftell renvoie -1 quand il ne peut pas donner la taille. Exemple : un
     * tube (FIFO), qui n'a pas de taille.
     * Sans ce test, NbState vaudrait 0 : rien ne serait lu, et le fichier
     * serait remplacé par 81 octets (en-tête + signature) sans les données.
     *
     * seek != 0 : si fseek rate, on n'est pas allé à la fin et ftell renvoie 0.
     * Le fichier aurait l'air vide : même problème, sans que ftell le signale.
     *
     * Trop gros : au-delà de GCM_TAILLE_MAX (~64 Go), le compteur de
     * ConterBlockGenerator repartirait à 0 (voir la définition de GCM_TAILLE_MAX).
     * Le (uint64_t) ne pose pas de problème : filesize n'est plus négatif ici.
     */

    if(seek != 0 || filesize < 0 || (uint64_t)filesize > GCM_TAILLE_MAX){
        fclose(file_in);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_TAILLE;
    }
    rewind(file_in);

    // Au plus 4 294 967 294 morceaux : tient dans un uint32_t, comme le compteur
    uint32_t NbState = (filesize + 15) / 16;


    // Path tempo
    char* tmpPath = calloc(strlen(path)+5,sizeof(char));
    if(tmpPath == NULL){
        fclose(file_in);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_MEMOIRE;
    }
    memcpy(tmpPath,path,strlen(path));
    strcat(tmpPath,".tmp");
    FILE* file_out = fopen(tmpPath, "wb");
    if(!file_out){
        free(tmpPath);
        fclose(file_in);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_CREATION;
    }

    /* Le .tmp prend les mêmes droits que le fichier d'origine.
     * Sans ça, fopen crée un fichier neuf avec les droits par défaut :
     * un fichier en 600 (lisible par toi seul) devenait 664 (lisible par tous).
     * & 0777 : on garde seulement les droits rwx du propriétaire, du groupe et des autres.
     *
     * Sous Windows, les droits ne sont pas des rwx (chmod ne sait gérer que
     * « lecture seule ») : ce bloc n'est compilé que sous Linux (#ifndef = « si PAS
     * Windows »). Le .tmp, créé dans le même dossier, reçoit les droits du dossier.
     */
    #ifndef _WIN32
        struct stat infos;
        if(stat(path, &infos) != 0 || chmod(tmpPath, infos.st_mode & 0777) != 0){
            fclose(file_out);
            fclose(file_in);
            remove(tmpPath);
            free(tmpPath);
            uint8_tToZero(key, 32);
            uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
            return AES_ERR_DROITS;
        }
    #endif


    // Ecriture de la version
    uint8_t p_version = (uint8_t) VERSION;
    if(fwrite(&p_version, 1, 1, file_out) != 1){
        fclose(file_out);
        fclose(file_in);
        remove(tmpPath);
        free(tmpPath);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_ECRITURE;
    }
    // Ecriture du nombre de tour 
    uint8_t nbrDeTour[4];
    nbrDeTour[0] = ((uint32_t) PBKDF2_TOURS >> 24) & 0xff;
    nbrDeTour[1] = ((uint32_t) PBKDF2_TOURS >> 16) & 0xff;
    nbrDeTour[2] = ((uint32_t) PBKDF2_TOURS >> 8) & 0xff;
    nbrDeTour[3] = ((uint32_t) PBKDF2_TOURS >> 0) & 0xff;
    if(fwrite(nbrDeTour, 1, 4, file_out) != 4){
        fclose(file_out);
        fclose(file_in);
        remove(tmpPath);
        free(tmpPath);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_ECRITURE;
    }

    if(fwrite(salt, 1, 16, file_out) != 16){
        fclose(file_out);
        fclose(file_in);
        remove(tmpPath);
        free(tmpPath);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_ECRITURE;
    }

    if(fwrite(nonce, 1, 12, file_out) != 12){
        fclose(file_out);
        fclose(file_in);
        remove(tmpPath);
        free(tmpPath);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_ECRITURE;
    }

    if(fwrite(verif, 1, 32, file_out) != 32){
        fclose(file_out);
        fclose(file_in);
        remove(tmpPath);
        free(tmpPath);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_ECRITURE;
    }

    // Création de la clé dérivée H (AES de 16 octets à 0)
    uint8_t bufferStateH[4][4];
    memset(bufferStateH, 0, 16);
     
    AES_Encrypt_Rondes(bufferStateH, GenratedKey);

    // La sortie d'AES se lit colonne par colonne, comme le ciphertext.
    // (un memcpy la lirait ligne par ligne : H serait dans le désordre)
    uint8_t zeroEncrypted[16];
    int indexH = 0;
    for(int colonne = 0; colonne < 4; colonne++){
        for(int ligne = 0; ligne < 4; ligne++){
            zeroEncrypted[indexH] = bufferStateH[ligne][colonne];
            indexH++;
        }
    }
    
    uint8_t plaintextState[16];
    uint8_t accumulateur[16] = {0x00};
    for(uint32_t state=0;state<NbState;state++){
        memset(plaintextState, 0, 16);

        /* Octets à lire : 16, ou ce qui reste au dernier morceau.
         * Si fread en lit moins (erreur de lecture, fichier raccourci pendant
         * le chiffrement), le chiffré serait plus court que filesize, que le
         * morceau "longueur" utilise : le fichier ne se déchiffrerait jamais.
         */
        long long reste = filesize - (long long)state * 16;
        size_t attendu = 16;
        if(reste < 16){
            attendu = reste;
        }
        size_t bytes_read = fread(plaintextState, 1, attendu, file_in);
        if(bytes_read != attendu){
            fclose(file_out);
            fclose(file_in);
            remove(tmpPath);
            free(tmpPath);
            uint8_tToZero(key, 32);
            uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
            return AES_ERR_LECTURE;
        }

        // Chiffrer en CTR
        uint8_t CompteurBlockState[4][4];
        ConterBlockGenerator(CompteurBlockState, nonce, state + 2);

        AES_Encrypt_Rondes(CompteurBlockState, GenratedKey);

        // Création du ciphertext
        uint8_t ciphertextState[16] = {0};
        size_t index = 0;
        for(int colonne = 0; colonne < 4; colonne++){
            for(int ligne = 0; ligne < 4; ligne++){
                if(index < bytes_read){
                    ciphertextState[index] = plaintextState[index] ^ CompteurBlockState[ligne][colonne];
                }
                index++;
            }
        }

        // GHASH
        for(int i = 0; i < 16; i++){
            accumulateur[i] ^= ciphertextState[i];
        }
        uint8_t temp[16];
        gf128_multiply(temp,accumulateur,zeroEncrypted);
        memcpy(accumulateur,temp,16);

        if(fwrite(ciphertextState, 1, bytes_read, file_out) != bytes_read){
            fclose(file_out);
            fclose(file_in);
            remove(tmpPath);
            free(tmpPath);
            uint8_tToZero(key, 32);
            uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
            return AES_ERR_ECRITURE;
        }
    }

    /* MORCEAU "LONGUEUR"
     * Pourquoi : la signature (accumulateur) ne dépend que des morceaux
     * chiffrés. Sans ce morceau, on pourrait ajouter 16 octets à 0 au
     * début du chiffré sans changer la signature (car 0 x H = 0).
     * En mettant la taille du texte dans la signature, tout ajout ou
     * retrait d'octets change la taille, donc la signature, et le
     * fichier est refusé au déchiffrement.
     *
     * Contenu (exemple : texte de 329 octets = 2632 bits = 0x0A48) :
     *   [00 00 00 00 00 00 00 00 | 00 00 00 00 00 00 0A 48]
     *    8 octets à 0              taille du texte en bits,
     *    (règle du vrai GCM)       octet de poids fort en premier
     *
     * Découpage de la taille en octets (comme dans ConterBlockGenerator) :
     *   i = 0 : (bits >> 0) & 0xff = 0x48 -> case 15
     *   i = 1 : (bits >> 8) & 0xff = 0x0A -> case 14
     *   i = 2..7 :                   0x00 -> cases 13 à 8
     */
    uint8_t blocLongueur[16] = {0};
    uint64_t bits = (uint64_t)filesize * 8;
    for(int i = 0; i < 8; i++){
        blocLongueur[15 - i] = (bits >> (8 * i)) & 0xff;
    }

    // On l'ajoute à la signature, exactement comme les autres morceaux
    for(int i = 0; i < 16; i++){
        accumulateur[i] ^= blocLongueur[i];
    }
    uint8_t temp[16];
    gf128_multiply(temp, accumulateur, zeroEncrypted);
    memcpy(accumulateur, temp, 16);

    /* MASQUE N°1 (cache la signature)
     * Pourquoi : la nonce n'entre pas dans le calcul de la signature.
     * Sans ce masque, on pourrait modifier la nonce sans changer la
     * signature : le fichier serait accepté mais déchiffré en déchets.
     * Le masque n°1 est fabriqué à partir de la nonce (comme les masques
     * des morceaux de texte, qui utilisent les n°2, 3, 4...). Si la nonce
     * change, le masque change, la signature est fausse, fichier refusé.
     * Bonus : la signature est cachée, donc personne ne peut s'en servir
     * pour retrouver H (zeroEncrypted) et fabriquer de fausses signatures.
     */
    uint8_t masqueTag[4][4];
    ConterBlockGenerator(masqueTag, nonce, 1);

    AES_Encrypt_Rondes(masqueTag, GenratedKey);

    // Le masque est une matrice rangée colonne par colonne :
    // on la lit dans le même ordre que pour le ciphertext
    int index = 0;
    for(int colonne = 0; colonne < 4; colonne++){
        for(int ligne = 0; ligne < 4; ligne++){
            accumulateur[index] ^= masqueTag[ligne][colonne];
            index++;
        }
    }

    if(fwrite(accumulateur, 1, 16, file_out) != 16){
        fclose(file_out);
        fclose(file_in);
        remove(tmpPath);
        free(tmpPath);
        uint8_tToZero(key, 32);
uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_ECRITURE;
    }

    // Même en cas d'échec, fclose a fermé file_out : on ne le referme pas
    if(fclose(file_out) != 0){
        fclose(file_in);
        remove(tmpPath);
        free(tmpPath);
        uint8_tToZero(key, 32);
uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_ECRITURE;
    }
    fclose(file_in);

    #ifdef _WIN32
        /* Sous Windows, rename refuse d'écraser un fichier qui existe déjà.
        * MoveFileExA avec MOVEFILE_REPLACE_EXISTING fait le même travail que
        * le rename de Linux. Attention : il renvoie 0 quand ça RATE. */
        if(MoveFileExA(tmpPath, path, MOVEFILE_REPLACE_EXISTING) == 0){
    #else
        if(rename(tmpPath, path) != 0){
    #endif
        remove(tmpPath);
        free(tmpPath);
        uint8_tToZero(key, 32);
uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_REMPLACEMENT;
    }
    free(tmpPath);
    uint8_tToZero(key, 32);
uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
    return AES_OK;
}

int AES_GCM_Decrypt_File(char* path,char* password){
    FILE* fileInfo = fopen(path, "rb");
    if(fileInfo == NULL){
        return AES_ERR_OUVERTURE;
    }

    // Déterminer la taille du fichier (_ftelli64 sous Windows : voir AES_GCM_Encrypt_File)
    #ifdef _WIN32
        int seek = _fseeki64(fileInfo, 0, SEEK_END);
        long long filesize = _ftelli64(fileInfo);
    #else
        int seek = fseek(fileInfo, 0, SEEK_END);
        long long filesize = ftell(fileInfo);
    #endif
    rewind(fileInfo);

    // Taille illisible : fseek raté, ou ftell à -1 (un tube, par exemple)
    if(seek != 0 || filesize < 0){
        fclose(fileInfo);
        return AES_ERR_TAILLE;
    }

    // 12 = nonce, 16 = salt, 16 = tag, 1 = version, 4 = nbr de tour, 32 = empreinte
    long long tailleChiffre = filesize - 16 - 12 - 16 - 1 - 4 - 32;
    // Plus gros que GCM_TAILLE_MAX : aucun fichier chiffré valide ne peut l'être
    if(tailleChiffre < 0 || (uint64_t)tailleChiffre > GCM_TAILLE_MAX){
        fclose(fileInfo);
        return AES_ERR_FORMAT;
    }
    uint32_t NbState = (tailleChiffre + 15) / 16;

    /* Les fread de l'en-tête sont vérifiés : si la lecture rate (clé USB
     * débranchée...), les cases resteraient pleines de déchets et on
     * renverrait AES_ERR_VERSION ou AES_ERR_AUTH, c'est-à-dire un code faux.
     */

    // RECUPERATION DE LA VERSION
    uint8_t version;
    if(fread(&version,sizeof(uint8_t),1, fileInfo) != 1){
        fclose(fileInfo);
        return AES_ERR_LECTURE;
    }
    if(version != VERSION){
        fclose(fileInfo);
        return AES_ERR_VERSION;
    }

    // RECUPERATION DU NOMBRE DE TOUR
    uint8_t octetsTour[4];
    uint32_t nbrDeTour = 0;
    if(fread(octetsTour,sizeof(uint8_t),4, fileInfo) != 4){
        fclose(fileInfo);
        return AES_ERR_LECTURE;
    }
    nbrDeTour = ((uint32_t) octetsTour[0] << 24)
              | ((uint32_t) octetsTour[1] << 16)
              | ((uint32_t) octetsTour[2] << 8)
              | ((uint32_t) octetsTour[3] << 0);
    // 0 tour : jamais écrit par AES_GCM_Encrypt_File, donc fichier abîmé.
    // Sans ce test, PBKDF2 le refuserait avec AES_ERR_PARAM, ce qui ferait
    // croire que c'est l'appel de la fonction qui est faux.
    if(nbrDeTour == 0){
        fclose(fileInfo);
        return AES_ERR_FORMAT;
    }

    // RECUPERATION DU SEL
    uint8_t salt[16];
    if(fread(salt,sizeof(uint8_t),16, fileInfo) != 16){
        fclose(fileInfo);
        return AES_ERR_LECTURE;
    }

    // RECUPERATION DE LA NONCE
    uint8_t nonce[12];
    if(fread(nonce, sizeof(uint8_t), 12, fileInfo) != 12){
        fclose(fileInfo);
        return AES_ERR_LECTURE;
    }

    // RECUPERATION DE L'EMPREINTE
    uint8_t verifFichier[32];
    if(fread(verifFichier, sizeof(uint8_t), 32, fileInfo) != 32){
        fclose(fileInfo);
        return AES_ERR_LECTURE;
    }


    // FABRICATION DE LA CLE
    uint8_t key[32];
    word GenratedKey[60];
    size_t size_password = strlen(password);
    // Code de PBKDF2 renvoyé tel quel (explication dans AES_GCM_Encrypt_File)
    int code = PBKDF2(key,password,size_password,salt,16,nbrDeTour);
    if(code != AES_OK){
        fclose(fileInfo);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return code;
    }

    uint8_t verif[32];
    code = AES_HMAC(verif, key, 32, (uint8_t*)VERIF_MESSAGE, sizeof(VERIF_MESSAGE) - 1);
    if(code != AES_OK){
        fclose(fileInfo);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return code;
    }

    // Comparaison en temps fixe (explication dans AES_GCM_Decrypt)
    int erreurMdp = 0;
    for(int i = 0; i < 32; i++){
        uint8_t difference = verif[i] ^ verifFichier[i];   // 0 si les 2 octets sont identiques
        erreurMdp = erreurMdp | difference;                // on garde tous les 1 déjà vus
    }
    if(erreurMdp){
        fclose(fileInfo);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_MDP;
    }
    word ExplodedKey[8];
    Explode(key, ExplodedKey);
    GenerateKey(GenratedKey, ExplodedKey);
    uint8_tToZero((uint8_t*)ExplodedKey, sizeof(ExplodedKey));

    // Création de la clé dérivée H (AES de 16 octets à 0)
    uint8_t bufferStateH[4][4];
    memset(bufferStateH, 0, 16);

    AES_Encrypt_Rondes(bufferStateH, GenratedKey);

    // La sortie d'AES se lit colonne par colonne, comme le ciphertext.
    // (un memcpy la lirait ligne par ligne : H serait dans le désordre)
    uint8_t zeroEncrypted[16];
    int indexH = 0;
    for(int colonne = 0; colonne < 4; colonne++){
        for(int ligne = 0; ligne < 4; ligne++){
            zeroEncrypted[indexH] = bufferStateH[ligne][colonne];
            indexH++;
        }
    }

    /* VERIFICATION DE LA SIGNATURE AVANT D'ECRIRE QUOI QUE CE SOIT
     * 1er passage : on lit tous les morceaux seulement pour calculer la
     * signature, sans rien déchiffrer ni écrire. Si elle est fausse, on
     * s'arrête ici : le fichier .tmp n'est jamais créé.
     * Les accolades { } forment un bloc : tout ce qui est déclaré dedans
     * disparaît à la fin, donc le code plus bas peut réutiliser les mêmes
     * noms (blocLongueur, masqueTag, tag...) sans conflit.
     */
    {
        uint8_t NewAccumulateur[16] = {0x00};
        for(uint32_t state=0;state<NbState;state++){
            // Lecture du ciphertext
            uint8_t ciphertextState[16] = {0};
            long long reste = tailleChiffre - (long long)state * 16;   // octets qu'il reste à lire
            size_t taille = 16;
            if(reste < 16){
                taille = reste;
            }
            if(fread(ciphertextState, 1, taille, fileInfo) != taille){
                fclose(fileInfo);
                uint8_tToZero(key, 32);
                uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
                return AES_ERR_LECTURE;
            }

            // GHASH
            for(int i = 0; i < 16; i++){
                NewAccumulateur[i] ^= ciphertextState[i];
            }
            uint8_t temp[16];
            gf128_multiply(temp,NewAccumulateur,zeroEncrypted);
            memcpy(NewAccumulateur,temp,16);
        }

        // MORCEAU "LONGUEUR" (une seule fois, après tous les morceaux)
        uint8_t blocLongueur[16] = {0};
        uint64_t bits = (uint64_t)tailleChiffre * 8;
        for(int i = 0; i < 8; i++){
            blocLongueur[15 - i] = (bits >> (8 * i)) & 0xff;
        }
        for(int i = 0; i < 16; i++){
            NewAccumulateur[i] ^= blocLongueur[i];
        }
        uint8_t temp[16];
        gf128_multiply(temp, NewAccumulateur, zeroEncrypted);
        memcpy(NewAccumulateur, temp, 16);

        // MASQUE N°1
        uint8_t masqueTag[4][4];
        ConterBlockGenerator(masqueTag, nonce, 1);

        AES_Encrypt_Rondes(masqueTag, GenratedKey);

        int index = 0;
        for(int colonne = 0; colonne < 4; colonne++){
            for(int ligne = 0; ligne < 4; ligne++){
                NewAccumulateur[index] ^= masqueTag[ligne][colonne];
                index++;
            }
        }

        // RECUPERATION DU tag et comparaison
        uint8_t tag[16];
        int error = 0;
        if(fread(tag, 1, 16, fileInfo) != 16){
            fclose(fileInfo);
            uint8_tToZero(key, 32);
            uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
            return AES_ERR_LECTURE;
        }
        for(int i = 0; i < 16; i++){
            error |= tag[i] ^ NewAccumulateur[i];
        }

        if(error){
            fclose(fileInfo);
            uint8_tToZero(key, 32);
            uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
            return AES_ERR_AUTH;
        }
    }

    // Retour au début du chiffré (juste après l'en-tête de 65 octets)
    if(fseek(fileInfo, 65, SEEK_SET) != 0){
        fclose(fileInfo);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_LECTURE;
    }
    char* tmpPath = calloc(strlen(path)+5,sizeof(char));
    if(tmpPath == NULL){
        fclose(fileInfo);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_MEMOIRE;
    }
    memcpy(tmpPath,path,strlen(path));
    strcat(tmpPath,".tmp");
    FILE* file_write = fopen(tmpPath, "wb");
    if(file_write == NULL){
        fclose(fileInfo);
        free(tmpPath);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_CREATION;
    }

    // Le .tmp prend les mêmes droits que l'original (explication dans AES_GCM_Encrypt_File).
    // Ici c'est le plus important : le .tmp va contenir le texte déchiffré.
    // Seulement sous Linux, comme dans AES_GCM_Encrypt_File.
    #ifndef _WIN32
    struct stat infos;
        if(stat(path, &infos) != 0 || chmod(tmpPath, infos.st_mode & 0777) != 0){
            fclose(file_write);
            fclose(fileInfo);
            remove(tmpPath);
            free(tmpPath);
            uint8_tToZero(key, 32);
            uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
            return AES_ERR_DROITS;
        }
    #endif

    uint8_t plaintextState[16];
    uint8_t accumulateur[16] = {0x00};
    for(uint32_t state=0;state<NbState;state++){
        // Lecture du ciphertext
        uint8_t ciphertextState[16] = {0};
        long long reste = tailleChiffre - (long long)state * 16;   // octets qu'il reste à lire
        size_t taille = 16;
        if(reste < 16){
            taille = reste;
        }
        if(fread(ciphertextState, 1, taille, fileInfo) != taille){
            fclose(file_write);
            fclose(fileInfo);
            remove(tmpPath);
            free(tmpPath);
            uint8_tToZero(key, 32);
            uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
            return AES_ERR_LECTURE;
        }

        // GHASH
        for(int i = 0; i < 16; i++){
            accumulateur[i] ^= ciphertextState[i];
        }
        uint8_t temp[16];
        gf128_multiply(temp,accumulateur,zeroEncrypted);
        memcpy(accumulateur,temp,16);

        // Dechiffrement en CTR
        uint8_t CompteurBlockState[4][4];
        ConterBlockGenerator(CompteurBlockState, nonce, state + 2);

        AES_Encrypt_Rondes(CompteurBlockState, GenratedKey);

        // Récupération du plaintext
        int index = 0;
        for(int colonne = 0; colonne < 4; colonne++){
            for(int ligne = 0; ligne < 4; ligne++){
                plaintextState[index] = ciphertextState[index] ^ CompteurBlockState[ligne][colonne];
                index++;
            }
        }

        /* Disque plein : le .tmp serait incomplet, mais la 2e vérification du
         * tag passerait quand même (elle porte sur ce qui a été LU) et le
         * rename remplacerait le fichier chiffré par un texte tronqué.
         */
        if(fwrite(plaintextState, 1, taille, file_write) != taille){
            fclose(file_write);
            fclose(fileInfo);
            remove(tmpPath);
            free(tmpPath);
            uint8_tToZero(key, 32);
            uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
            return AES_ERR_ECRITURE;
        }
    }


    /* MORCEAU "LONGUEUR" : même calcul qu'au chiffrement
     * (explication complète dans AES_GCM_Encrypt_File).
     * Attention : ici on prend tailleChiffre (la taille du texte, sans
     * nonce ni tag) et PAS filesize (la taille du fichier chiffré entier).
     * Sinon les deux côtés ne calculent pas la même signature et tous
     * les déchiffrements échouent.
     */
    uint8_t blocLongueur[16] = {0};
    uint64_t bits = (uint64_t)tailleChiffre * 8;
    for(int i = 0; i < 8; i++){
        blocLongueur[15 - i] = (bits >> (8 * i)) & 0xff;
    }

    // On l'ajoute à la signature, exactement comme les autres morceaux
    for(int i = 0; i < 16; i++){
        accumulateur[i] ^= blocLongueur[i];
    }
    uint8_t temp[16];
    gf128_multiply(temp, accumulateur, zeroEncrypted);
    memcpy(accumulateur, temp, 16);

    /* MASQUE N°1 : même calcul qu'au chiffrement
     * (explication complète dans AES_GCM_Encrypt_File).
     */
    uint8_t masqueTag[4][4];
    ConterBlockGenerator(masqueTag, nonce, 1);
    
    AES_Encrypt_Rondes(masqueTag, GenratedKey);

    int index = 0;
    for(int colonne = 0; colonne < 4; colonne++){
        for(int ligne = 0; ligne < 4; ligne++){
            accumulateur[index] ^= masqueTag[ligne][colonne];
            index++;
        }
    }

    // RECUPERATION DU tag
    uint8_t tag[16];
    int error = 0;
    if(fread(tag, 1, 16, fileInfo) != 16){
        fclose(file_write);
        fclose(fileInfo);
        remove(tmpPath);
        free(tmpPath);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_LECTURE;
    }

    // Vérification de l'intégritée du fichier
    for(int i = 0; i < 16; i++){
        error |= tag[i] ^ accumulateur[i];
    }

    if(error){
        fclose(file_write);
        fclose(fileInfo);
        remove(tmpPath);
        free(tmpPath);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_AUTH;  // Authentification échouée
    }

    fclose(fileInfo);
    // fclose écrit ce qui reste dans le tampon : c'est souvent là que "disque plein" arrive
    if(fclose(file_write) != 0){
        remove(tmpPath);
        free(tmpPath);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_ECRITURE;
    }

    #ifdef _WIN32
        // Même chose que dans AES_GCM_Encrypt_File : 0 = échec
        if(MoveFileExA(tmpPath, path, MOVEFILE_REPLACE_EXISTING) == 0){
    #else
        if(rename(tmpPath, path) != 0){
    #endif
        remove(tmpPath);
        free(tmpPath);
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_REMPLACEMENT;
    }
    free(tmpPath);
    uint8_tToZero(key, 32);
    uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
    return AES_OK;
}

int AES_GCM_Encrypt(uint8_t** dest,size_t* size_dest,uint8_t* src,size_t size_src,char* password){
    if(src == NULL || password == NULL){
        return AES_ERR_PARAM;
    }
    // *dest doit valoir NULL : sinon le calloc écraserait l'adresse d'un buffer déjà alloué
    if(dest == NULL || *dest != NULL || size_dest == NULL){
        return AES_ERR_PARAM;
    }
    // Trop gros : le compteur repartirait à 0 (voir GCM_TAILLE_MAX)
    if((uint64_t)size_src > GCM_TAILLE_MAX){
        return AES_ERR_TAILLE;
    }

    // GENERATION DE LA NONCE ET DU SEL
    uint8_t nonce[12];
    uint8_t salt[16];
    #ifdef _WIN32
        // Même chose que dans AES_GCM_Encrypt_File : le hasard de Windows
        if(BCryptGenRandom(NULL, nonce, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0){
            return AES_ERR_ALEA;
        }
        if(BCryptGenRandom(NULL, salt, 16, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0){
            return AES_ERR_ALEA;
        }
    #else
        FILE *f = fopen("/dev/urandom", "rb");
        if(f == NULL){
            return AES_ERR_ALEA;
        }

        if(fread(nonce, sizeof(uint8_t), 12, f) != 12){
            fclose(f);
            return AES_ERR_ALEA;
        }
        if(fread(salt,sizeof(uint8_t), 16, f) != 16){
            fclose(f);
            return AES_ERR_ALEA;
        }
        fclose(f);
    #endif

    // CREATION DE LA CLE AVEC PBKDF2
    uint8_t key[32];
    word GenratedKey[60];
    size_t size_password = strlen(password);
    // Code de PBKDF2 renvoyé tel quel (explication dans AES_GCM_Encrypt_File)
    int code = PBKDF2(key,password,size_password,salt,16,PBKDF2_TOURS);
    if(code != AES_OK){
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return code;
    }
    uint8_t verif[32];
    code = AES_HMAC(verif, key, 32, (uint8_t*)VERIF_MESSAGE, sizeof(VERIF_MESSAGE) - 1);
    if(code != AES_OK){
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return code;
    }

    word ExplodedKey[8];
    Explode(key, ExplodedKey);
    GenerateKey(GenratedKey, ExplodedKey);
    uint8_tToZero((uint8_t*)ExplodedKey, sizeof(ExplodedKey));

    // LECTURE DU SOURCE
    uint32_t NbState = (size_src + 15) / 16;
    *dest = calloc(size_src + 81,sizeof(uint8_t));
    if((*dest) == NULL){
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_MEMOIRE;
    }

    size_t index_write = 0;

    // Ecriture de la version
    (*dest)[index_write] = (uint8_t) VERSION;
    index_write++;
    // Ecriture du nombre de tour 
    uint8_t nbrDeTour[4];
    nbrDeTour[0] = ((uint32_t) PBKDF2_TOURS >> 24) & 0xff;
    nbrDeTour[1] = ((uint32_t) PBKDF2_TOURS >> 16) & 0xff;
    nbrDeTour[2] = ((uint32_t) PBKDF2_TOURS >> 8) & 0xff;
    nbrDeTour[3] = ((uint32_t) PBKDF2_TOURS >> 0) & 0xff;
    for(size_t i = 0;i<4;i++){
        (*dest)[index_write] = nbrDeTour[i];
        index_write++;
    }
    // Ecriture du salt
    for(size_t i = 0;i<16;i++){
        (*dest)[index_write] = salt[i];
        index_write++;
    }
    // Ecriture de la nonce
    for(size_t i = 0;i<12;i++){
        (*dest)[index_write] = nonce[i];
        index_write++;
    }
    // Ecriture de la vérification
    for(size_t i = 0;i<32;i++){
        (*dest)[index_write] = verif[i];
        index_write++;
    }

    // Création de la clé dérivée H (AES de 16 octets à 0)
    uint8_t bufferStateH[4][4];
    memset(bufferStateH, 0, 16);

    AES_Encrypt_Rondes(bufferStateH, GenratedKey);

    // La sortie d'AES se lit colonne par colonne, comme le ciphertext.
    // (un memcpy la lirait ligne par ligne : H serait dans le désordre)
    uint8_t zeroEncrypted[16];
    int indexH = 0;
    for(int colonne = 0; colonne < 4; colonne++){
        for(int ligne = 0; ligne < 4; ligne++){
            zeroEncrypted[indexH] = bufferStateH[ligne][colonne];
            indexH++;
        }
    }

    uint8_t plaintextState[16];
    uint8_t accumulateur[16] = {0x00};
    size_t index_read = 0;
    for(uint32_t state=0;state<NbState;state++){
        // vérification de byte restant
        size_t bytes_read = 16;
        if(size_src - index_read < 16){
            bytes_read = size_src - index_read;
        }

        memset(plaintextState, 0, 16);
        for(size_t i = 0; i < bytes_read; i++){
            plaintextState[i] = src[index_read];
            index_read++;
        }

        // Chiffrer en CTR
        uint8_t CompteurBlockState[4][4];
        ConterBlockGenerator(CompteurBlockState, nonce, state + 2);

        AES_Encrypt_Rondes(CompteurBlockState, GenratedKey);

        // Création du ciphertext
        uint8_t ciphertextState[16] = {0};
        size_t index = 0;
        for(int colonne = 0; colonne < 4; colonne++){
            for(int ligne = 0; ligne < 4; ligne++){
                if(index < bytes_read){
                    ciphertextState[index] = plaintextState[index] ^ CompteurBlockState[ligne][colonne];
                }
                index++;
            }
        }

        // GHASH
        for(int i = 0; i < 16; i++){
            accumulateur[i] ^= ciphertextState[i];
        }
        uint8_t temp[16];
        gf128_multiply(temp,accumulateur,zeroEncrypted);
        memcpy(accumulateur,temp,16);
        
        for(size_t i = 0; i < bytes_read;i++){
            (*dest)[index_write] = ciphertextState[i];
            index_write++;
        }
    }

    uint8_t blocLongueur[16] = {0};
    uint64_t bits = (uint64_t)size_src * 8;
    for(int i = 0; i < 8; i++){
        blocLongueur[15 - i] = (bits >> (8 * i)) & 0xff;
    }

    // On l'ajoute à la signature, exactement comme les autres morceaux
    for(int i = 0; i < 16; i++){
        accumulateur[i] ^= blocLongueur[i];
    }
    uint8_t temp[16];
    gf128_multiply(temp, accumulateur, zeroEncrypted);
    memcpy(accumulateur, temp, 16);

    uint8_t masqueTag[4][4];
    ConterBlockGenerator(masqueTag, nonce, 1);

    AES_Encrypt_Rondes(masqueTag, GenratedKey);

    // Le masque est une matrice rangée colonne par colonne :
    // on la lit dans le même ordre que pour le ciphertext
    int index = 0;
    for(int colonne = 0; colonne < 4; colonne++){
        for(int ligne = 0; ligne < 4; ligne++){
            accumulateur[index] ^= masqueTag[ligne][colonne];
            index++;
        }
    }

    for(size_t i = 0;i<16;i++){
        (*dest)[index_write] = accumulateur[i];
        index_write++;
    }

    *size_dest = index_write;

    uint8_tToZero(key, 32);
uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
    return AES_OK;
}



int AES_GCM_Decrypt(uint8_t** dest,size_t* size_dest,uint8_t* src,size_t size_src,char* password){
    if(src == NULL || password == NULL){
        return AES_ERR_PARAM;
    }
    // *dest doit valoir NULL : sinon le calloc écraserait l'adresse d'un buffer déjà alloué
    if(dest == NULL || *dest != NULL || size_dest == NULL){
        return AES_ERR_PARAM;
    }

    if(size_src < 81){
        return AES_ERR_FORMAT;
    }

    // 16 = tag, 12 = nonce, 16 = sel, 1 = version, 4 = tours, 32 = empreinte
    long long tailleChiffre = size_src - 16 - 12 - 16 - 1 - 4 - 32;
    // Plus gros que GCM_TAILLE_MAX : aucune donnée chiffrée valide ne peut l'être
    if(tailleChiffre < 0 || (uint64_t)tailleChiffre > GCM_TAILLE_MAX){
        return AES_ERR_FORMAT;
    }
    uint32_t NbState = (tailleChiffre + 15) / 16;

    size_t index_read = 0;
    size_t index_write = 0;

    // RECUPERATION DE LA VERSION
    int version = (uint8_t)src[index_read];
    if(version != VERSION){
        return AES_ERR_VERSION;
    }
    index_read++;

    // RECUPERATION DU NOMBRE DE TOUR
    uint8_t octetsTour[4];
    uint32_t nbrDeTour = 0;
    for(size_t i=0;i<4;i++){
        octetsTour[i] = src[index_read];
        index_read++;
    }
    nbrDeTour = ((uint32_t) octetsTour[0] << 24)
              | ((uint32_t) octetsTour[1] << 16)
              | ((uint32_t) octetsTour[2] << 8)
              | ((uint32_t) octetsTour[3] << 0);
    // 0 tour : données abîmées (explication dans AES_GCM_Decrypt_File)
    if(nbrDeTour == 0){
        return AES_ERR_FORMAT;
    }

    // RECUPERATION DU SEL
    uint8_t salt[16];
    for(size_t i=0;i<16;i++){
        salt[i] = src[index_read];
        index_read++;
    }

    // RECUPERATION DE LA NONCE
    uint8_t nonce[12];
    for(size_t i=0;i<12;i++){
        nonce[i] = src[index_read];
        index_read++;
    }

    // RECUPERATION DE L'EMPREINTE
    uint8_t verifFichier[32];
    for(size_t i=0;i<32;i++){
        verifFichier[i] = src[index_read];
        index_read++;
    }


    // FABRICATION DE LA CLE
    uint8_t key[32];
    word GenratedKey[60];
    size_t size_password = strlen(password);
    // Code de PBKDF2 renvoyé tel quel (explication dans AES_GCM_Encrypt_File)
    int code = PBKDF2(key,password,size_password,salt,16,nbrDeTour);
    if(code != AES_OK){
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return code;
    }
    uint8_t verif[32];
    code = AES_HMAC(verif, key, 32, (uint8_t*)VERIF_MESSAGE, sizeof(VERIF_MESSAGE) - 1);
    if(code != AES_OK){
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return code;
    }

    /* COMPARAISON DE L'EMPREINTE (en temps fixe)
    * ^ (XOR) : 0 si les deux octets sont identiques, sinon les bits qui diffèrent sont à 1
    *     10100101 ^ 10100101 = 00000000   identiques
    *     00001111 ^ 00001011 = 00000100   différents : le bit qui change est à 1
    *
    * |= (OU) : erreurMdp = erreurMdp | difference
    *     Un 1 ne redevient jamais 0 : erreurMdp garde la trace de TOUS les octets différents.
    *     octet 0 : 00000000 | 00000000 = 00000000
    *     octet 2 : 00000000 | 00000100 = 00000100   <- une différence
    *     octet 3 : 00000100 | 00000000 = 00000100   <- elle reste
    *
    * À la fin : erreurMdp == 0 seulement si les 32 octets sont identiques.
    * La boucle fait toujours les 32 tours (contrairement à memcmp, qui s'arrête
    * à la première différence) : le temps ne dit rien sur le nombre d'octets bons.
    */
    int erreurMdp = 0;
    for(int i = 0; i < 32; i++){
        uint8_t difference = verif[i] ^ verifFichier[i];   // 0 si les 2 octets sont identiques
        erreurMdp = erreurMdp | difference;                // on garde tous les 1 déjà vus
    }
    if(erreurMdp){
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_MDP;
    }

    word ExplodedKey[8];
    Explode(key, ExplodedKey);
    GenerateKey(GenratedKey, ExplodedKey);
    uint8_tToZero((uint8_t*)ExplodedKey, sizeof(ExplodedKey));

    // Création de la clé dérivée H (AES de 16 octets à 0)
    uint8_t bufferStateH[4][4];
    memset(bufferStateH, 0, 16);

    AES_Encrypt_Rondes(bufferStateH, GenratedKey);

    // La sortie d'AES se lit colonne par colonne, comme le ciphertext.
    // (un memcpy la lirait ligne par ligne : H serait dans le désordre)
    uint8_t zeroEncrypted[16];
    int indexH = 0;
    for(int colonne = 0; colonne < 4; colonne++){
        for(int ligne = 0; ligne < 4; ligne++){
            zeroEncrypted[indexH] = bufferStateH[ligne][colonne];
            indexH++;
        }
    }

    {
        uint8_t NewAccumulateur[16] = {0x00};
        for(uint32_t state=0;state<NbState;state++){
            // Lecture du ciphertext
            uint8_t ciphertextState[16] = {0};
            long long reste = tailleChiffre - (long long)state * 16;   // octets qu'il reste à lire
            size_t taille = 16;
            if(reste < 16){
                taille = reste;
            }

            for(size_t i=0;i<taille;i++){
                ciphertextState[i] = src[index_read];
                index_read++;
            }

            // GHASH
            for(int i = 0; i < 16; i++){
                NewAccumulateur[i] ^= ciphertextState[i];
            }
            uint8_t temp[16];
            gf128_multiply(temp,NewAccumulateur,zeroEncrypted);
            memcpy(NewAccumulateur,temp,16);
        }

        // MORCEAU "LONGUEUR" (une seule fois, après tous les morceaux)
        uint8_t blocLongueur[16] = {0};
        uint64_t bits = (uint64_t)tailleChiffre * 8;
        for(int i = 0; i < 8; i++){
            blocLongueur[15 - i] = (bits >> (8 * i)) & 0xff;
        }
        for(int i = 0; i < 16; i++){
            NewAccumulateur[i] ^= blocLongueur[i];
        }
        uint8_t temp[16];
        gf128_multiply(temp, NewAccumulateur, zeroEncrypted);
        memcpy(NewAccumulateur, temp, 16);

        // MASQUE N°1
        uint8_t masqueTag[4][4];
        ConterBlockGenerator(masqueTag, nonce, 1);

        AES_Encrypt_Rondes(masqueTag, GenratedKey);

        int index = 0;
        for(int colonne = 0; colonne < 4; colonne++){
            for(int ligne = 0; ligne < 4; ligne++){
                NewAccumulateur[index] ^= masqueTag[ligne][colonne];
                index++;
            }
        }

        // RECUPERATION DU tag et comparaison
        uint8_t tag[16];
        int error = 0;
        for(size_t i=0;i<16;i++){
            tag[i] = src[index_read];
            index_read++;
        }

        for(int i = 0; i < 16; i++){
            error |= tag[i] ^ NewAccumulateur[i];
        }

        if(error){
            uint8_tToZero(key, 32);
uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
            return AES_ERR_AUTH;
        }
    }

    index_read = 65;
    
    *dest = calloc((size_src - 81) + 1,sizeof(uint8_t));
    if((*dest) == NULL){
        uint8_tToZero(key, 32);
        uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_MEMOIRE;
    }

    uint8_t plaintextState[16];
    uint8_t accumulateur[16] = {0x00};
    for(uint32_t state=0;state<NbState;state++){
        // Lecture du ciphertext
        uint8_t ciphertextState[16] = {0};
        long long reste = tailleChiffre - (long long)state * 16;   // octets qu'il reste à lire
        size_t taille = 16;
        if(reste < 16){
            taille = reste;
        }
        for(size_t i=0;i<taille;i++){
            ciphertextState[i] = src[index_read];
            index_read++;
        }

        // GHASH
        for(int i = 0; i < 16; i++){
            accumulateur[i] ^= ciphertextState[i];
        }
        uint8_t temp[16];
        gf128_multiply(temp,accumulateur,zeroEncrypted);
        memcpy(accumulateur,temp,16);

        // Dechiffrement en CTR
        uint8_t CompteurBlockState[4][4];
        ConterBlockGenerator(CompteurBlockState, nonce, state + 2);

        AES_Encrypt_Rondes(CompteurBlockState, GenratedKey);

        // Récupération du plaintext
        int index = 0;
        for(int colonne = 0; colonne < 4; colonne++){
            for(int ligne = 0; ligne < 4; ligne++){
                plaintextState[index] = ciphertextState[index] ^ CompteurBlockState[ligne][colonne];
                index++;
            }
        }

        for(size_t i=0;i<taille;i++){
            (*dest)[index_write] = plaintextState[i];
            index_write++;
        }
    }

    uint8_t blocLongueur[16] = {0};
    uint64_t bits = (uint64_t)tailleChiffre * 8;
    for(int i = 0; i < 8; i++){
        blocLongueur[15 - i] = (bits >> (8 * i)) & 0xff;
    }

    // On l'ajoute à la signature, exactement comme les autres morceaux
    for(int i = 0; i < 16; i++){
        accumulateur[i] ^= blocLongueur[i];
    }
    uint8_t temp[16];
    gf128_multiply(temp, accumulateur, zeroEncrypted);
    memcpy(accumulateur, temp, 16);

    /* MASQUE N°1 : même calcul qu'au chiffrement
     * (explication complète dans AES_GCM_Encrypt_File).
     */
    uint8_t masqueTag[4][4];
    ConterBlockGenerator(masqueTag, nonce, 1);

    AES_Encrypt_Rondes(masqueTag, GenratedKey);

    int index = 0;
    for(int colonne = 0; colonne < 4; colonne++){
        for(int ligne = 0; ligne < 4; ligne++){
            accumulateur[index] ^= masqueTag[ligne][colonne];
            index++;
        }
    }

    // RECUPERATION DU tag
    uint8_t tag[16];
    int error = 0;
    for(size_t i=0;i<16;i++){
        tag[i] = src[index_read];
        index_read++;
    }

    // Vérification de l'intégritée du fichier 
    for(int i = 0; i < 16; i++){
        error |= tag[i] ^ accumulateur[i];
    }

    if(error){
        free(*dest);
        *dest = NULL;
        uint8_tToZero(key, 32);
uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
        return AES_ERR_AUTH;  // Authentification échouée
    }

    *size_dest = index_write;

    uint8_tToZero(key, 32);
uint8_tToZero((uint8_t*)GenratedKey, sizeof(GenratedKey));
    return AES_OK;
}

void uint8_tToZero(uint8_t* p_uint8_t,size_t size){
    if(p_uint8_t == NULL){
        return;
    }
    volatile uint8_t* p = p_uint8_t;
    for(size_t i=0;i<size;i++){
        p[i] = 0x00;
    }
}

//////////////////////////////////////////////////////////
// SHA 256

int padding(uint8_t** dest,uint8_t* mess,size_t* size){
    // Nombre de blocs de 64 octets pour ranger : message + 0x80 + 8 octets de taille
    // = (size + 9 + 63) / 64 arrondi au-dessus, simplifié en (size + 8) / 64 + 1
    size_t nbrOfBloc = ((*size + 8) / 64) + 1;
    // Taille finale du message paddé, en octets
    size_t nbrOfOctet = nbrOfBloc * 64;

    // Allocation dynamique de *dest, calloc met tout à 0 (les zéros du padding sont déjà là)
    // Si *dest != NULL alors erreur
    uint8_t* tmp = NULL;
    if(*dest == NULL){
        tmp = calloc(nbrOfOctet,sizeof(uint8_t));
        if(tmp == NULL){
            return AES_ERR_MEMOIRE;
        }
        *dest = tmp;
    }else{
        return AES_ERR_PARAM;
    }
    
    // Copie du mess vers dest de 0 à size-1, puis 0x80 (= 1000 0000 : un bit 1 suivi de 0)
    memcpy(*dest,mess,*size);
    (*dest)[*size] = 0x80;


    /* Range la taille du message EN BITS dans les 8 derniers octets,
     * le plus gros octet en premier (big-endian, imposé par la norme)
    */
    uint64_t sizeInBits = (uint64_t)*size * 8;
    for (size_t i = 0; i < 8; i++) {
        // exemple 11 22 33 44 55 66 77 88, avec 1 seul bloc (cases 56 à 63)
        /*  tour  décalage   après >>                    garde   va dans la case
         *   0    >> 56      00 00 00 00 00 00 00 11      11      56
         *   1    >> 48      00 00 00 00 00 00 11 22      22      57
         *   2    >> 40      00 00 00 00 00 11 22 33      33      58
         *   3    >> 32      00 00 00 00 11 22 33 44      44      59
         *   4    >> 24      00 00 00 11 22 33 44 55      55      60
         *   5    >> 16      00 00 11 22 33 44 55 66      66      61
         *   6    >> 8       00 11 22 33 44 55 66 77      77      62
         *   7    >> 0       11 22 33 44 55 66 77 88      88      63
        */
        (*dest)[nbrOfOctet - 8 + i] = (uint8_t)(sizeInBits >> (56 - (8 * i)));
    }

    // size devient la taille du message paddé
    *size = nbrOfOctet;
    return AES_OK;
}

// Accélération (Claude)
uint32_t ROTR(uint32_t num, size_t n){ return (num >> n) | (num << (32 - n)); }
uint32_t choose(uint32_t x, uint32_t y, uint32_t z){ return (x & y) ^ (~x & z); }
uint32_t majority(uint32_t x, uint32_t y, uint32_t z){ return (x & y) ^ (x & z) ^ (y & z); }

uint32_t SIG0(uint32_t x){
    uint32_t morceau1 = ROTR(x, 2);
    uint32_t morceau2 = ROTR(x, 13);
    uint32_t morceau3 = ROTR(x, 22);
    return morceau1 ^ morceau2 ^ morceau3;
}

uint32_t SIG1(uint32_t x){
    uint32_t morceau1 = ROTR(x, 6);
    uint32_t morceau2 = ROTR(x, 11);
    uint32_t morceau3 = ROTR(x, 25);
    return morceau1 ^ morceau2 ^ morceau3;
}

uint32_t sig0(uint32_t x){
    uint32_t morceau1 = ROTR(x, 7);
    uint32_t morceau2 = ROTR(x, 18);
    uint32_t morceau3 = x >> 3;
    return morceau1 ^ morceau2 ^ morceau3;
}

uint32_t sig1(uint32_t x){
    uint32_t morceau1 = ROTR(x, 17);
    uint32_t morceau2 = ROTR(x, 19);
    uint32_t morceau3 = x >> 10;
    return morceau1 ^ morceau2 ^ morceau3;
}

void compressing(uint32_t H[8], uint8_t* mess){
    uint32_t W[64];

    // Partie 1 : W[0] à W[15], on colle les octets du bloc 4 par 4
    for(size_t t = 0; t < 16; t++){
        uint32_t morceau1 = (uint32_t)mess[4*t] << 24;
        uint32_t morceau2 = (uint32_t)mess[4*t + 1] << 16;
        uint32_t morceau3 = (uint32_t)mess[4*t + 2] << 8;
        uint32_t morceau4 = (uint32_t)mess[4*t + 3];
        W[t] = morceau1 | morceau2 | morceau3 | morceau4;
    }

    // Partie 2 : W[16] à W[63], fabriqués à partir des W précédents
    for(size_t t = 16; t < 64; t++){
        W[t] = sig1(W[t-2]) + W[t-7] + sig0(W[t-15]) + W[t-16];
    }

    // Partie 3 : Les rondes
    uint32_t a = H[0];
    uint32_t b = H[1];
    uint32_t c = H[2];
    uint32_t d = H[3];
    uint32_t e = H[4];
    uint32_t f = H[5];
    uint32_t g = H[6];
    uint32_t h = H[7];

    uint32_t T1;
    uint32_t T2;
    for(size_t ronde = 0; ronde < 64; ronde++){
        // Les lettres au lieu de H[...]
        T1 = h + SIG1(e) + choose(e, f, g) + K[ronde] + W[ronde];
        T2 = SIG0(a) + majority(a, b, c);

        // Les 8 variables avancent d'une place
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    // Partie 4 : on ajoute le mélange à l'ancien H
    H[0] += a;
    H[1] += b;
    H[2] += c;
    H[3] += d;
    H[4] += e;
    H[5] += f;
    H[6] += g;
    H[7] += h;
}


int AES_SHA256(uint8_t* dest, uint8_t* mess, size_t size){
    uint32_t H[8] = HASH_CONST;
    uint8_t* buffer = NULL;

    // 1. Padding : size devient la taille du buffer paddé
    // (code de padding renvoyé tel quel : AES_ERR_MEMOIRE ou AES_ERR_PARAM)
    int code = padding(&buffer, mess, &size);
    if (code != AES_OK) {
        return code;
    }

    // 2. On compresse chaque bloc de 64 octets
    for (size_t k = 0; k < size / 64; k++) {
        compressing(H, buffer + k * 64);
    }

    // 3. On découpe chaque H[i] en 4 octets dans dest
    for (size_t i = 0; i < 8; i++) {
        dest[4*i]     = (uint8_t)(H[i] >> 24);
        dest[4*i + 1] = (uint8_t)(H[i] >> 16);
        dest[4*i + 2] = (uint8_t)(H[i] >> 8);
        dest[4*i + 3] = (uint8_t)(H[i]);
    }

    uint8_tToZero(buffer,size);
    uint8_tToZero((uint8_t*)H,sizeof(H));
    free(buffer);
    return AES_OK;
}

int AES_HMAC(uint8_t* dest,uint8_t* key,size_t size_key,uint8_t* mess,size_t size_mess){
    if(dest == NULL){
        return AES_ERR_PARAM;
    }
    // Code renvoyé par AES_SHA256 (3 appels), qu'on fait remonter tel quel
    int code;

    // Phase 1
    uint8_t localKey[64] = {0};
    if(size_key > 64){
        code = AES_SHA256(localKey,key,size_key);
        if(code != AES_OK){
            uint8_tToZero(localKey,64);
            return code;
        }
    }else{
        memcpy(localKey,key,size_key);
    }

    // Phase 2
    uint8_t keyIn[64] = {0};
    uint8_t keyOut[64] = {0};
    for(int i=0;i<64;i++){
        keyIn[i] = localKey[i] ^ 0x36;
        keyOut[i] = localKey[i] ^ 0x5c;
    }

    // Phase 3
    uint8_t* buffer = calloc(64 + size_mess,sizeof(uint8_t));
    if(buffer == NULL){
        uint8_tToZero(localKey,64);
        uint8_tToZero(keyIn,64);
        uint8_tToZero(keyOut,64);
        return AES_ERR_MEMOIRE;
    }
    memcpy(buffer,keyIn,64);
    memcpy(buffer+64,mess,size_mess);

    uint8_t hached[32];
    code = AES_SHA256(hached,buffer,64 + size_mess);
    if(code != AES_OK){
        uint8_tToZero(localKey,64);
        uint8_tToZero(keyIn,64);
        uint8_tToZero(keyOut,64);
        uint8_tToZero(buffer,64 + size_mess);
        uint8_tToZero(hached,32);
        free(buffer);
        return code;
    }
    uint8_tToZero(buffer,64 + size_mess);
    free(buffer);

    // Phase 4
    uint8_t bufferOut[96];
    memcpy(bufferOut,keyOut,64);
    memcpy(bufferOut+64,hached,32);

    code = AES_SHA256(dest,bufferOut,96);
    if(code != AES_OK){
        uint8_tToZero(hached,32);
        uint8_tToZero(localKey,64);
        uint8_tToZero(keyIn,64);
        uint8_tToZero(keyOut,64);
        uint8_tToZero(bufferOut,96);
        return code;
    }

    uint8_tToZero(hached,32);
    uint8_tToZero(localKey,64);
    uint8_tToZero(keyIn,64);
    uint8_tToZero(keyOut,64);
    uint8_tToZero(bufferOut,96);
    return AES_OK;
}

int PBKDF2(uint8_t* dest,char* password,size_t size_password,uint8_t* salt,size_t size_salt,size_t tour){
    if(dest == NULL || tour == 0){
        return AES_ERR_PARAM;
    }

    // Phase 1
    uint8_t ZeroOne[4] = {0x00,0x00,0x00,0x01};
    uint8_t *mess = calloc(size_salt + 4,sizeof(uint8_t));
    if(mess == NULL){
        return AES_ERR_MEMOIRE;
    }
    memcpy(mess,salt,size_salt);
    memcpy(mess+size_salt,ZeroOne,4);

    // Phase 2 : le 1er tour (avec le sel) ne change pas
    uint8_t U[32];
    // Code de AES_HMAC (puis de AES_SHA256 plus bas) renvoyé tel quel
    int code = AES_HMAC(U,(uint8_t*)password,size_password,mess,size_salt + 4);
    if(code != AES_OK){
        free(mess);
        return code;
    }
    free(mess);
    memcpy(dest, U, 32);

    /* Phase 3 : le MORCEAU 1, calculé UNE SEULE FOIS
     * Le morceau 1 (keyIn ou keyOut) ne dépend que du mot de passe :
     * son compressing donne toujours le même H (2223a11b et 8efd7f67
     * avec "password"). On le calcule ici et on garde le résultat
     * dans Hin et Hout, au lieu de le refaire à chaque tour.
     */

    // Même chose que AES_HMAC (Phase 1 et 2)
    uint8_t localKey[64] = {0};
    if(size_password > 64){
        code = AES_SHA256(localKey,(uint8_t*)password,size_password);
        if(code != AES_OK){
            uint8_tToZero(U, sizeof(U));
            return code;
        }
    }else{
        memcpy(localKey,password,size_password);
    }
    uint8_t keyIn[64];
    uint8_t keyOut[64];
    for(int i=0;i<64;i++){
        keyIn[i] = localKey[i] ^ 0x36;
        keyOut[i] = localKey[i] ^ 0x5c;
    }

    // Même chose que AES_SHA256 (H = HASH_CONST puis compressing),
    // mais seulement sur le morceau 1. Pas de padding : keyIn fait
    // déjà 64 octets, c'est un morceau complet.
    uint32_t Hin[8] = HASH_CONST;
    compressing(Hin, keyIn);
    uint32_t Hout[8] = HASH_CONST;
    compressing(Hout, keyOut);

    /* Phase 4 : le MORCEAU 2, préparé une fois
     * C'est le padding que AES_SHA256 ajoutait, fait à la main :
     *   octets 0 à 31  : les 32 octets à hacher (rempli dans la boucle)
     *   octet 32       : 0x80
     *   octets 33 à 61 : 0 (déjà à 0 grâce au = {0})
     *   octets 62 et 63: taille du message ENTIER en bits
     *                    = (64 + 32) octets * 8 = 768 bits = 0x0300
     * Le SHA intérieur et le SHA extérieur hachent tous les deux
     * 64 + 32 octets : le même morceau 2 sert aux deux, seuls les
     * octets 0 à 31 changent.
     */
    uint8_t morceau2[64] = {0};
    morceau2[32] = 0x80;
    morceau2[62] = 0x03;
    morceau2[63] = 0x00;

    uint32_t H[8];
    for(size_t i=1;i<tour;i++){
        // SHA intérieur : on repart de Hin (copie, car compressing modifie H)
        memcpy(morceau2, U, 32);
        memcpy(H, Hin, sizeof(H));
        compressing(H, morceau2);

        // On découpe H en 32 octets (comme AES_SHA256),
        // directement au début du morceau 2 pour le SHA extérieur
        for(size_t k=0;k<8;k++){
            morceau2[4*k]     = (uint8_t)(H[k] >> 24);
            morceau2[4*k + 1] = (uint8_t)(H[k] >> 16);
            morceau2[4*k + 2] = (uint8_t)(H[k] >> 8);
            morceau2[4*k + 3] = (uint8_t)(H[k]);
        }

        // SHA extérieur : on repart de Hout
        memcpy(H, Hout, sizeof(H));
        compressing(H, morceau2);

        // Le résultat devient le nouveau U
        for(size_t k=0;k<8;k++){
            U[4*k]     = (uint8_t)(H[k] >> 24);
            U[4*k + 1] = (uint8_t)(H[k] >> 16);
            U[4*k + 2] = (uint8_t)(H[k] >> 8);
            U[4*k + 3] = (uint8_t)(H[k]);
        }

        for(size_t j=0;j<32;j++){
            dest[j] ^= U[j];
        }
    }

    // Efface tout ce qui vient du mot de passe
    // (avec Hin et Hout, on peut calculer le HMAC sans connaître le mot de passe)
    uint8_tToZero(localKey, sizeof(localKey));
    uint8_tToZero(keyIn, sizeof(keyIn));
    uint8_tToZero(keyOut, sizeof(keyOut));
    uint8_tToZero((uint8_t*)Hin, sizeof(Hin));
    uint8_tToZero((uint8_t*)Hout, sizeof(Hout));
    uint8_tToZero((uint8_t*)H, sizeof(H));
    uint8_tToZero(morceau2, sizeof(morceau2));
    uint8_tToZero(U, sizeof(U));

    return AES_OK;
}