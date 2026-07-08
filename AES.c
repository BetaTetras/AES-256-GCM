#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <string.h>

#define MA_CLE {0x00, 0x01, 0x02, 0x03, \
                0x04, 0x05, 0x06, 0x07, \
                0x08, 0x09, 0x0a, 0x0b, \
                0x0c, 0x0d, 0x0e, 0x0f, \
                0x10, 0x11, 0x12, 0x13, \
                0x14, 0x15, 0x16, 0x17, \
                0x18, 0x19, 0x1a, 0x1b, \
                0x1c, 0x1d, 0x1e, 0x1f}

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
void push(uint8_t ligne[4],int x);
void pop(uint8_t ligne[4], int x);

uint8_t xtime(uint8_t a);
uint8_t mul(uint8_t a, uint8_t b);
void MixColumns(uint8_t state[4][4]);
void InvMixColumns(uint8_t state[4][4]);

void RotWord(uint8_t ligne[4]);
void SubWord(uint8_t ligne[4]);
void Explode(uint8_t cle[32],word w[8]);
void GenerateKey(word finaleW[60],word initialW[8]);

void AES_Encrypt_state(uint8_t state[4][4], uint8_t cle[32]);
void AES_Decrypt_state(uint8_t state[4][4], uint8_t cle[32]);

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

int main(){
    uint8_t cle[32] = MA_CLE;

    uint8_t original[4][4] = {
        {0x00, 0x44, 0x88, 0xcc},
        {0x11, 0x55, 0x99, 0xdd},
        {0x22, 0x66, 0xaa, 0xee},
        {0x33, 0x77, 0xbb, 0xff}
    };

    // Copie de travail
    uint8_t state[4][4];
    memcpy(state, original, sizeof(state));

    printf("=== Plaintext ===\n");
    printState(state);

    AES_Encrypt_state(state, cle);
    printf("\n=== Chiffre ===\n");
    printState(state);

    AES_Decrypt_state(state, cle);
    printf("\n=== Dechiffre ===\n");
    printState(state);

    // Verification automatique
    printf("\n=== Verification ===\n");
    int ok = 1;
    for(int i = 0; i < 4 && ok; i++)
        for(int y = 0; y < 4 && ok; y++)
            if(state[i][y] != original[i][y]) ok = 0;

    printf(ok ? "OK - Identique au plaintext\n" : "ERREUR - Different du plaintext\n");

    return 0;
}

//////////////////////////////////////////////////////////

// Générée un state debug pour annalyse et verification
void initStateDebugAlpha(uint8_t state[4][4]){
    for(int i=0;i<4;i++){
        for(int y=0;y<4;y++){
            state[i][y] = 0xff;
        }
    }
}

// Générée un state debug pour annalyse et verification avec des valeur logique
void initStateDebugBeta(uint8_t state[4][4]){
    int index = 0;
    for(int i=0;i<4;i++){
        for(int y=0;y<4;y++){
            state[i][y] = index;
            index++;
        }
    }
}

//////////////////////////////////////////////////////////

// Affichage des hexa
void printState(uint8_t state[4][4]){
    for(int i = 0; i < 4; i++){
        for(int y = 0; y < 4; y++){
            printf("0x%02x ", state[i][y]);
        }
        printf("\n");
    }
}

// Affiche un mot
void printWord(word w, int index){
    printf("W[%02d] = %02x %02x %02x %02x\n", index, w[0], w[1], w[2], w[3]);
}

// Debug de clef 
void debugGenerateKey(word finaleW[60]){
    printf("=== DEBUG GenerateKey ===\n");
    for(int i=0;i<60;i++){
        printWord(finaleW[i], i);
    }
}

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


void Explode(uint8_t cle[32],word w[8]){
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

void AES_Encrypt_state(uint8_t state[4][4], uint8_t cle[32]){
    word ExplodedKey[8];
    Explode(cle,ExplodedKey);
    word GenratedKey[60];
    GenerateKey(GenratedKey,ExplodedKey);
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

void AES_Decrypt_state(uint8_t state[4][4], uint8_t cle[32]) {
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
}

//////////////////////////////////////////////////////////

void fileBinaryTrancription(uint8_t (*dest)[4][4], char* path){
    FILE *file = fopen(path, "rb");
    if(file == NULL){
        return;
    }

    fseek(file, 0, SEEK_END);
    size_t fileSize = ftell(file);
    rewind(file);

    uint8_t* datas = (uint8_t*)calloc(fileSize, sizeof(uint8_t));
    fread(datas, 1, fileSize, file);

    if(fileSize % 16 == 0){
        int index = 0;
        for(int j = 0; j < fileSize/16; j++){
            for(int k = 0; k < 4; k++){
                for(int l = 0; l < 4; l++){
                    dest[j][k][l] = datas[index++];
                }
            }
        }
    } else {
        int lastBloc = fileSize / 16;
        int octetRestant = fileSize % 16;
        uint8_t padding = 16 - octetRestant;  // ✅ déclaré ici
        int index = 0;

        for (int j = 0; j < lastBloc; j++){
            for (int k = 0; k < 4; k++){
                for (int l = 0; l < 4; l++){
                    dest[j][k][l] = datas[index++];
                }
            }
        }

        for (int i = 0; i < octetRestant; i++){
            dest[lastBloc][i / 4][i % 4] = datas[index++];
        }

        for (int i = octetRestant; i < 16; i++){
            dest[lastBloc][i / 4][i % 4] = padding;  // ✅ padding au lieu de missingOctet
        }
    }

    fclose(file);
    free(datas);
}