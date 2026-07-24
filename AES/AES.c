#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <string.h>

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

int ByteTranscription(char* path,int *NbState,uint8_t (**dest)[4][4]);

void StringToKeyConverter(const char* str,uint8_t (*key)[32]);

int AES_Encrypt_File(char* path,uint8_t key[32]);
int AES_Decrypt_File(char* path,uint8_t key[32]);

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

int ByteTranscription(char* path,int *NbState,uint8_t (**dest)[4][4]){
    // On ouvre le fichier en readBinary (rb)
    FILE* file = fopen(path, "rb");
    if(!file){
        return 1;
    }

    // On détermine la taille du fichier 
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    rewind(file);

    if(size == 0){
        fclose(file);
        return 1;
    }

    // Les octet en trop si fichier non multiple de 16
    // On détermine le nombre de state
    if(size % 16 == 0){
        *NbState = size / 16;
    }else{
        *NbState = (size / 16) + 1;
    }

    // On réalloue dest pour qu'il sois de la taille du nombre de state
    *dest = realloc(*dest, (*NbState) * sizeof(uint8_t[4][4]));

    for(int state=0;state<*NbState;state++){
        uint8_t buffer[16] = {0};
        fread(buffer, 1, 16, file);

        int index = 0;
        for(int colonne = 0; colonne < 4; colonne++){
            for(int ligne = 0; ligne < 4; ligne++){
                (*dest)[state][ligne][colonne] = buffer[index++];
            }
        }
    }

    fclose(file);
    return 0;
}

int AES_Encrypt_File(char* path,uint8_t key[32]){
    // Appelle d'un pointeur vers une liste de states
    uint8_t (*b_file)[4][4] = NULL;
    int NbState;

    // Transcription du fichier en pointeur de liste de state
    if(ByteTranscription(path,&NbState,&b_file) == 1){
        return 1;
    }

    // Ouverture du fichier pour check la taille du fichier (nombre d'octet)
    FILE* fcheck = fopen(path,"rb");
    if(!fcheck){
        free(b_file);
        return 1;
    }
    fseek(fcheck, 0, SEEK_END);
    long size = ftell(fcheck);
    fclose(fcheck);

    // On détermine si on a besoin de padding si la taille du fichier est un mutiple de 16 
    int padding;
    if(size % 16 == 0){
        padding = 16;

        // On ajoute un state de padding entier si c'est un multiple
        b_file = realloc(b_file, (NbState + 1) * sizeof(uint8_t[4][4]));
        for(int ligne=0; ligne<4; ligne++){
            for(int colonne=0; colonne<4; colonne++){
                b_file[NbState][ligne][colonne] = 16;
            }
        }
        NbState++;
    }else{
        padding = 16 - (size % 16);

        for(int i = size % 16; i < 16; i++){
            int colonne = i / 4;
            int ligne = i % 4;
            b_file[NbState-1][ligne][colonne] = (uint8_t)padding;
        }
    }

    // Ecriture du fichier encryptée 
    FILE* file = fopen(path,"wb");
    if(!file){
        free(b_file);
        return 1;
    }

    uint8_t buffeur_state[4][4];
    for(int i=0;i<NbState;i++){
        memcpy(buffeur_state, b_file[i], sizeof(buffeur_state));
        AES_Encrypt_state(buffeur_state,key);

        for(int colonne = 0; colonne < 4; colonne++){
            for(int ligne = 0; ligne < 4; ligne++){
                fwrite(&buffeur_state[ligne][colonne], 1, 1, file);
            }
        }
    }

    fclose(file);
    free(b_file);
    return 0;
}

int AES_Decrypt_File(char* path,uint8_t key[32]){
    uint8_t (*b_file)[4][4] = NULL;
    int NbState;

    if(ByteTranscription(path,&NbState,&b_file) == 1){
        return 1;
    }

    // On décrypte tout le fichier 
    for(int i=0;i<NbState;i++){
        AES_Decrypt_state(b_file[i], key);
    }

    // Le dernier state on le mes de cotée a cause du padding
    // Rappel : Si NbState = 2 alors il y'a b_file[0] et b_file[1] et donc b_file[2] = OOM
    uint8_t padding = b_file[NbState-1][3][3];
    // Nombre d'Octet a écrire
    long NombreOctet = (long)NbState * 16 - padding;

    FILE* file = fopen(path,"wb");
    if(!file){
        free(b_file);
        return 1;
    }

    // On suis le nombre d'octet écrit pour le padding 
    long indexOctet = 0;
    for(int i=0;i<NbState;i++){
        for(int colonne = 0; colonne < 4; colonne++){
            for(int ligne = 0; ligne < 4; ligne++){
                if(indexOctet < NombreOctet){
                    fwrite(&b_file[i][ligne][colonne], 1, 1, file);
                    indexOctet++;
                }
            }
        }
    }

    fclose(file);
    free(b_file);
    return 0;
}

//////////////////////////////////////////////////////////

void ConterBlockGenerator(uint8_t state[4][4], uint8_t nonce[12],int compteur){
    uint8_t buffer[16];
    memcpy(buffer, nonce, 12);

    /* Pour transformée un nombre (compteur) en 4 octet pour la suite du code
     * il faut extraire les 4 octet que constitue un int standare car un 
     * int est en sois un uint32_t.
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
    // On def res a 0 sur ses 16 octet
    memset(res,0x00,16);
    // On crée un copy par ce que a est une const
    uint8_t a_CPY[16];
    // On copy a dans a_CPY
    memcpy(a_CPY, a, 16);

    // Sur chaque bit (16*8 = 128)
    for(int i = 0; i < 128;i++){
        // Pour extraire le bit numéro i du tableau b de 16 octets.
        int bit = (b[i / 8] >> (7 - (i % 8))) & 1;
        if(bit){
            for(int j=0; j<16;j++){
                res[j] ^= a_CPY[j];
            }
        }

        // Most Significant Bit 
        uint8_t msb = (a_CPY[0] >> 7) & 1;


        /* En gros dans la suite de mon code on décale d'un bit vers la GAUCHE
         * sur TOUT les octete confondu :
         *   Octet5    Octet4   Octet3    Octet2    Octet1
         * [10000000][10000000][00001100][00000000][00000010]
         * [00000001][00000000][00011000][00000000][00000101]
        */
        int extra = 0;
        uint8_t buffer;
        int index = 15;
        for(int j=0;j<16;j++){
            buffer = a_CPY[index];
            a_CPY[index] = a_CPY[index] << 1;
            if(extra){
                a_CPY[index] = a_CPY[index] | 0x01;
            }
            extra = 0;
            extra =  buffer >> 7;
            index --;
        }
        if(extra == 1){
            a_CPY[15] = a_CPY[15] | 0x01;
        }
        if(msb == 1){
            a_CPY[15] ^= 0x87;
        }
    
    }
}

void GHASH(uint8_t tag[16],const uint8_t (*Stats)[4][4], const int NbState,const uint8_t key[32]){
    // En gros dans cette partie on crée une state remplis de 0 puis on
    // la chiffre avec la cle afin de générée une suite linaire (donc
    // pas de [4]x[4] mais direct 16) de cette state
    uint8_t bufferState[4][4];
    memset(bufferState,0,16);
    AES_Encrypt_state(&bufferState,key);

    uint8_t zeroEncrypted[16];
    memcpy(zeroEncrypted,(uint8_t*)bufferState,16);

    uint8_t accumulateur[16] = {0x00};
    
    for(int i=0;i<NbState;i++){
        int index = 0;
        for(int colonne = 0; colonne < 4; colonne++){
            for(int ligne = 0; ligne < 4; ligne++){
                accumulateur[index] ^= Stats[i][ligne][colonne];
                index ++;
            }
        }

        uint8_t temp[16];
        gf128_multiply(temp,accumulateur,zeroEncrypted);
        memcpy(accumulateur,temp,16);
    }
    memcpy(tag, accumulateur, 16);
}

int AES_GCM_Encrypt_File(char* path,uint8_t key[32]){
    // GENERATION DE LA NONCE
    FILE *f = fopen("/dev/urandom", "rb");
    if(f == NULL){
        return 1;
    }
    uint8_t nonce[12];
    if(fread(nonce, sizeof(uint8_t), 12, f)!= 12){
        fclose(f);
        return 1;
    }
    fclose(f);

    // RECUPERATION DES STATS
    // b_file = liste de state du fichier a chiffrée
    // NbState = Nombre de state de se fichiée
    uint8_t (*b_file)[4][4] = NULL;
    int NbState;
    if(ByteTranscription(path,&NbState,&b_file) == 1){
        return 1;
    }

    // CHIFFREMENT DES DONNEES
    uint8_t (*ciphertext)[4][4] = calloc(NbState,sizeof(uint8_t[4][4]));
    for(int compteur=0;compteur<NbState;compteur++){
        uint8_t CompteurBlockState[4][4];
        ConterBlockGenerator(&CompteurBlockState,nonce,compteur);
        AES_Encrypt_state(CompteurBlockState,key);

        for(int ligne = 0; ligne < 4; ligne++){
            for(int colonne = 0; colonne < 4; colonne++){
                ciphertext[compteur][ligne][colonne] = b_file[compteur][ligne][colonne] ^ CompteurBlockState[ligne][colonne];
            }
        }
    }

    // GENERATION DU TAG
    uint8_t tag[16];
    GHASH(tag,ciphertext,NbState,key);


    FILE* file = fopen(path,"wb");
    if(file == NULL){
        free(b_file);
        return 1;
    }   
    
    // ECRITURE DE LA NONCE
    fwrite(nonce,1,12,file);

    // ECRITURE DU CIPHERTEXT
    for(int i=0;i<NbState;i++){
        for(int colonne = 0; colonne < 4; colonne++){
            for(int ligne = 0; ligne < 4; ligne++){
                fwrite(&ciphertext[i][ligne][colonne],1,1,file);
            }
        }
    }

    // ECRITURE DU TAG
    fwrite(tag, 1, 16, file);

    free(b_file);
    fclose(file);
    free(ciphertext);

    return 0;
}
//////////////////////////////////////////////////////////

// Génére une clé sous uint8_t depuis une string de 0 a +inf char
void StringToKeyConverter(const char* str,uint8_t (*key)[32]){
    int len = strlen(str);
    char* cpyStr = (char*)calloc(len+1,sizeof(char));
    strcpy(cpyStr,str);
    cpyStr[len] = '\0';

    for(int i=0;i<32;i++){
        (*key)[i] = 0x00;
    }

    for(int i=0;i<len;i++){
        (*key)[i % 32] = (uint8_t)cpyStr[i] ^ (*key)[i % 32];
    }

    for(int i=0;i<10;i++){
        for(int y=0;y<32;y++){
            if(y==0){
                (*key)[y] = SBOX[(*key)[y]] ^ (*key)[31];
            }else{
                (*key)[y] = SBOX[(*key)[y]] ^ (*key)[(y-1)%32];
            }
        }
    }

    free(cpyStr);
}