#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <string.h>

//                                           Les 8 premier nombre premier
//                  2          3           5          7          11         13         17         19
#define HASH_CONST {0x6a09e667,0xbb67ae85 ,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19}

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

int padding(uint8_t** dest,uint8_t* mess,size_t* size);
void compressing(uint32_t H[8], uint8_t* mess);
int SHA256(uint8_t* dest, uint8_t* mess, size_t size);

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
            return 1;
        }
        *dest = tmp;
    }else{
        return 1;
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
    return 0;
}

uint32_t ROTR(uint32_t num, size_t numberOfPush){
    uint32_t bit;
    for(size_t i = 0; i < numberOfPush; i++){
        // On sauvegarde le bit tout a droite
        bit = num << 31;
        // On décale les bit a droite de num
        num = num >> 1;
        // On Xor les deux
        num = num ^ bit;
    }
    return num;
}

uint32_t choose(uint32_t x, uint32_t y, uint32_t z){
    uint32_t bit;
    uint32_t res = 0;
    for(size_t i = 0; i < 32; i++){
        // On sauvegarde le bit x
        bit = x << i;
        bit = bit >> 31;
        if(bit == 1){
            // x vaut 1 : on sauvegarde le bit y
            bit = y << i;
            bit = bit >> 31;
        }else{
            // x vaut 0 : on sauvegarde le bit z
            bit = z << i;
            bit = bit >> 31;
        }
        // On le replace a la bonne place
        bit = bit << (31 - i);

        res = res ^ bit;
    }
    return res;
}

uint32_t majority(uint32_t x, uint32_t y, uint32_t z){
    uint32_t bit;
    int buffer;
    uint32_t res = 0;
    for(size_t i = 0; i < 32; i++){
        // On sauvegarde le bit x
        bit = x << (31 - i);
        bit = bit >> 31;
        buffer = (int)bit;

        // On sauvegarde le bit y
        bit = y << (31 - i);
        bit = bit >> 31;
        buffer = buffer + (int)bit;

        // On sauvegarde le bit z
        bit = z << (31 - i);
        bit = bit >> 31;
        buffer = buffer + (int)bit;

        // Si au moins 2 bits valent 1, on met un 1 en position i
        if(buffer >= 2){
            bit = (uint32_t)1;
            bit = bit << i;
            res = res ^ bit;
        }
    }
    return res;
}

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

void compressing(uint32_t H[8], uint8_t* mess){   // CORRIGÉ : H en paramètre
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


int SHA256(uint8_t* dest, uint8_t* mess, size_t size){
    uint32_t H[8] = HASH_CONST;
    uint8_t* buffer = NULL;

    // 1. Padding : size devient la taille du buffer paddé
    if (padding(&buffer, mess, &size) != 0) {
        return 1;
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

    free(buffer);
    return 0;
}

int HMAC(uint8_t* dest,uint8_t* key,size_t size_key,uint8_t* mess,size_t size_mess){
    if(dest == NULL){
        return 1;
    }
    // Phase 1
    uint8_t localKey[64] = {0};
    if(size_key > 64){
        if(SHA256(localKey,key,size_key) == 1){
            return 1;
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
        return 1;
    }
    memcpy(buffer,keyIn,64);
    memcpy(buffer+64,mess,size_mess);

    uint8_t hached[32];
    if(SHA256(hached,buffer,64 + size_mess)){
        free(buffer);
        return 1;
    }
    free(buffer);

    // Phase 4
    uint8_t bufferOut[96];
    memcpy(bufferOut,keyOut,64);
    memcpy(bufferOut+64,hached,32);

    if(SHA256(dest,bufferOut,96)){
        return 1;
    }

    return 0;
}

int PBKDF2(uint8_t* dest,char* password,size_t size_password,uint8_t* salt,size_t size_salt,size_t tour){
    if(dest == NULL || tour == 0){
        return 1;
    }

    // Phase 1
    uint8_t ZeroOne[4] = {0x00,0x00,0x00,0x01};
    uint8_t *mess = calloc(size_salt + 4,sizeof(uint8_t));
    if(mess == NULL){
        return 1;
    }
    memcpy(mess,salt,size_salt);
    memcpy(mess+size_salt,ZeroOne,4);

    // Phase 2
    uint8_t U[32];
    if(HMAC(U,(uint8_t*)password,size_password,mess,size_salt + 4) == 1){
        free(mess);
        return 1;
    }
    free(mess);

    memcpy(dest, U, 32);
    uint8_t Unext[32];
    for(size_t i=1;i<tour;i++){
        if(HMAC(Unext,(uint8_t*)password,size_password,U,32) == 1){
            return 1;
        }
        memcpy(U,Unext,32);
        for(size_t j=0;j<32;j++){
            dest[j] ^= U[j];
        }
    }

    return 0;

}