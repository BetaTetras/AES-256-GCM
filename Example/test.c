#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <string.h>
#include "../AES/AES.c"

int main(){

    int state;
    state = AES_GCM_Encrypt_File("./Subaru.txt", "monMotDePasse");
    printf("Code : %d\n", state);
    
    state = AES_GCM_Decrypt_File("./Subaru.txt","monMotDePasse");
    printf("Code : %d\n", state);

    return 0;
}