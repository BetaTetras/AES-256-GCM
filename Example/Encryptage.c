#include <stdio.h>
#include <stdint.h> 
#include <stdlib.h>
#include <string.h>
#include "../AES/AES.c"

int main(){

    // Création d'un tableau de 32 octet qui servira de clée de chiffrement
    uint8_t Cle[32];

    //Génération de la cle depuis une string (mot de passe)
    StringToKeyConverter("Password123",&Cle);

    // Chiffrement du fichier nommée "test.txt" avec la cle générée
    // AES_Encrypt_File("./Subaru.txt",Cle);
    AES_GCM_Encrypt_File("./Subaru.txt",Cle);

    // Le fichier est alord chiffrée de facon sécurisée est ne peut 
    // se faire déchiffrée uniquement grace a la clé générée ou pas
    // le mot de passe qui a permis de crée la clé de chiffrement 

    // AES_Decrypt_File("./Subaru.txt",Cle);
    // AES_GCM_Decrypt_File("./Encrypted",Cle);
    
    return 0;
}