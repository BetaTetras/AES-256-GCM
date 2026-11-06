#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

/* Codes de retour de toutes les fonctions int ci-dessous.
 * 0 = réussite : un simple if(AES_GCM_Encrypt_File(...)) détecte toutes les erreurs. */
#define AES_OK                0   /* tout s'est bien passé */
#define AES_ERR_PARAM         1   /* mauvais argument : pointeur NULL, *dest pas à NULL, PBKDF2 avec tour == 0 */
#define AES_ERR_AUTH          2   /* tag faux : le mot de passe est bon, mais les données (nonce, chiffré, tag) ont été modifiées */
#define AES_ERR_VERSION       3   /* chiffré par une autre version du programme */
#define AES_ERR_MEMOIRE       4   /* malloc/calloc a échoué */
#define AES_ERR_ALEA          5   /* /dev/urandom ou BCryptGenRandom a échoué */
#define AES_ERR_OUVERTURE     6   /* impossible d'ouvrir le fichier (absent, droits) */
#define AES_ERR_TAILLE        7   /* taille illisible (tube) ou plus grosse que GCM_TAILLE_MAX */
#define AES_ERR_FORMAT        8   /* pas un chiffré valide : trop petit, trop gros, ou 0 tour dans l'en-tête */
#define AES_ERR_LECTURE       9   /* fread a lu moins que prévu (ou fseek raté) */
#define AES_ERR_CREATION     10   /* impossible de créer le .tmp (dossier en lecture seule) */
#define AES_ERR_DROITS       11   /* stat/chmod du .tmp a échoué (pas sous Windows) */
#define AES_ERR_ECRITURE     12   /* fwrite/fclose a échoué (disque plein...) */
#define AES_ERR_REMPLACEMENT 13   /* rename/MoveFileExA a échoué */
#define AES_ERR_MDP          14   /* mauvais mot de passe (ou sel, tours ou empreinte modifiés dans l'en-tête) */

/* Chiffrement de fichiers (API principale) */
int AES_GCM_Encrypt_File(char* path, char* password);
int AES_GCM_Decrypt_File(char* path, char* password);

/* Chiffrement en mémoire (même format que les fichiers chiffrés)
 * *dest doit valoir NULL : la fonction l'alloue, l'appelant le libère avec free.
 * Decrypt ajoute un '\0' après le texte (non compté dans *size_dest). */
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
