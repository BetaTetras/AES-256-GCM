# AES-256-GCM + PBKDF2 en C

🇬🇧 [English version](README.en.md)

Bibliothèque C de chiffrement par mot de passe, de fichiers ou de données en mémoire, écrite entièrement à la main : AES-256, mode GCM (CTR + GHASH), SHA-256, HMAC-SHA256 et PBKDF2. Elle n'utilise aucune bibliothèque externe : seulement la bibliothèque standard C et quelques fonctions du système (hasard, droits et remplacement de fichiers).

Un appel suffit pour chiffrer un fichier en place, ou un tampon en mémoire, avec un mot de passe ; le déchiffrement vérifie l'intégrité des données avant de rendre quoi que ce soit.

> [!WARNING]
> **Projet pédagogique, non audité.** Le code n'a fait l'objet d'aucune revue de sécurité. Pour protéger des données réelles, utilisez une bibliothèque éprouvée comme libsodium ou OpenSSL.

---

## Table des matières

- [Fonctionnalités](#fonctionnalités)
- [Démarrage rapide](#démarrage-rapide)
  - [1. L'en-tête](#1-len-tête)
  - [2. Exemple : petit outil en ligne de commande](#2-exemple--petit-outil-en-ligne-de-commande)
  - [3. Compiler et lancer](#3-compiler-et-lancer)
- [API](#api)
  - [Chiffrement de fichiers (API principale)](#chiffrement-de-fichiers-api-principale)
  - [Chiffrement en mémoire](#chiffrement-en-mémoire)
  - [Codes de retour](#codes-de-retour)
  - [Primitives cryptographiques](#primitives-cryptographiques)
- [Format des données chiffrées](#format-des-données-chiffrées)
- [Fonctionnement interne](#fonctionnement-interne)
  - [Organisation du code](#organisation-du-code)
  - [Paramètres](#paramètres)
- [Conformité et tests](#conformité-et-tests)
  - [Compatibilité](#compatibilité)
- [Performances](#performances)
- [Limites connues](#limites-connues)
- [Licence](#licence)
- [Références](#références)

---

## Fonctionnalités

- **AES-256** conforme à FIPS-197 (14 rondes, expansion de clé en 60 mots).
- **Chiffrement authentifié AES-256-GCM** conforme à NIST SP 800-38D : chiffrement en mode compteur (CTR) et tag d'authentification de 16 octets. Les données chiffrées sont lisibles par toute autre implémentation GCM (voir [Compatibilité](#compatibilité)).
- **Dérivation de clé PBKDF2-HMAC-SHA256** avec **600 000 itérations** (recommandation OWASP) : la clé de 32 octets est dérivée du mot de passe et d'un sel aléatoire. Le nombre d'itérations est **enregistré dans le fichier** : il pourra être augmenté dans une version future sans rendre illisibles les fichiers existants.
- **Mauvais mot de passe reconnu** : une empreinte de la clé (HMAC-SHA256) rangée dans l'en-tête distingue un mauvais mot de passe (code `14`) de données modifiées (code `2`). Le mauvais mot de passe est refusé juste après PBKDF2, sans lire les données : ≈ 1,4 s, quelle que soit la taille du fichier.
- **Sel et nonce aléatoires** tirés du générateur aléatoire du système (`/dev/urandom`, ou `BCryptGenRandom` sous Windows) à chaque chiffrement : chiffrer deux fois les mêmes données avec le même mot de passe donne deux résultats différents.
- **Chiffrement de fichiers ou en mémoire** : `AES_GCM_Encrypt` / `AES_GCM_Decrypt` travaillent sur un tampon, sans rien écrire sur le disque, et produisent exactement le même format qu'un fichier chiffré.
- **Pas de padding** : le texte chiffré a exactement la taille des données d'origine (+ 81 octets d'en-tête et de tag).
- **Fichiers traités par blocs de 16 octets** : la mémoire utilisée reste constante, quelle que soit la taille du fichier.
- **Écriture sûre** : le résultat est écrit dans `<fichier>.tmp` puis renommé. Chaque écriture est vérifiée : en cas de mauvais mot de passe, de fichier altéré ou de disque plein, le `.tmp` est supprimé et l'original reste intact. Sous Linux, macOS et BSD, le fichier garde ses droits d'accès (un fichier en `600` reste en `600`) ; sous Windows, il prend ceux de son dossier. Un fichier trop gros, ou dont la taille ne peut pas être lue, est refusé sans être modifié.
- **Hygiène mémoire** : la clé et ses copies (sous-clés AES), ainsi que les valeurs intermédiaires de PBKDF2, HMAC et SHA-256, sont effacées avant chaque retour, avec une écriture `volatile` que le compilateur ne peut pas supprimer. Les tampons alloués sont effacés avant d'être libérés. Le tag et l'empreinte de la clé sont comparés en temps constant.

---

## Démarrage rapide

### 1. L'en-tête

Le code tient dans un seul fichier source, `AES.c`. L'en-tête `AES.h` contient les prototypes publics :

```c
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
```

### 2. Exemple : petit outil en ligne de commande

```c
#include <stdio.h>
#include <string.h>
#include "AES.h"

int main(int argc, char *argv[]) {
    if (argc != 4) {
        fprintf(stderr, "Usage : %s <chiffrer|dechiffrer> <fichier> <mot_de_passe>\n", argv[0]);
        return 1;
    }

    int r;
    if (strcmp(argv[1], "chiffrer") == 0) {
        r = AES_GCM_Encrypt_File(argv[2], argv[3]);
    } else {
        r = AES_GCM_Decrypt_File(argv[2], argv[3]);
    }

    if (r == AES_OK)               puts("OK");
    else if (r == AES_ERR_MDP)     puts("Mot de passe incorrect");
    else if (r == AES_ERR_AUTH)    puts("Fichier altéré");
    else if (r == AES_ERR_VERSION) puts("Fichier chiffré avec une autre version (format inconnu)");
    else                           printf("Erreur %d (voir les codes de retour)\n", r);
    return r;
}
```

> Pour l'exemple, le mot de passe est passé en argument. Dans un vrai programme, il vaut mieux le saisir au clavier : un argument de ligne de commande reste visible dans l'historique du shell et dans la liste des processus.

### 3. Compiler et lancer

**Linux, macOS, BSD :**

```bash
gcc -std=c11 -Wall -Wextra -O2 -o aescli main.c AES.c

./aescli chiffrer   note.txt "mon mot de passe"
./aescli dechiffrer note.txt "mon mot de passe"
```

**Windows (MinGW-w64, par exemple avec MSYS2) :** ajouter `-lbcrypt`, la bibliothèque de Windows qui fournit `BCryptGenRandom` :

```bat
gcc -std=c11 -Wall -Wextra -O2 -o aescli.exe main.c AES.c -lbcrypt

aescli.exe chiffrer   note.txt "mon mot de passe"
aescli.exe dechiffrer note.txt "mon mot de passe"
```

**Plateformes :**

- **Linux, macOS, BSD** : tout système POSIX fournissant `/dev/urandom`.
- **Windows** : avec MinGW-w64. Le code compile sans avertissement (`-Wall -Wextra -pedantic`), mais n'a **pas encore été testé sur une machine Windows**. Visual Studio (MSVC) n'a pas été essayé.

Les différences entre systèmes sont isolées dans des blocs `#ifdef _WIN32` de `AES.c` : source de hasard, lecture de la taille du fichier (`ftell` / `_ftelli64`, car un `long` ne fait que 32 bits sous Windows), remplacement du fichier (`rename` / `MoveFileExA`) et copie des droits d'accès (Linux, macOS, BSD seulement).

---

## API

### Chiffrement de fichiers (API principale)

```c
int AES_GCM_Encrypt_File(char* path, char* password);
int AES_GCM_Decrypt_File(char* path, char* password);
```

| Paramètre  | Description |
|------------|-------------|
| `path`     | Chemin du fichier. Il est **remplacé** par sa version chiffrée (ou déchiffrée). |
| `password` | Mot de passe, chaîne C terminée par `\0`. |

Retour : `0` en cas de succès, sinon un code d'erreur (voir [Codes de retour](#codes-de-retour)). En cas d'erreur, le fichier d'origine est intact et aucun `.tmp` ne reste.

Le déchiffrement se fait en deux passes : la première calcule et vérifie le tag sans rien écrire ; la seconde déchiffre dans `<fichier>.tmp`, revérifie le tag, puis renomme.

### Chiffrement en mémoire

```c
int AES_GCM_Encrypt(uint8_t** dest, size_t* size_dest, uint8_t* src, size_t size_src, char* password);
int AES_GCM_Decrypt(uint8_t** dest, size_t* size_dest, uint8_t* src, size_t size_src, char* password);
```

| Paramètre | Description |
|-----------|-------------|
| `dest` | Adresse d'un pointeur qui doit valoir `NULL`. La fonction alloue le résultat et y met son adresse ; l'appelant le libère avec `free`. |
| `size_dest` | Reçoit la taille du résultat : `size_src + 81` pour `AES_GCM_Encrypt`, `size_src - 81` pour `AES_GCM_Decrypt`. |
| `src`, `size_src` | Données d'entrée : le texte clair (`AES_GCM_Encrypt`) ou les données chiffrées (`AES_GCM_Decrypt`). |
| `password` | Mot de passe, chaîne C terminée par `\0`. |

Retour : `0` en cas de succès, sinon un code d'erreur (voir [Codes de retour](#codes-de-retour)). En cas d'erreur, `*dest` reste `NULL`.

- Le résultat de `AES_GCM_Encrypt` a exactement le format d'un fichier chiffré : on peut l'écrire tel quel dans un fichier et le relire avec `AES_GCM_Decrypt_File`, et inversement.
- `AES_GCM_Decrypt` ajoute un `'\0'` après le texte (non compté dans `*size_dest`) : un texte déchiffré, du JSON par exemple, s'utilise directement comme chaîne C.
- Le texte déchiffré est sensible : effacez-le avant de le libérer, avec une boucle d'écriture `volatile` (un simple `memset` juste avant `free` peut être supprimé par le compilateur).

```c
const char* json = "{\"site\":\"exemple\",\"mdp\":\"secret\"}";
uint8_t* chiffre = NULL;  size_t taille_chiffre = 0;
uint8_t* clair   = NULL;  size_t taille_clair   = 0;

if (AES_GCM_Encrypt(&chiffre, &taille_chiffre, (uint8_t*)json, strlen(json), "mon mot de passe") != 0) {
    puts("Erreur de chiffrement");
    return 1;
}

int r = AES_GCM_Decrypt(&clair, &taille_clair, chiffre, taille_chiffre, "mon mot de passe");
if (r == AES_OK)               printf("%s\n", (char*)clair);   /* '\0' ajouté par AES_GCM_Decrypt */
else if (r == AES_ERR_MDP)     puts("Mot de passe incorrect");
else if (r == AES_ERR_AUTH)    puts("Données altérées");
else if (r == AES_ERR_VERSION) puts("Données chiffrées avec une autre version");

free(chiffre);
free(clair);   /* effacer clair avant s'il contient des secrets */
```

### Codes de retour

Toutes les fonctions qui renvoient un `int` utilisent les mêmes codes, définis dans `AES.h`. `0` (`AES_OK`) veut dire succès : un simple `if (r != AES_OK)` détecte n'importe quelle erreur, et la comparaison avec les noms ci-dessous dit laquelle.

| Code | Nom | Signification | Renvoyé par |
|:----:|-----|---------------|-------------|
| `0` | `AES_OK` | Succès | toutes |
| `1` | `AES_ERR_PARAM` | Mauvais argument : pointeur `NULL`, `*dest` différent de `NULL`, `PBKDF2` appelé avec `tour` = 0 | `AES_GCM_Encrypt`, `AES_GCM_Decrypt`, `AES_HMAC`, `PBKDF2` |
| `2` | `AES_ERR_AUTH` | **Données modifiées** : le mot de passe est bon, mais le tag est faux (nonce, chiffré ou tag modifié) | les deux fonctions de déchiffrement |
| `3` | `AES_ERR_VERSION` | **Version inconnue** : le premier octet n'est pas `8`, par exemple des données chiffrées avec la V7 ou avant (voir [Compatibilité](#compatibilité)) | les deux fonctions de déchiffrement |
| `4` | `AES_ERR_MEMOIRE` | Allocation impossible (`calloc`) | toutes |
| `5` | `AES_ERR_ALEA` | Générateur aléatoire indisponible (`/dev/urandom` ou `BCryptGenRandom`) | les deux fonctions de chiffrement |
| `6` | `AES_ERR_OUVERTURE` | Fichier introuvable ou sans droit de lecture (`fopen` raté) | les deux fonctions fichier |
| `7` | `AES_ERR_TAILLE` | Taille illisible (tube nommé, dossier) ou données plus grosses que la taille maximale (voir [Limites connues](#limites-connues)) | les deux fonctions de chiffrement ; `AES_GCM_Decrypt_File` pour une taille illisible |
| `8` | `AES_ERR_FORMAT` | Pas des données chiffrées valides : moins de 81 octets, plus que la taille maximale + 81 octets, ou 0 itération dans l'en-tête | les deux fonctions de déchiffrement |
| `9` | `AES_ERR_LECTURE` | Lecture interrompue (`fread` ou `fseek` raté, fichier raccourci pendant l'opération) | les deux fonctions fichier |
| `10` | `AES_ERR_CREATION` | Impossible de créer `<fichier>.tmp` (dossier en lecture seule, par exemple) | les deux fonctions fichier |
| `11` | `AES_ERR_DROITS` | Impossible de copier les droits d'accès sur le `.tmp` (`stat` ou `chmod` raté ; Linux, macOS, BSD seulement) | les deux fonctions fichier |
| `12` | `AES_ERR_ECRITURE` | Écriture impossible (`fwrite` ou `fclose` raté, disque plein) | les deux fonctions fichier |
| `13` | `AES_ERR_REMPLACEMENT` | Impossible de remplacer l'original par le `.tmp` (`rename` ou `MoveFileExA` raté) | les deux fonctions fichier |
| `14` | `AES_ERR_MDP` | **Mauvais mot de passe** : l'empreinte de la clé ne correspond pas à celle de l'en-tête. Aussi renvoyé si le sel, le nombre d'itérations ou l'empreinte ont été modifiés dans l'en-tête | les deux fonctions de déchiffrement |

En cas d'erreur, rien n'est modifié : pour les fichiers, l'original est intact et aucun `.tmp` ne reste ; en mémoire, `*dest` reste `NULL`.

**Mauvais mot de passe (`14`) ou données modifiées (`2`) ?** Le déchiffrement fait deux vérifications, dans cet ordre :

1. Juste après PBKDF2, il recalcule l'**empreinte de la clé** et la compare à celle de l'en-tête. Si elles diffèrent, la clé est fausse : code `14`. Aucune donnée n'est lue.
2. Ensuite seulement, il calcule le **tag** sur les données. S'il est faux alors que la clé est bonne, ce sont les données qui ont été modifiées : code `2`.

Un sel ou un nombre d'itérations modifié donne une autre clé, donc une autre empreinte : ce cas répond aussi `14`. Le code `14` veut donc dire « mauvais mot de passe, ou en-tête modifié ». Le code `2`, lui, n'apparaît qu'avec le bon mot de passe.

```c
int r = AES_GCM_Decrypt_File("note.txt", "mon mot de passe");
if (r == AES_OK)                 puts("OK");
else if (r == AES_ERR_MDP)       puts("Mot de passe incorrect");
else if (r == AES_ERR_AUTH)      puts("Fichier altéré");
else if (r == AES_ERR_OUVERTURE) puts("Fichier introuvable");
else                             printf("Erreur %d\n", r);
```

### Primitives cryptographiques

Ces fonctions sont utilisables séparément. Le préfixe `AES_` de `AES_SHA256` et `AES_HMAC` évite le conflit de noms avec les fonctions `SHA256` et `HMAC` d'OpenSSL.

| Fonction | Rôle | Sortie | Retour |
|----------|------|--------|--------|
| `AES_Encrypt_State(state, cle)` | Chiffre **un** bloc de 16 octets en place avec une clé de 32 octets. | `state` modifié | — |
| `AES_Decrypt_State(state, cle)` | Déchiffre un bloc de 16 octets en place. | `state` modifié | — |
| `AES_SHA256(dest, mess, size)` | Empreinte SHA-256 de `size` octets. | `dest` : 32 octets | `0`, ou `4` (allocation) |
| `AES_HMAC(dest, key, size_key, mess, size_mess)` | HMAC-SHA256 (clé de n'importe quelle taille). | `dest` : 32 octets | `0`, `1` (`dest` à `NULL`) ou `4` (allocation) |
| `PBKDF2(dest, password, size_password, salt, size_salt, tour)` | PBKDF2-HMAC-SHA256 avec `tour` itérations (≥ 1). | `dest` : **32 octets** (taille fixe) | `0`, `1` (`dest` à `NULL` ou `tour` = 0) ou `4` (allocation) |

**Disposition d'un bloc AES.** Comme dans FIPS-197, la matrice `state[ligne][colonne]` est remplie **colonne par colonne** : l'octet `i` du bloc va dans `state[i % 4][i / 4]`.

```
octets 00 01 02 … 0f   →   0x00 0x04 0x08 0x0c
                           0x01 0x05 0x09 0x0d
                           0x02 0x06 0x0a 0x0e
                           0x03 0x07 0x0b 0x0f
```

```c
/* Charger 16 octets dans un state, chiffrer, relire */
uint8_t state[4][4];
for (int i = 0; i < 16; i++) state[i % 4][i / 4] = bloc[i];
AES_Encrypt_State(state, cle);
for (int i = 0; i < 16; i++) bloc[i] = state[i % 4][i / 4];
```

---

## Format des données chiffrées

Le format est le même pour un fichier et pour un tampon en mémoire. Pour des données d'origine de **N** octets, le résultat fait **N + 81** octets :

```
[Version - 1 o][Nombre d'itérations - 4 o][Sel - 16 o][Nonce - 12 o][Empreinte - 32 o][Chiffré - N o][Tag - 16 o]
```

| Position (octets) | Taille | Contenu |
|-------------------|:------:|---------|
| `0`               | 1  | Version du format : `8` |
| `1` – `4`         | 4  | Nombre d'itérations PBKDF2, entier non signé de 32 bits, poids fort en premier (600 000 = `00 09 27 C0`) |
| `5` – `20`        | 16 | Sel PBKDF2, aléatoire |
| `21` – `32`       | 12 | Nonce, aléatoire |
| `33` – `64`       | 32 | Empreinte de la clé : HMAC-SHA256(K, `"Say thx to Tetras"`) |
| `65` – `64+N`     | N  | Texte chiffré (même taille que l'original) |
| `65+N` – `80+N`   | 16 | Tag d'authentification |

Le chiffrement écrit la valeur de `PBKDF2_TOURS` ; le déchiffrement utilise le nombre d'itérations lu dans le fichier. Augmenter `PBKDF2_TOURS` dans une version future ne rendra donc pas illisibles les fichiers déjà chiffrés.

L'en-tête ne fait pas partie du tag, mais il ne peut pas être modifié sans être détecté : une autre version est refusée (code `3`) ; un autre nombre d'itérations ou un autre sel donnent une autre clé, donc une autre empreinte (code `14`), comme une empreinte modifiée ; une autre nonce change le masque du tag (code `2`).

**L'empreinte n'aide pas à deviner le mot de passe.** Pour tester un mot de passe, il faut toujours passer par PBKDF2 et ses 600 000 itérations, exactement comme avec le tag. Elle ne révèle rien non plus de la clé, puisque HMAC est à sens unique. Elle permet seulement de refuser un mauvais mot de passe sans lire les données.

---

## Fonctionnement interne

```
mot de passe ──┐
               ├──►  PBKDF2-HMAC-SHA256 (itérations de l'en-tête, 600 000 au chiffrement)  ──►  clé K (32 octets)
sel (16 o) ────┘

Empreinte = HMAC-SHA256(K, "Say thx to Tetras")       comparée à celle de l'en-tête, avant de lire les données
H         = AES-256(K, 0¹²⁸)                          clé du hachage GHASH
Bloc i    = nonce ‖ compteur (i + 2)                  compteur sur 32 bits, poids fort en premier
Chiffré i = Clair i ⊕ AES-256(K, Bloc i)              mode CTR ; dernier bloc tronqué
S         = GHASH_H(blocs chiffrés ‖ bloc longueur)   bloc longueur = 0⁶⁴ ‖ taille en bits (64 bits)
Tag       = S ⊕ AES-256(K, nonce ‖ 00 00 00 01)
```

- Le **bloc longueur** empêche d'ajouter ou de retirer des blocs sans changer le tag.
- Le **masque** `AES(K, nonce ‖ 1)` lie le tag à la nonce et cache la valeur de GHASH, donc de H.
- La **multiplication dans GF(2¹²⁸)** suit la convention de GCM : bits rangés à l'envers, décalage vers la droite et réduction par `0xE1` sur le premier octet (SP 800-38D, § 6.3).
- La **comparaison du tag** parcourt toujours les 16 octets et cumule les différences (`diff |= a ^ b`) sans branchement : sa durée ne dépend pas du nombre d'octets corrects. L'empreinte (32 octets) est comparée de la même façon.
- La **clé AES étendue** (les 60 mots des 15 clés de ronde) est calculée une seule fois par fonction GCM, puis utilisée pour tous les blocs par `AES_Encrypt_Rondes`, et effacée avant chaque retour.
- **`gf128_multiply`** range les 16 octets dans deux `uint64_t` : un XOR ou un décalage traite alors 8 octets d'un coup.
- **PBKDF2** : à chaque itération, HMAC hache `clé ⊕ ipad` et `clé ⊕ opad`, deux blocs qui ne dépendent que du mot de passe. Leur compression SHA-256 est donc calculée une seule fois au début : chaque itération ne fait plus que 2 compressions au lieu de 4.

### Organisation du code

| Module | Fonctions |
|--------|-----------|
| AES – rondes | `addRoundKey`, `SubBytes` / `InvSubBytes`, `ShiftRows` / `InvShiftRows` (via `push` / `pop`), `MixColumns` / `InvMixColumns` (via `xtime` / `mul` dans GF(2⁸)) |
| AES – clés | `Explode` (clé → 8 mots), `GenerateKey` (60 mots), `RotWord`, `SubWord` |
| AES – blocs | `AES_Encrypt_Rondes` (14 rondes avec une clé déjà étendue), `AES_Encrypt_State` (expansion + rondes + effacement), `AES_Decrypt_State` |
| GCM | `ConterBlockGenerator` (bloc compteur), `gf128_multiply` (multiplication dans GF(2¹²⁸)), `AES_GCM_Encrypt_File`, `AES_GCM_Decrypt_File`, `AES_GCM_Encrypt`, `AES_GCM_Decrypt` |
| SHA-256 | `padding`, `compressing`, `ROTR`, `choose`, `majority`, `SIG0`, `SIG1`, `sig0`, `sig1`, `AES_SHA256` |
| Dérivation de clé | `AES_HMAC`, `PBKDF2` |
| Utilitaire | `uint8_tToZero` (effacement mémoire que le compilateur ne peut pas supprimer), `uint8TOuint64` / `uint64TOuint8` (8 octets ↔ un `uint64_t`, poids fort en premier) |

### Paramètres

| Paramètre | Valeur | Où |
|-----------|--------|----|
| Version du format | 8 (premier octet de l'en-tête) | `#define VERSION` |
| Message de l'empreinte | `"Say thx to Tetras"` (17 octets ASCII, sans le `'\0'`) | `#define VERIF_MESSAGE` |
| Taille de l'empreinte | 32 octets (HMAC-SHA256) | `AES_GCM_*` |
| Itérations PBKDF2 au chiffrement | 600 000, écrit dans l'en-tête | `#define PBKDF2_TOURS` |
| Itérations PBKDF2 au déchiffrement | la valeur lue dans l'en-tête (1 à 4 294 967 295) | `AES_GCM_Decrypt*` |
| Taille du sel | 16 octets | `AES_GCM_*` |
| Taille de la nonce | 12 octets (96 bits) | `AES_GCM_*` |
| Taille du tag | 16 octets (128 bits) | `AES_GCM_*` |
| Taille maximale des données | 68 719 476 704 octets (≈ 64 Gio) | `#define GCM_TAILLE_MAX` |
| Données associées (AAD) | non prises en charge | — |

---

## Conformité et tests

Chaque composant a été testé contre les vecteurs de test officiels :

| Composant | Vecteur de test | Résultat |
|-----------|-----------------|:--------:|
| AES-256, chiffrement et déchiffrement | FIPS-197, annexe C.3 | ✅ |
| SHA-256 | FIPS 180-4 : `"abc"`, chaîne vide, message de 448 bits (2 blocs) | ✅ |
| HMAC-SHA256 | RFC 4231, cas 1, 2 et 6 (clé de 131 octets) | ✅ |
| PBKDF2-HMAC-SHA256 | `"password"` / `"salt"`, 1 et 4 096 itérations | ✅ |
| Texte chiffré GCM (flux CTR) | NIST GCM, cas de test 14 | ✅ |
| Multiplication GF(2¹²⁸) (GHASH) | NIST GCM, cas de test 2 | ✅ |
| Blocs compteur au-delà de 2³¹ (jusqu'à 4 294 967 295) | Comparaison avec AES-ECB (Python `cryptography`) | ✅ |
| Fichier complet (en-tête, sel, nonce, empreinte, chiffré, tag) | Python (`hashlib`, `hmac` et `AESGCM` de `cryptography`) lit l'en-tête, recalcule l'empreinte et déchiffre les fichiers de 0 à 100 000 octets ; les fichiers fabriqués par Python, à 600 000 et à 1 000 itérations, sont déchiffrés | ✅ |
| Données chiffrées en mémoire | Même comparaison avec Python, de 0 à 1 000 octets, à 600 000 et à 1 000 itérations | ✅ |
| `gf128_multiply` sur deux `uint64_t` | 1 000 000 de multiplications au hasard comparées à l'ancienne version octet par octet : 0 différence | ✅ |
| `AES_Encrypt_Rondes` (clé étendue une fois) | FIPS-197 C.3, et 100 000 blocs comparés à `AES_Encrypt_State` : 0 différence | ✅ |

Tests sur fichiers (aller-retour chiffrement → déchiffrement) :

| Scénario | Résultat |
|----------|:--------:|
| Fichiers de 0, 1, 15, 16, 17, 1 000 et 100 000 octets : contenu restitué à l'identique, taille + 81 octets, en-tête `08 00 09 27 C0` | ✅ |
| Mauvais mot de passe → code `14` en ≈ 1,4 s (fichier de 4 Mio comme de 40 Mio), fichier intact, pas de `.tmp` | ✅ |
| Chaque octet d'un fichier chiffré modifié un par un : version → code `3` ; itérations, sel et empreinte → code `14` ; nonce, chiffré et tag → code `2` ; fichier jamais modifié, pas de `.tmp` (l'octet de poids fort des itérations n'est pas testé : il demanderait 16 millions d'itérations, même cas que les autres) | ✅ |
| Fichier chiffré avec la V7 (81 octets ou plus) → code `3`, intact ; octet de version à `9` → code `3` | ✅ |
| Nombre d'itérations à 0 → code `8`, intact | ✅ |
| Fichier de moins de 81 octets, fichier vide → code `8` ; fichier introuvable → code `6` | ✅ |
| Disque plein (simulé avec `ulimit -f`) pendant le chiffrement ou le déchiffrement → code `12`, original intact, pas de `.tmp` | ✅ |
| Fichier en `600` → toujours `600` après chiffrement et déchiffrement | ✅ |
| Taille illisible (`ftell` renvoie `-1`, simulé avec un tube nommé) ou dossier à la place d'un fichier → code `7`, rien n'est modifié | ✅ |
| Fichier d'un octet de plus que la taille maximale (68 719 476 705 octets, fichier creux) → code `7`, intact, pas de `.tmp` ; la taille maximale (68 719 476 704 octets) est acceptée | ✅ |
| Fichier chiffré plus gros que la taille maximale + 81 octets → code `8` au déchiffrement, intact ; la taille maximale + 81 octets est acceptée | ✅ |
| Dossier en lecture seule → code `10`, original intact | ✅ |
| Pannes simulées : chaque appel système (`calloc`, `fopen`, `fread`, `fwrite`, `fclose`, `fseek`, `stat`, `chmod`, `rename`) mis en échec un par un, soit 65 cas → le code attendu, original intact, pas de `.tmp` (un `fclose` raté sur un fichier seulement lu ne change pas le résultat) | ✅ |
| Aucune copie de la clé ni de la clé étendue dans la pile après `AES_GCM_Encrypt_File` et `AES_GCM_Decrypt_File`, y compris après un mauvais mot de passe (vérifié en `-O0` et `-O2`, avec une copie de contrôle sans effacement qui, elle, en laisse) | ✅ |

Tests en mémoire :

| Scénario | Résultat |
|----------|:--------:|
| Aller-retour de 0, 1, 15, 16, 17, 1 000 et 100 000 octets : contenu identique, `'\0'` final, taille + 81 octets | ✅ |
| Mauvais mot de passe → code `14`, `*dest` reste `NULL` | ✅ |
| Chaque octet modifié un par un : version → code `3` ; itérations, sel et empreinte → code `14` ; nonce, chiffré et tag → code `2` | ✅ |
| Données au format V7 → code `3` ; nombre d'itérations à 0 → code `8` | ✅ |
| Moins de 81 octets → code `8` ; paramètre `NULL` ou `*dest` déjà rempli → code `1` | ✅ |
| Taille annoncée plus grande que la taille maximale (avec un petit buffer) → code `7` au chiffrement, `8` au déchiffrement, avant toute lecture, `*dest` reste `NULL` | ✅ |
| Pannes simulées : chaque `calloc` et chaque accès à `/dev/urandom` mis en échec un par un, soit 20 cas → code `4` ou `5`, `*dest` reste `NULL` | ✅ |
| Données chiffrées en mémoire, écrites dans un fichier, puis relues par `AES_GCM_Decrypt_File`, et l'inverse | ✅ |
| Aucune copie de la clé ni de la clé étendue dans la pile après `AES_GCM_Encrypt` et `AES_GCM_Decrypt`, y compris après un mauvais mot de passe (vérifié en `-O0` et `-O2`) | ✅ |
| Après `AES_HMAC`, ni la clé XOR `ipad` ni le hachage intérieur ne restent dans la pile ou dans la mémoire libérée | ✅ |

Tous les scénarios passent sous `valgrind` sans erreur ni fuite mémoire.

**Windows :** `AES.c` et l'exemple ci-dessus compilent avec MinGW-w64 (x86_64) sans avertissement (`-Wall -Wextra -pedantic`). Les tests ci-dessus n'ont pas encore été lancés sous Windows.

### Compatibilité

Après l'en-tête, le format suit la norme AES-256-GCM : avec la clé PBKDF2 (même mot de passe, même sel, même nombre d'itérations, lus dans l'en-tête), n'importe quelle implémentation GCM conforme peut déchiffrer les données, et inversement.

**Fichiers chiffrés avec la V7 :** la V8 ajoute l'empreinte de la clé (32 octets) dans l'en-tête, le format change donc. La V8 refuse les fichiers de la V7 (code `3`, fichier intact), et la V7 refuse ceux de la V8 (code `3` aussi, fichier intact). Pour les garder : les déchiffrer avec la V7, puis les rechiffrer avec la V8.

> [!NOTE]
> La V8 vérifie la taille avant la version : un fichier V7 de moins de 81 octets (moins de 32 octets de texte) est refusé avec le code `8` au lieu de `3`. Le fichier reste intact dans les deux cas.

**Fichiers chiffrés avec la V5 ou la V6 :** ils n'ont pas d'en-tête (version et itérations). La V8 les refuse (code `3`, ou `8` s'ils font moins de 81 octets ; fichier intact), et la V6 refuse les fichiers de la V8 (code `2`, fichier intact). Pour les garder : les déchiffrer avec la V6, puis les rechiffrer avec la V8.

> [!NOTE]
> Le premier octet d'un fichier V5 ou V6 est le début de son sel, donc du hasard : un fichier sur 256 commence par l'octet `8`. La V8 le lit alors comme un fichier V8, avec un nombre d'itérations tiré des octets suivants du sel (souvent plusieurs milliards) : le déchiffrement peut durer des heures avant de répondre `14`. Les déchiffrer avec la V6 évite ce cas.

**Fichiers chiffrés avec la V4 ou avant :** refusés aussi (code `3` ou `8`, avec le même cas d'un fichier sur 256) : les déchiffrer avec la version qui les a créés.

---

## Performances

Mesures indicatives (`gcc -O2`, Raspberry Pi 4 Model B à 1,8 GHz, Linux ; médiane de 3 mesures pour la V7 et la V8) :

| Opération | V8 | V7 | V6 | V5 |
|-----------|----|----|----|----|
| Dérivation de clé PBKDF2 (600 000 itérations), à chaque chiffrement ou déchiffrement | ≈ 1,4 s | ≈ 1,4 s | ≈ 1,4 s | ≈ 2,9 s |
| Chiffrement d'un fichier de 4 Mio | ≈ 2,1 s | ≈ 3,9 s | ≈ 3,8 s | ≈ 5,3 s |
| Déchiffrement d'un fichier de 4 Mio (deux passes) | ≈ 2,3 s | ≈ 5,7 s | ≈ 5,5 s | ≈ 7,0 s |
| Données seules, PBKDF2 à part | chiffrement ≈ 5,7 Mio/s, déchiffrement ≈ 4,5 Mio/s | chiffrement ≈ 1,6 Mio/s, déchiffrement ≈ 0,9 Mio/s | — | — |
| Refus d'un mauvais mot de passe, fichier de 4 Mio | ≈ 1,4 s | ≈ 3,1 s | — | — |
| Refus d'un mauvais mot de passe, fichier de 40 Mio | ≈ 1,4 s | ≈ 18,8 s | — | — |

La V8 traite les données 3,5 fois plus vite au chiffrement et 5 fois plus vite au déchiffrement (PBKDF2 à part), grâce à deux changements qui ne modifient pas le résultat :

- `gf128_multiply` (le calcul du tag) travaille sur deux nombres de 64 bits au lieu de 16 octets : un XOR ou un décalage traite 8 octets d'un coup. Elle est ≈ 9 fois plus rapide (0,18 s au lieu de 1,7 s pour 4 Mio). Le déchiffrement en profite deux fois, car il calcule le tag à chacune de ses deux passes ;
- l'expansion de la clé AES (les 60 mots des clés de ronde) est faite une seule fois par fonction, au lieu d'une fois par bloc de 16 octets.

PBKDF2 n'a pas changé : il représente maintenant les deux tiers du temps pour 4 Mio.

Un mauvais mot de passe est maintenant refusé juste après PBKDF2, grâce à l'empreinte de la clé rangée dans l'en-tête. La V7 devait d'abord lire toutes les données pour calculer le tag.

Le gain de la V6 vient uniquement de PBKDF2 (voir [Fonctionnement interne](#fonctionnement-interne)) : le traitement des données lui-même n'a pas changé (≈ 2,5 s pour chiffrer 4 Mio, ≈ 4,3 s pour les déchiffrer, PBKDF2 à part). La V7 ne change que l'en-tête (5 octets) et ajoute l'effacement des valeurs intermédiaires de HMAC et SHA-256 : elle fait les mêmes calculs que la V6, et les écarts de mesure restent sous 0,2 s.

La durée de la dérivation de clé est proportionnelle au nombre d'itérations lu dans le fichier : deux fois plus d'itérations, deux fois plus de temps.

Le code reste simple plutôt que le plus rapide possible :

- `gf128_multiply` parcourt toujours les 128 bits un par un (sur deux `uint64_t`), sans tables précalculées ni instruction de multiplication du processeur ;
- AES est calculé octet par octet (`SubBytes`, `ShiftRows`, `MixColumns`), sans tables précalculées ni instructions AES du processeur.

---

## Limites connues

**Sécurité**

- Le nombre d'itérations lu dans un fichier n'est pas plafonné (choix) : un fichier modifié peut en demander jusqu'à 4 294 967 295, soit ≈ 2 h 45 de calcul sur Raspberry Pi 4 avant le refus (code `14`). Rien n'est lu ni écrit pendant ce temps, et le fichier reste intact.
- Le code `14` ne distingue pas un mauvais mot de passe d'un en-tête modifié (sel, itérations ou empreinte) : dans les deux cas, la clé calculée ne correspond pas à l'empreinte. Le code `2`, lui, est sûr : il n'arrive qu'avec le bon mot de passe.
- PBKDF2, `AES_HMAC` et `AES_SHA256` effacent leurs valeurs intermédiaires, mais deux traces peuvent rester : les variables de travail de SHA-256 (`W` et `a` à `h` dans `compressing`) restent sur la pile, car les effacer ralentirait PBKDF2, qui appelle `compressing` 1,2 million de fois ; et une copie peut rester dans les registres du processeur après un `memcpy`, ce que le C ne permet pas d'effacer. Le mot de passe lui-même reste sous la responsabilité de l'appelant.
- Pas de données associées authentifiées (AAD).

**Robustesse**

- Un fichier `<fichier>.tmp` déjà présent est écrasé sans avertissement.
- Taille maximale des données : 68 719 476 704 octets (≈ 64 Gio), pour un fichier comme en mémoire, sous Linux comme sous Windows. C'est la limite de GCM lui-même (NIST SP 800-38D) : le compteur ne fait que 32 bits, et au-delà les mêmes masques resserviraient. Les quatre fonctions `AES_GCM_*` refusent une taille plus grande (code `7` au chiffrement, `8` au déchiffrement) sans rien modifier. Aller plus loin demanderait de découper les données en plusieurs messages GCM (nouveau format de fichier).
- Aucun fichier de cette taille n'a été chiffré en entier pendant les tests (≈ 3 h 15 de chiffrement et ≈ 4 h de déchiffrement sur Raspberry Pi 4 avec la V8, par extrapolation des mesures sur 4 Mio) : les limites ont été vérifiées sur des fichiers creux, et les blocs compteur au-delà de 2³¹ comparés à Python.
- Les fonctions internes (`padding`, `compressing`, `push`, `pop`, `mul`…) sont globales et portent des noms génériques : conflit possible avec une autre bibliothèque liée au même programme. Les déclarer `static` réglerait le problème.

**Windows** (comportement attendu, pas encore testé sur une machine Windows)

- Un fichier en lecture seule est refusé (code `13`, intact) : Windows refuse de le remplacer.
- Le résultat prend les droits d'accès du dossier, pas ceux du fichier d'origine.
- Les chemins passent par l'API « ANSI » (`fopen`, `MoveFileExA`) : un nom de fichier contenant des caractères absents de la page de code de Windows ne peut pas être ouvert.

---

## Licence

MIT, voir [LICENSE](LICENSE).

---

## Références

- [FIPS 197 — Advanced Encryption Standard (AES)](https://csrc.nist.gov/pubs/fips/197/final)
- [NIST SP 800-38D — Galois/Counter Mode (GCM)](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [FIPS 180-4 — Secure Hash Standard (SHA-256)](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [RFC 2104 — HMAC](https://www.rfc-editor.org/rfc/rfc2104)
- [RFC 4231 — Vecteurs de test HMAC-SHA256](https://www.rfc-editor.org/rfc/rfc4231)
- [RFC 8018 — PKCS #5 : PBKDF2](https://www.rfc-editor.org/rfc/rfc8018)
- [OWASP — Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
