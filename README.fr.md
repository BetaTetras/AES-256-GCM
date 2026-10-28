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
- **Sel et nonce aléatoires** tirés du générateur aléatoire du système (`/dev/urandom`, ou `BCryptGenRandom` sous Windows) à chaque chiffrement : chiffrer deux fois les mêmes données avec le même mot de passe donne deux résultats différents.
- **Chiffrement de fichiers ou en mémoire** : `AES_GCM_Encrypt` / `AES_GCM_Decrypt` travaillent sur un tampon, sans rien écrire sur le disque, et produisent exactement le même format qu'un fichier chiffré.
- **Pas de padding** : le texte chiffré a exactement la taille des données d'origine (+ 49 octets d'en-tête et de tag).
- **Fichiers traités par blocs de 16 octets** : la mémoire utilisée reste constante, quelle que soit la taille du fichier.
- **Écriture sûre** : le résultat est écrit dans `<fichier>.tmp` puis renommé. Chaque écriture est vérifiée : en cas de mauvais mot de passe, de fichier altéré ou de disque plein, le `.tmp` est supprimé et l'original reste intact. Sous Linux, macOS et BSD, le fichier garde ses droits d'accès (un fichier en `600` reste en `600`) ; sous Windows, il prend ceux de son dossier. Un fichier trop gros, ou dont la taille ne peut pas être lue, est refusé sans être modifié.
- **Hygiène mémoire** : la clé et ses copies (sous-clés AES), ainsi que les valeurs intermédiaires de PBKDF2, HMAC et SHA-256, sont effacées avant chaque retour, avec une écriture `volatile` que le compilateur ne peut pas supprimer. Les tampons alloués sont effacés avant d'être libérés. Le tag est comparé en temps constant.

---

## Démarrage rapide

### 1. L'en-tête

Le code tient dans un seul fichier source, `AES.c`. L'en-tête `AES.h` contient les prototypes publics :

```c
#ifndef AES_H
#define AES_H

#include <stdint.h>
#include <stddef.h>

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

    if (r == 0)      puts("OK");
    else if (r == 2) puts("Mot de passe incorrect ou fichier altéré");
    else if (r == 3) puts("Fichier chiffré avec une autre version (format inconnu)");
    else             puts("Erreur (fichier introuvable, lecture/écriture, disque plein, mémoire)");
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

| Code retour | `AES_GCM_Encrypt_File` | `AES_GCM_Decrypt_File` |
|:-----------:|------------------------|------------------------|
| `0` | Succès | Succès |
| `1` | Erreur : générateur aléatoire indisponible, fichier introuvable, taille illisible ou fichier trop gros (voir [Limites connues](#limites-connues)), ouverture, lecture, écriture (disque plein), allocation, renommage. L'original est intact. | Erreur : fichier introuvable, fichier de moins de 49 octets ou trop gros, nombre d'itérations égal à 0, ouverture, écriture (disque plein), allocation, renommage. L'original est intact. |
| `2` | — | **Échec d'authentification** : mauvais mot de passe *ou* fichier modifié. Le fichier n'est pas touché. |
| `3` | — | **Version inconnue** : le premier octet n'est pas `7`, par exemple un fichier chiffré avec la V6 ou une version antérieure (voir [Compatibilité](#compatibilité)). Le fichier n'est pas touché. |

Un mauvais mot de passe et un fichier altéré donnent tous deux `2` : les deux cas sont indiscernables par construction.

Le déchiffrement se fait en deux passes : la première calcule et vérifie le tag sans rien écrire ; la seconde déchiffre dans `<fichier>.tmp`, revérifie le tag, puis renomme.

### Chiffrement en mémoire

```c
int AES_GCM_Encrypt(uint8_t** dest, size_t* size_dest, uint8_t* src, size_t size_src, char* password);
int AES_GCM_Decrypt(uint8_t** dest, size_t* size_dest, uint8_t* src, size_t size_src, char* password);
```

| Paramètre | Description |
|-----------|-------------|
| `dest` | Adresse d'un pointeur qui doit valoir `NULL`. La fonction alloue le résultat et y met son adresse ; l'appelant le libère avec `free`. |
| `size_dest` | Reçoit la taille du résultat : `size_src + 49` pour `AES_GCM_Encrypt`, `size_src - 49` pour `AES_GCM_Decrypt`. |
| `src`, `size_src` | Données d'entrée : le texte clair (`AES_GCM_Encrypt`) ou les données chiffrées (`AES_GCM_Decrypt`). |
| `password` | Mot de passe, chaîne C terminée par `\0`. |

| Code retour | `AES_GCM_Encrypt` | `AES_GCM_Decrypt` |
|:-----------:|-------------------|-------------------|
| `0` | Succès | Succès |
| `1` | Erreur : paramètre `NULL`, `*dest` différent de `NULL`, données trop grosses (voir [Limites connues](#limites-connues)), générateur aléatoire indisponible, allocation | Erreur : paramètre `NULL`, `*dest` différent de `NULL`, moins de 49 octets ou trop gros, nombre d'itérations égal à 0, allocation |
| `2` | — | **Échec d'authentification** : mauvais mot de passe *ou* données modifiées. `*dest` reste `NULL`. |
| `3` | — | **Version inconnue** : le premier octet n'est pas `7`. `*dest` reste `NULL`. |

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
if (r == 0)      printf("%s\n", (char*)clair);   /* '\0' ajouté par AES_GCM_Decrypt */
else if (r == 2) puts("Mot de passe incorrect ou données altérées");
else if (r == 3) puts("Données chiffrées avec une autre version");

free(chiffre);
free(clair);   /* effacer clair avant s'il contient des secrets */
```

### Primitives cryptographiques

Ces fonctions sont utilisables séparément. Le préfixe `AES_` de `AES_SHA256` et `AES_HMAC` évite le conflit de noms avec les fonctions `SHA256` et `HMAC` d'OpenSSL.

| Fonction | Rôle | Sortie | Retour |
|----------|------|--------|--------|
| `AES_Encrypt_State(state, cle)` | Chiffre **un** bloc de 16 octets en place avec une clé de 32 octets. | `state` modifié | — |
| `AES_Decrypt_State(state, cle)` | Déchiffre un bloc de 16 octets en place. | `state` modifié | — |
| `AES_SHA256(dest, mess, size)` | Empreinte SHA-256 de `size` octets. | `dest` : 32 octets | `0` succès, `1` allocation |
| `AES_HMAC(dest, key, size_key, mess, size_mess)` | HMAC-SHA256 (clé de n'importe quelle taille). | `dest` : 32 octets | `0` / `1` |
| `PBKDF2(dest, password, size_password, salt, size_salt, tour)` | PBKDF2-HMAC-SHA256 avec `tour` itérations (≥ 1). | `dest` : **32 octets** (taille fixe) | `0` / `1` |

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

Le format est le même pour un fichier et pour un tampon en mémoire. Pour des données d'origine de **N** octets, le résultat fait **N + 49** octets :

```
[Version - 1 o][Nombre d'itérations - 4 o][Sel - 16 o][Nonce - 12 o][Chiffré - N o][Tag - 16 o]
```

| Position (octets) | Taille | Contenu |
|-------------------|:------:|---------|
| `0`               | 1  | Version du format : `7` |
| `1` – `4`         | 4  | Nombre d'itérations PBKDF2, entier non signé de 32 bits, poids fort en premier (600 000 = `00 09 27 C0`) |
| `5` – `20`        | 16 | Sel PBKDF2, aléatoire |
| `21` – `32`       | 12 | Nonce, aléatoire |
| `33` – `32+N`     | N  | Texte chiffré (même taille que l'original) |
| `33+N` – `48+N`   | 16 | Tag d'authentification |

Le chiffrement écrit la valeur de `PBKDF2_TOURS` ; le déchiffrement utilise le nombre d'itérations lu dans le fichier. Augmenter `PBKDF2_TOURS` dans une version future ne rendra donc pas illisibles les fichiers déjà chiffrés.

La version et le nombre d'itérations ne font pas partie du tag, mais ils ne peuvent pas être modifiés sans être détectés : une autre version est refusée (code `3`), et un autre nombre d'itérations donne une autre clé, donc un tag faux (code `2`).

---

## Fonctionnement interne

```
mot de passe ──┐
               ├──►  PBKDF2-HMAC-SHA256 (itérations de l'en-tête, 600 000 au chiffrement)  ──►  clé K (32 octets)
sel (16 o) ────┘

H         = AES-256(K, 0¹²⁸)                          clé du hachage GHASH
Bloc i    = nonce ‖ compteur (i + 2)                  compteur sur 32 bits, poids fort en premier
Chiffré i = Clair i ⊕ AES-256(K, Bloc i)              mode CTR ; dernier bloc tronqué
S         = GHASH_H(blocs chiffrés ‖ bloc longueur)   bloc longueur = 0⁶⁴ ‖ taille en bits (64 bits)
Tag       = S ⊕ AES-256(K, nonce ‖ 00 00 00 01)
```

- Le **bloc longueur** empêche d'ajouter ou de retirer des blocs sans changer le tag.
- Le **masque** `AES(K, nonce ‖ 1)` lie le tag à la nonce et cache la valeur de GHASH, donc de H.
- La **multiplication dans GF(2¹²⁸)** suit la convention de GCM : bits rangés à l'envers, décalage vers la droite et réduction par `0xE1` sur le premier octet (SP 800-38D, § 6.3).
- La **comparaison du tag** parcourt toujours les 16 octets et cumule les différences (`diff |= a ^ b`) sans branchement : sa durée ne dépend pas du nombre d'octets corrects.
- **PBKDF2** : à chaque itération, HMAC hache `clé ⊕ ipad` et `clé ⊕ opad`, deux blocs qui ne dépendent que du mot de passe. Leur compression SHA-256 est donc calculée une seule fois au début : chaque itération ne fait plus que 2 compressions au lieu de 4.

### Organisation du code

| Module | Fonctions |
|--------|-----------|
| AES – rondes | `addRoundKey`, `SubBytes` / `InvSubBytes`, `ShiftRows` / `InvShiftRows` (via `push` / `pop`), `MixColumns` / `InvMixColumns` (via `xtime` / `mul` dans GF(2⁸)) |
| AES – clés | `Explode` (clé → 8 mots), `GenerateKey` (60 mots), `RotWord`, `SubWord` |
| AES – blocs | `AES_Encrypt_State`, `AES_Decrypt_State` |
| GCM | `ConterBlockGenerator` (bloc compteur), `gf128_multiply` (multiplication dans GF(2¹²⁸)), `AES_GCM_Encrypt_File`, `AES_GCM_Decrypt_File`, `AES_GCM_Encrypt`, `AES_GCM_Decrypt` |
| SHA-256 | `padding`, `compressing`, `ROTR`, `choose`, `majority`, `SIG0`, `SIG1`, `sig0`, `sig1`, `AES_SHA256` |
| Dérivation de clé | `AES_HMAC`, `PBKDF2` |
| Utilitaire | `uint8_tToZero` (effacement mémoire que le compilateur ne peut pas supprimer) |

### Paramètres

| Paramètre | Valeur | Où |
|-----------|--------|----|
| Version du format | 7 (premier octet de l'en-tête) | `#define VERSION` |
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
| Fichier complet (en-tête, sel, nonce, chiffré, tag) | Python (`hashlib` + `AESGCM` de `cryptography`) lit l'en-tête et déchiffre les fichiers de 0 à 100 000 octets ; les fichiers fabriqués par Python, à 600 000 et à 1 000 itérations, sont déchiffrés | ✅ |
| Données chiffrées en mémoire | Même comparaison avec Python, de 0 à 1 000 octets, à 600 000 et à 1 000 itérations | ✅ |

Tests sur fichiers (aller-retour chiffrement → déchiffrement) :

| Scénario | Résultat |
|----------|:--------:|
| Fichiers de 0, 1, 15, 16, 17, 1 000 et 100 000 octets : contenu restitué à l'identique, taille + 49 octets, en-tête `07 00 09 27 C0` | ✅ |
| Mauvais mot de passe → code `2`, fichier intact, pas de `.tmp` | ✅ |
| Chaque octet d'un fichier chiffré modifié un par un : version → code `3`, tous les autres (itérations comprises) → code `2`, fichier jamais modifié | ✅ |
| Fichier chiffré avec la V6 → code `3`, intact ; octet de version à `8` → code `3` | ✅ |
| Nombre d'itérations à 0 → code `1`, intact | ✅ |
| Fichier de moins de 49 octets, fichier vide, fichier introuvable → code `1` | ✅ |
| Disque plein (simulé avec `ulimit -f`) pendant le chiffrement ou le déchiffrement → code `1`, original intact, pas de `.tmp` | ✅ |
| Fichier en `600` → toujours `600` après chiffrement et déchiffrement | ✅ |
| Taille illisible (`ftell` renvoie `-1`, simulé avec un tube nommé) → code `1`, rien n'est modifié | ✅ |
| Fichier d'un octet de plus que la taille maximale (68 719 476 705 octets, fichier creux) → code `1`, intact, pas de `.tmp` ; la taille maximale (68 719 476 704 octets) est acceptée | ✅ |
| Fichier chiffré plus gros que la taille maximale + 49 octets → code `1` au déchiffrement, intact ; la taille maximale + 49 octets est acceptée | ✅ |
| Dossier en lecture seule → code `1`, original intact | ✅ |

Tests en mémoire :

| Scénario | Résultat |
|----------|:--------:|
| Aller-retour de 0, 17 et 1 000 octets : contenu identique, `'\0'` final, taille + 49 octets | ✅ |
| Mauvais mot de passe → code `2`, `*dest` reste `NULL` | ✅ |
| Octets modifiés (version, itérations, sel, nonce, chiffré, tag) : version → code `3`, les autres → code `2` | ✅ |
| Données chiffrées avec la V6 → code `3` ; nombre d'itérations à 0 → code `1` | ✅ |
| Moins de 49 octets, paramètre `NULL` ou `*dest` déjà rempli → code `1` | ✅ |
| Taille annoncée plus grande que la taille maximale (avec un petit buffer) → code `1` avant toute lecture, `*dest` reste `NULL` | ✅ |
| Données chiffrées en mémoire, écrites dans un fichier, puis relues par `AES_GCM_Decrypt_File`, et l'inverse | ✅ |
| Aucune copie de la clé dans la pile après `AES_GCM_Encrypt` (vérifié en `-O0` et `-O2`) | ✅ |
| Après `AES_HMAC`, ni la clé XOR `ipad` ni le hachage intérieur ne restent dans la pile ou dans la mémoire libérée | ✅ |

Tous les scénarios passent sous `valgrind` sans erreur ni fuite mémoire.

**Windows :** `AES.c` et l'exemple ci-dessus compilent avec MinGW-w64 (x86_64) sans avertissement (`-Wall -Wextra -pedantic`). Les tests ci-dessus n'ont pas encore été lancés sous Windows.

### Compatibilité

Après l'en-tête, le format suit la norme AES-256-GCM : avec la clé PBKDF2 (même mot de passe, même sel, même nombre d'itérations, lus dans l'en-tête), n'importe quelle implémentation GCM conforme peut déchiffrer les données, et inversement.

**Fichiers chiffrés avec la V5 ou la V6 :** ils n'ont pas d'en-tête (version et itérations). La V7 les refuse (code `3`, fichier intact), et la V6 refuse les fichiers de la V7 (code `2`, fichier intact). Pour les garder : les déchiffrer avec la V6, puis les rechiffrer avec la V7.

> [!NOTE]
> Le premier octet d'un fichier V5 ou V6 est le début de son sel, donc du hasard : un fichier sur 256 commence par l'octet `7`. La V7 le lit alors comme un fichier V7, avec un nombre d'itérations tiré des octets suivants du sel (souvent plusieurs milliards) : le déchiffrement peut durer des heures avant de répondre `2`. Les déchiffrer avec la V6 évite ce cas.

**Fichiers chiffrés avec la V4 ou avant :** refusés aussi (code `3`, avec le même cas d'un fichier sur 256) : les déchiffrer avec la version qui les a créés.

---

## Performances

Mesures indicatives (`gcc -O2`, Raspberry Pi 4 Model B à 1,8 GHz, Linux ; médiane de 3 mesures pour la V7) :

| Opération | V7 | V6 | V5 |
|-----------|----|----|----|
| Dérivation de clé PBKDF2 (600 000 itérations), à chaque chiffrement ou déchiffrement | ≈ 1,4 s | ≈ 1,4 s | ≈ 2,9 s |
| Chiffrement d'un fichier de 4 Mio | ≈ 3,9 s | ≈ 3,8 s | ≈ 5,3 s |
| Déchiffrement d'un fichier de 4 Mio (deux passes) | ≈ 5,7 s | ≈ 5,5 s | ≈ 7,0 s |
| Données seules, PBKDF2 à part | chiffrement ≈ 1,6 Mio/s, déchiffrement ≈ 0,9 Mio/s | — | — |

Le gain de la V6 vient uniquement de PBKDF2 (voir [Fonctionnement interne](#fonctionnement-interne)) : le traitement des données lui-même n'a pas changé (≈ 2,5 s pour chiffrer 4 Mio, ≈ 4,3 s pour les déchiffrer, PBKDF2 à part). La V7 ne change que l'en-tête (5 octets) et ajoute l'effacement des valeurs intermédiaires de HMAC et SHA-256 : elle fait les mêmes calculs que la V6, et les écarts de mesure restent sous 0,2 s.

La durée de la dérivation de clé est proportionnelle au nombre d'itérations lu dans le fichier : deux fois plus d'itérations, deux fois plus de temps.

Le code privilégie la lisibilité sur la vitesse :

- `AES_Encrypt_State` recalcule l'expansion de clé (60 mots) **à chaque bloc**, puis l'efface ;
- `gf128_multiply` traite les 128 bits un par un.

---

## Limites connues

**Sécurité**

- Le nombre d'itérations lu dans un fichier n'est pas plafonné (choix) : un fichier modifié peut en demander jusqu'à 4 294 967 295, soit ≈ 2 h 45 de calcul sur Raspberry Pi 4 avant le refus (code `2`). Rien n'est lu ni écrit pendant ce temps, et le fichier reste intact.
- PBKDF2, `AES_HMAC` et `AES_SHA256` effacent leurs valeurs intermédiaires, mais deux traces peuvent rester : les variables de travail de SHA-256 (`W` et `a` à `h` dans `compressing`) restent sur la pile, car les effacer ralentirait PBKDF2, qui appelle `compressing` 1,2 million de fois ; et une copie peut rester dans les registres du processeur après un `memcpy`, ce que le C ne permet pas d'effacer. Le mot de passe lui-même reste sous la responsabilité de l'appelant.
- Pas de données associées authentifiées (AAD).

**Robustesse**

- Un fichier `<fichier>.tmp` déjà présent est écrasé sans avertissement.
- Taille maximale des données : 68 719 476 704 octets (≈ 64 Gio), pour un fichier comme en mémoire, sous Linux comme sous Windows. C'est la limite de GCM lui-même (NIST SP 800-38D) : le compteur ne fait que 32 bits, et au-delà les mêmes masques resserviraient. Les quatre fonctions `AES_GCM_*` refusent une taille plus grande (code `1`) sans rien modifier. Aller plus loin demanderait de découper les données en plusieurs messages GCM (nouveau format de fichier).
- Aucun fichier de cette taille n'a été chiffré en entier pendant les tests (≈ 11 h 30 de chiffrement et ≈ 19 h 30 de déchiffrement sur Raspberry Pi 4, par extrapolation des mesures sur 4 Mio) : les limites ont été vérifiées sur des fichiers creux, et les blocs compteur au-delà de 2³¹ comparés à Python.
- Les fonctions internes (`padding`, `compressing`, `push`, `pop`, `mul`…) sont globales et portent des noms génériques : conflit possible avec une autre bibliothèque liée au même programme. Les déclarer `static` réglerait le problème.

**Windows** (comportement attendu, pas encore testé sur une machine Windows)

- Un fichier en lecture seule est refusé (code `1`, intact) : Windows refuse de le remplacer.
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
