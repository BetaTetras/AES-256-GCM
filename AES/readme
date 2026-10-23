# AES-256-GCM + PBKDF2 en C

Bibliothèque C de chiffrement de fichiers par mot de passe, écrite entièrement à la main : AES-256, mode GCM (CTR + GHASH), SHA-256, HMAC-SHA256 et PBKDF2. Elle ne dépend que de la bibliothèque standard C.

Un appel suffit pour chiffrer un fichier en place avec un mot de passe ; le déchiffrement vérifie l'intégrité du fichier avant d'écrire quoi que ce soit.

> [!WARNING]
> **Projet pédagogique, non audité.** Le code n'a fait l'objet d'aucune revue de sécurité et le tag d'authentification ne suit pas encore exactement la norme GCM (voir [Conformité et tests](#conformité-et-tests)). Pour protéger des données réelles, utilisez une bibliothèque éprouvée comme libsodium ou OpenSSL.

---

## Fonctionnalités

- **AES-256** conforme à FIPS-197 (14 rondes, expansion de clé en 60 mots).
- **Chiffrement authentifié de type GCM** : chiffrement en mode compteur (CTR) et tag d'authentification de 16 octets.
- **Dérivation de clé PBKDF2-HMAC-SHA256** : la clé de 32 octets est dérivée du mot de passe et d'un sel aléatoire.
- **Sel et nonce aléatoires** tirés de `/dev/urandom` à chaque chiffrement : chiffrer deux fois le même fichier avec le même mot de passe donne deux résultats différents.
- **Traitement par blocs de 16 octets** : la mémoire utilisée reste constante, quelle que soit la taille du fichier.
- **Pas de padding** : le texte chiffré a exactement la taille du fichier d'origine (+ 44 octets d'en-tête et de tag).
- **Écriture sûre** : le résultat est écrit dans `<fichier>.tmp` puis renommé ; en cas de mauvais mot de passe ou de fichier altéré, rien n'est écrit et l'original reste intact.

---

## Démarrage rapide

### 1. Créer l'en-tête

Le code tient dans un seul fichier source (appelé ici `aes.c`). Pour l'utiliser depuis un autre fichier, créer `aes.h` avec les prototypes publics :

```c
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
```

### 2. Exemple : petit outil en ligne de commande

```c
#include <stdio.h>
#include <string.h>
#include "aes.h"

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
    else             puts("Erreur (fichier introuvable, lecture/écriture, mémoire)");
    return r;
}
```

> Pour l'exemple, le mot de passe est passé en argument. Dans un vrai programme, il vaut mieux le saisir au clavier : un argument de ligne de commande reste visible dans l'historique du shell et dans la liste des processus.

### 3. Compiler et lancer

```bash
gcc -std=c11 -Wall -Wextra -O2 -o aescli main.c aes.c

./aescli chiffrer   note.txt "mon mot de passe"
./aescli dechiffrer note.txt "mon mot de passe"
```

**Plateformes :** Linux, macOS, BSD (tout système fournissant `/dev/urandom`). Windows natif n'est pas pris en charge.

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
| `1` | Erreur : `/dev/urandom` illisible, fichier introuvable, ouverture, allocation, renommage | Erreur : fichier introuvable, fichier de moins de 44 octets, ouverture, allocation, renommage |
| `2` | — | **Échec d'authentification** : mauvais mot de passe *ou* fichier modifié. Le fichier n'est pas touché. |

Un mauvais mot de passe et un fichier altéré donnent tous deux `2` : les deux cas sont indiscernables par construction.

Le déchiffrement se fait en deux passes : la première calcule et vérifie le tag sans rien écrire ; la seconde déchiffre dans `<fichier>.tmp`, revérifie le tag, puis renomme.

### Primitives cryptographiques

Ces fonctions sont utilisables séparément.

| Fonction | Rôle | Sortie | Retour |
|----------|------|--------|--------|
| `AES_Encrypt_State(state, cle)` | Chiffre **un** bloc de 16 octets en place avec une clé de 32 octets. | `state` modifié | — |
| `AES_Decrypt_State(state, cle)` | Déchiffre un bloc de 16 octets en place. | `state` modifié | — |
| `SHA256(dest, mess, size)` | Empreinte SHA-256 de `size` octets. | `dest` : 32 octets | `0` succès, `1` allocation |
| `HMAC(dest, key, size_key, mess, size_mess)` | HMAC-SHA256 (clé de n'importe quelle taille). | `dest` : 32 octets | `0` / `1` |
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

### Fonctions héritées (déconseillées)

```c
int AES_Encrypt_File(char* path, uint8_t key[32]);
int AES_Decrypt_File(char* path, uint8_t key[32]);
```

Première version du projet : AES-256 en mode **ECB** avec padding PKCS#7 et une clé brute de 32 octets. Ces fonctions sont conservées pour l'historique mais **ne doivent pas être utilisées** :

- en ECB, deux blocs identiques donnent deux blocs chiffrés identiques, ce qui laisse voir la structure des données ;
- aucune authentification : une modification du fichier n'est pas détectée ;
- le fichier est réécrit directement (sans `.tmp`) : une interruption en cours d'écriture fait perdre les données ;
- le padding n'est pas vérifié au déchiffrement.

---

## Format du fichier chiffré

Pour un fichier d'origine de **N** octets, le fichier chiffré fait **N + 44** octets :

| Position (octets) | Taille | Contenu |
|-------------------|:------:|---------|
| `0` – `15`        | 16 | Sel PBKDF2, aléatoire |
| `16` – `27`       | 12 | Nonce, aléatoire |
| `28` – `27+N`     | N  | Texte chiffré (même taille que l'original) |
| `28+N` – `43+N`   | 16 | Tag d'authentification |

Le nombre d'itérations PBKDF2 n'est **pas** enregistré dans le fichier : modifier `PBKDF2_TOURS` rend illisibles les fichiers chiffrés auparavant.

---

## Fonctionnement interne

```
mot de passe ──┐
               ├──►  PBKDF2-HMAC-SHA256 (13 000 itérations)  ──►  clé K (32 octets)
sel (16 o) ────┘

H         = AES-256(K, 0¹²⁸)                          clé du hachage GHASH
Bloc i    = nonce ‖ compteur (i + 2)                  compteur sur 32 bits, poids fort en premier
Chiffré i = Clair i ⊕ AES-256(K, Bloc i)              mode CTR ; dernier bloc tronqué
S         = GHASH_H(blocs chiffrés ‖ bloc longueur)   bloc longueur = 0⁶⁴ ‖ taille en bits (64 bits)
Tag       = S ⊕ AES-256(K, nonce ‖ 00 00 00 01)
```

- Le **bloc longueur** empêche d'ajouter ou de retirer des blocs sans changer le tag.
- Le **masque** `AES(K, nonce ‖ 1)` lie le tag à la nonce et cache la valeur de GHASH, donc de H.

### Organisation du code

| Module | Fonctions |
|--------|-----------|
| AES – rondes | `addRoundKey`, `SubBytes` / `InvSubBytes`, `ShiftRows` / `InvShiftRows` (via `push` / `pop`), `MixColumns` / `InvMixColumns` (via `xtime` / `mul` dans GF(2⁸)) |
| AES – clés | `Explode` (clé → 8 mots), `GenerateKey` (60 mots), `RotWord`, `SubWord` |
| AES – blocs | `AES_Encrypt_State`, `AES_Decrypt_State` |
| GCM | `ConterBlockGenerator` (bloc compteur), `gf128_multiply` (multiplication dans GF(2¹²⁸)), `AES_GCM_Encrypt_File`, `AES_GCM_Decrypt_File` |
| SHA-256 | `padding`, `compressing`, `ROTR`, `choose`, `majority`, `SIG0`, `SIG1`, `sig0`, `sig1`, `SHA256` |
| Dérivation de clé | `HMAC`, `PBKDF2` |
| Héritage ECB | `ByteTranscription`, `AES_Encrypt_File`, `AES_Decrypt_File` |

### Paramètres

| Paramètre | Valeur | Où |
|-----------|--------|----|
| Itérations PBKDF2 | 13 000 | `#define PBKDF2_TOURS` |
| Taille du sel | 16 octets | `AES_GCM_*_File` |
| Taille de la nonce | 12 octets (96 bits) | `AES_GCM_*_File` |
| Taille du tag | 16 octets (128 bits) | `AES_GCM_*_File` |
| Données associées (AAD) | non prises en charge | — |

---

## Conformité et tests

Chaque composant a été testé contre les vecteurs de test officiels :

| Composant | Vecteur de test | Résultat |
|-----------|-----------------|:--------:|
| AES-256, chiffrement et déchiffrement | FIPS-197, annexe C.3 | ✅ |
| SHA-256 | FIPS 180-4 : `"abc"`, chaîne vide, message de 448 bits (2 blocs) | ✅ |
| HMAC-SHA256 | RFC 4231, cas 2 et cas 6 (clé de 131 octets) | ✅ |
| PBKDF2-HMAC-SHA256 | `"password"` / `"salt"`, 1 et 4 096 itérations | ✅ |
| Texte chiffré GCM (flux CTR) | NIST GCM, cas de test 14 | ✅ |
| **Tag GCM** | NIST GCM, cas de test 14 | ❌ |

Tests sur fichiers (aller-retour chiffrement → déchiffrement) :

| Scénario | Résultat |
|----------|:--------:|
| Fichiers de 0, 1, 15, 16, 17, 100, 1 000 et 65 537 octets : contenu restitué à l'identique, taille + 44 octets | ✅ |
| Mauvais mot de passe → code `2`, fichier intact | ✅ |
| Un octet du fichier chiffré modifié → code `2` | ✅ |
| Fichier de moins de 44 octets → code `1` | ✅ |

### Écarts avec la norme GCM

L'authentification fonctionne de façon cohérente entre chiffrement et déchiffrement (toutes les altérations testées sont détectées), mais le tag n'est **pas** celui de la norme NIST SP 800-38D. Conséquence : les fichiers produits **ne peuvent pas être déchiffrés par une implémentation GCM standard** (OpenSSL, `cryptography` en Python…), sauf le cas particulier du fichier vide. Cette variante de GHASH n'a pas été analysée du point de vue sécurité.

Deux écarts en sont la cause :

1. **H est lu dans le mauvais ordre.** `memcpy(zeroEncrypted, (uint8_t*)bufferStateH, 16)` copie la matrice ligne par ligne, alors que la sortie d'AES se lit colonne par colonne. H se retrouve transposé.
2. **`gf128_multiply` n'utilise pas la convention de GCM.** Elle décale vers la gauche et réduit avec `0x87` sur le dernier octet ; GCM utilise l'ordre de bits inversé : décalage vers la droite et réduction avec `0xE1` sur le premier octet (SP 800-38D, § 6.3).

Une version corrigée de ces deux points a été testée : ses fichiers sont déchiffrés sans erreur par `AESGCM` (Python `cryptography`) avec la même clé PBKDF2. **Attention :** appliquer cette correction change le tag, donc les fichiers chiffrés avec la version actuelle ne seront plus lisibles par la version corrigée. Les déchiffrer avant de mettre à jour.

---

## Performances

Mesures indicatives (`gcc -O2`, machine de test Linux x86-64) :

| Opération | Durée |
|-----------|-------|
| Dérivation de clé PBKDF2 (13 000 itérations) | ≈ 0,3 s par chiffrement ou déchiffrement |
| Chiffrement d'un fichier de 4 Mo | ≈ 1,7 s (≈ 3 Mo/s) |

Le code privilégie la lisibilité sur la vitesse :

- `AES_Encrypt_State` recalcule l'expansion de clé (60 mots) **à chaque bloc** ;
- `gf128_multiply` traite les 128 bits un par un ;
- `choose`, `majority` et `ROTR` (SHA-256) travaillent bit par bit au lieu d'utiliser les opérateurs `&`, `^`, `|` sur le mot entier.

---

## Limites connues

**Sécurité**

- Tag GCM non conforme à la norme (voir [Écarts avec la norme GCM](#écarts-avec-la-norme-gcm)).
- 13 000 itérations PBKDF2, c'est peu : l'OWASP recommande 600 000 itérations pour PBKDF2-HMAC-SHA256. Penser à enregistrer le nombre d'itérations dans l'en-tête du fichier avant de l'augmenter.
- La comparaison du tag s'arrête au premier octet différent (comparaison non constante en temps).
- La clé, les sous-clés et les valeurs intermédiaires ne sont pas effacées de la mémoire après usage.
- Pas de données associées authentifiées (AAD).

**Robustesse**

- Les valeurs de retour de `fwrite` et `fclose` ne sont pas vérifiées : en cas de disque plein, un `.tmp` incomplet peut remplacer le fichier d'origine. Garder une sauvegarde des fichiers importants.
- Plusieurs `fread` ne sont pas vérifiés (`gcc -O2` affiche des avertissements `warn_unused_result`).
- Un fichier `<fichier>.tmp` déjà présent est écrasé sans avertissement.
- Taille maximale : environ 32 Gio (compteur de blocs en `int`), et 2 Gio sur les systèmes où `long` fait 32 bits (`ftell`).
- Toutes les fonctions sont globales avec des noms génériques. `SHA256` et `HMAC` portent le même nom que des fonctions d'OpenSSL : lier les deux dans un même programme provoquera un conflit. Déclarer les fonctions internes `static` ou leur ajouter un préfixe.

---

## Références

- [FIPS 197 — Advanced Encryption Standard (AES)](https://csrc.nist.gov/pubs/fips/197/final)
- [NIST SP 800-38D — Galois/Counter Mode (GCM)](https://csrc.nist.gov/pubs/sp/800/38/d/final)
- [FIPS 180-4 — Secure Hash Standard (SHA-256)](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [RFC 2104 — HMAC](https://www.rfc-editor.org/rfc/rfc2104)
- [RFC 4231 — Vecteurs de test HMAC-SHA256](https://www.rfc-editor.org/rfc/rfc4231)
- [RFC 8018 — PKCS #5 : PBKDF2](https://www.rfc-editor.org/rfc/rfc8018)
- [OWASP — Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)