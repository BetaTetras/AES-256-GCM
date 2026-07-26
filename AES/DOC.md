# Documentation Complète du Code AES-256

## 📋 Vue d'ensemble
Ce code implémente l'algorithme de chiffrement **AES-256** (Advanced Encryption Standard avec clé de 256 bits). AES est un algorithme symétrique qui chiffre et déchiffre des données en utilisant les mêmes clés.

---

## 🔑 FONCTIONS DE CONFIGURATION

### `void initStateDebugAlpha(uint8_t state[4][4])`
**Utilité:** Fonction de test/debug qui initialise une matrice avec tous les octets à `0xff` (255).
**Quand l'utiliser:** Pour tester le code avec des données simples.
```
Avant: état vide
Après: Matrice 4x4 remplie de 0xff
```

### `void initStateDebugBeta(uint8_t state[4][4])`
**Utilité:** Fonction de test/debug qui initialise une matrice avec des nombres séquentiels (0, 1, 2, ..., 15).
**Quand l'utiliser:** Pour déboguer et suivre facilement les transformations des données.
```
Résultat:
0x00 0x01 0x02 0x03
0x04 0x05 0x06 0x07
0x08 0x09 0x0a 0x0b
0x0c 0x0d 0x0e 0x0f
```

---

## 📊 FONCTIONS D'AFFICHAGE

### `void printState(uint8_t state[4][4])`
**Utilité:** Affiche la matrice d'état en format hexadécimal (4 lignes x 4 colonnes).
**Sortie:**
```
0x00 0x44 0x88 0xcc 
0x11 0x55 0x99 0xdd 
...
```
**Usage:** Déboguer et visualiser l'état du chiffrement à chaque étape.

### `void printWord(word w, int index)`
**Utilité:** Affiche un "mot" (4 octets) avec son numéro d'index dans les clés.
**Sortie:** `W[00] = 00 01 02 03`
**Usage:** Déboguer la génération des clés de ronde.

### `void debugGenerateKey(word finaleW[60])`
**Utilité:** Affiche les 60 mots générés à partir de la clé principale (pour tous les diagnostics clé).
**Usage:** Vérifier que la clé a été correctement développée.

---

## 🔐 FONCTIONS PRINCIPALES D'AES

### `void addRoundKey(uint8_t state[4][4], word rondKey[4])`
**Utilité:** Effectue une **addition XOR** entre l'état et une clé de ronde.
**Fonctionnement:**
```
Pour chaque élément state[i][y]:
  state[i][y] = state[i][y] XOR rondKey[y][i]
```
**Important:** L'indexation est transposée pour les colonnes.
**Rôle dans AES:** Mélange la clé avec les données (étape de sécurité critique).

---

## 🔀 OPÉRATIONS DE SUBSTITUTION

### `void SubBytes(uint8_t state[4][4])`
**Utilité:** Remplace chaque octet par sa valeur dans la **S-BOX** (table de substitution).
**Fonctionnement:**
```
Avant: state[0][0] = 0x19
Après: state[0][0] = SBOX[0x19] = 0xd4
```
**Rôle:** Ajoute de la non-linéarité pour la sécurité cryptographique.
**Direction:** Chiffrement uniquement.

### `void InvSubBytes(uint8_t state[4][4])`
**Utilité:** Inverse l'opération `SubBytes` en utilisant la **S-BOX inverse**.
```
Avant: state[0][0] = 0xd4
Après: state[0][0] = INV_SBOX[0xd4] = 0x19
```
**Direction:** Déchiffrement uniquement.

---

## ↔️ OPÉRATIONS DE DÉCALAGE DE LIGNES

### `void ShiftRows(uint8_t state[4][4])`
**Utilité:** Décale les éléments de chaque ligne vers la gauche (rotation).
**Fonctionnement:**
```
Ligne 0: pas de décalage
Ligne 1: décalé 1 fois vers la gauche
Ligne 2: décalé 2 fois vers la gauche
Ligne 3: décalé 3 fois vers la gauche

Avant:           Après:
a0 a4 a8 ac      a0 a4 a8 ac
b0 b4 b8 bc  →   b4 b8 bc b0
c0 c4 c8 cc      c8 cc c0 c4
d0 d4 d8 dc      dc d0 d4 d8
```
**Rôle:** Disperse les données horizontalement.

### `void InvShiftRows(uint8_t state[4][4])`
**Utilité:** Inverse l'opération `ShiftRows` (décalage vers la droite).
**Direction:** Déchiffrement uniquement.

### `void push(uint8_t ligne[4], int x)`
**Utilité:** Effectue `x` rotations circulaires vers la **gauche** sur une ligne.
```
push([a, b, c, d], 1) → [b, c, d, a]
push([a, b, c, d], 2) → [c, d, a, b]
```
**Utilisée par:** `ShiftRows`

### `void pop(uint8_t ligne[4], int x)`
**Utilité:** Effectue `x` rotations circulaires vers la **droite** sur une ligne (inverse de `push`).
```
pop([a, b, c, d], 1) → [d, a, b, c]
```
**Utilisée par:** `InvShiftRows`

---

## 🧮 OPÉRATIONS DE MULTIPLICATION EN GF(2^8)

### `uint8_t xtime(uint8_t octet)`
**Utilité:** Multiplie par 2 dans le corps de Galois GF(2^8).
**Fonctionnement:**
```
Si le bit 7 = 1: décaler à gauche ET faire XOR avec 0x1b
Sinon: juste décaler à gauche
```
**Exemple:**
```
xtime(0x57) = 0xae
xtime(0x80) = 0x1b
```
**Rôle:** Élément de base pour `MixColumns`.

### `uint8_t mul(uint8_t a, uint8_t b)`
**Utilité:** Multiplie deux octets dans GF(2^8) en utilisant des `xtime` répétées.
**Algorithme:** Décompose la multiplication binaire.
```
Pour chaque bit de b:
  - Si le bit = 1: ajouter (XOR) la valeur courante de a
  - Décaler a vers la gauche (xtime)
```
**Exemple:** `mul(0x57, 0x13) = 0xff`

---

## 🎨 OPÉRATION DE MÉLANGE DE COLONNES

### `void MixColumns(uint8_t state[4][4])`
**Utilité:** Effectue une transformation linéaire sur chaque **colonne** de la matrice d'état.
**Fonctionnement:** Multiplie chaque colonne par une matrice fixe en GF(2^8):
```
┌     ┐   ┌           ┐   ┌     ┐
│ a0' │   │ 02 03 01 01 │   │ a0 │
│ a1' │ = │ 01 02 03 01 │ × │ a1 │
│ a2' │   │ 01 01 02 03 │   │ a2 │
│ a3' │   │ 03 01 01 02 │   │ a3 │
└     ┘   └           ┘   └     ┘
```
**Résultat:**
```
a0' = 2*a0 ⊕ 3*a1 ⊕ a2 ⊕ a3
a1' = a0 ⊕ 2*a1 ⊕ 3*a2 ⊕ a3
a2' = a0 ⊕ a1 ⊕ 2*a2 ⊕ 3*a3
a3' = 3*a0 ⊕ a1 ⊕ a2 ⊕ 2*a3
```
**Rôle:** Diffuse les données verticalement.

### `void InvMixColumns(uint8_t state[4][4])`
**Utilité:** Inverse l'opération `MixColumns` pour le déchiffrement.
**Utilise une matrice inverse différente:**
```
┌     ┐   ┌           ┐   ┌     ┐
│ a0' │   │ 0e 0b 0d 09 │   │ a0 │
│ a1' │ = │ 09 0e 0b 0d │ × │ a1 │
│ a2' │   │ 0d 09 0e 0b │   │ a2 │
│ a3' │   │ 0b 0d 09 0e │   │ a3 │
└     ┘   └           ┘   └     ┘
```

---

## 🔑 FONCTIONS DE GÉNÉRATION DE CLÉ

### `void SubWord(uint8_t ligne[4])`
**Utilité:** Remplace chaque octet d'un mot par son équivalent dans la S-BOX.
**Utilisée par:** Génération de clé de ronde.

### `void RotWord(uint8_t ligne[4])`
**Utilité:** Effectue une rotation circulaire d'un mot vers la gauche.
```
Avant: [a0, a1, a2, a3]
Après: [a1, a2, a3, a0]
```
**Utilisée par:** Génération de clé de ronde.

### `void Explode(uint8_t cle[32], word w[8])`
**Utilité:** Convertit la clé de 32 octets en 8 mots de 4 octets chacun.
```
Clé:     [00 01 02 03 04 05 06 07 ...]
         ↓
W[0]:    [00 01 02 03]
W[1]:    [04 05 06 07]
...
W[7]:    [1c 1d 1e 1f]
```

### `void GenerateKey(word finaleW[60], word initialW[8])`
**Utilité:** **Génère les 60 mots de clé** (15 rondes × 4 mots) à partir des 8 mots initiaux.
**Algorithme pour chaque mot W[i]:**
```
Si i % 8 == 0:
  W[i] = (SubWord(RotWord(W[i-1])) ⊕ RCON[i/8]) ⊕ W[i-8]

Sinon si i % 8 == 4:
  W[i] = SubWord(W[i-1]) ⊕ W[i-8]

Sinon:
  W[i] = W[i-1] ⊕ W[i-8]
```
**Rôle:** Créer 60 mots différents pour les 15 rondes de chiffrement.

---

## 🔐 FONCTIONS DE CHIFFREMENT/DÉCHIFFREMENT PRINCIPAL

### `void AES_Encrypt_State(uint8_t state[4][4], uint8_t cle[32])`
**Utilité:** **Chiffre une matrice 4×4** (16 octets) avec AES-256.

**Étapes:**
1. Explode la clé en 8 mots
2. Génère les 60 mots de clé
3. **AddRoundKey** initial (clé W[0..3])
4. **13 rondes** complètes:
   - SubBytes
   - ShiftRows
   - MixColumns
   - AddRoundKey
5. **Ronde finale** (sans MixColumns):
   - SubBytes
   - ShiftRows
   - AddRoundKey (W[56..59])

**Résultat:** État chiffré.

### `void AES_Decrypt_State(uint8_t state[4][4], uint8_t cle[32])`
**Utilité:** **Déchiffre une matrice 4×4** avec la même clé.

**Étapes (inverse de chiffrement):**
1. Explode et génère les 60 mots de clé (identique)
2. **AddRoundKey** final (W[56..59])
3. **13 rondes inverses** (de la 13ème à la 1ère):
   - InvShiftRows
   - InvSubBytes
   - AddRoundKey
   - InvMixColumns
4. **Ronde initiale** (sans InvMixColumns):
   - InvShiftRows
   - InvSubBytes
   - AddRoundKey (W[0..3])

**Résultat:** État d'origine récupéré.

---

## 📁 FONCTION DE LECTURE DE FICHIER

### `void fileBinaryTrancription(uint8_t (*dest)[4][4], char* path)`
**Utilité:** Lit un fichier binaire et le charge dans un **tableau de matrices AES**.
**Fonctionnement:**

1. **Ouverture du fichier** en mode binaire lecture
2. **Calcul de la taille** du fichier
3. **Allocation mémoire** pour les données
4. **Lecture complète** du fichier
5. **Conversion en matrices 4×4:**
   - Si taille multiple de 16 → conversion directe
   - Sinon → **ajout de padding PKCS#7:**
     ```
     Bytes restants: 5 octets
     Padding à ajouter: 16 - 5 = 11 octets
     Chaque octet de padding = 0x0b (11 en décimal)
     ```
6. **Fermeture** du fichier et libération mémoire

**Exemple:**
```
Fichier: 40 octets
→ 2 matrices complètes (32 octets)
→ 1 matrice partielle (8 octets) + 8 octets de padding

dest[0] = première matrice 4×4
dest[1] = deuxième matrice 4×4
dest[2] = matrice 4×4 avec padding
```

---

## 🔄 FLUX COMPLET D'UTILISATION

```
┌─────────────────────────────────────────┐
│ 1. Chiffrement d'une matrice            │
├─────────────────────────────────────────┤
│ AES_Encrypt_State(state, cle)           │
│   ↓ AddRoundKey (W[0..3])               │
│   ↓ Boucle 13 fois:                     │
│     ↓ SubBytes → ShiftRows              │
│     ↓ MixColumns → AddRoundKey          │
│   ↓ SubBytes → ShiftRows                │
│   ↓ AddRoundKey (W[56..59])             │
│ Résultat: state chiffré                 │
└─────────────────────────────────────────┘

┌─────────────────────────────────────────┐
│ 2. Déchiffrement de la matrice          │
├─────────────────────────────────────────┤
│ AES_Decrypt_State(state, cle)           │
│   ↓ AddRoundKey (W[56..59])             │
│   ↓ Boucle 13 fois (inverse):           │
│     ↓ InvShiftRows → InvSubBytes        │
│     ↓ AddRoundKey → InvMixColumns       │
│   ↓ InvShiftRows → InvSubBytes          │
│   ↓ AddRoundKey (W[0..3])               │
│ Résultat: state original restauré       │
└─────────────────────────────────────────┘
```

---

## 📌 TABLEAU RÉCAPITULATIF

| Fonction | Type | Rôle | Utilisée par |
|----------|------|------|--------------|
| `initStateDebugAlpha/Beta` | Debug | Initialiser l'état pour tests | Tests manuels |
| `printState/Word` | Debug | Afficher l'état | Déboguer |
| `SubBytes` | Transformation | Non-linéarité | Chiffrement |
| `InvSubBytes` | Transformation | Inverse SubBytes | Déchiffrement |
| `ShiftRows` | Dispersion | Diffusion horizontale | Chiffrement |
| `InvShiftRows` | Dispersion | Inverse ShiftRows | Déchiffrement |
| `MixColumns` | Diffusion | Diffusion verticale | Chiffrement |
| `InvMixColumns` | Diffusion | Inverse MixColumns | Déchiffrement |
| `xtime` | Multiplication | GF(2^8) ×2 | MixColumns |
| `mul` | Multiplication | GF(2^8) ×a | InvMixColumns |
| `addRoundKey` | Clé | Mélange clé | Tous les 2 étapes |
| `GenerateKey` | Clé | Génère 60 mots | Chiffrement & Déchiffrement |
| `AES_Encrypt_State` | Principal | Chiffre | main() |
| `AES_Decrypt_State` | Principal | Déchiffre | main() |
| `fileBinaryTrancription` | I/O | Charge fichier | Traitement fichiers |

---

## 🎯 RÉSUMÉ EN UNE PHRASE

**Ce code implémente AES-256:** prend un fichier/données 16 octets à la fois, les transforme 15 fois via substitution, décalage et mélange avec une clé de 256 bits pour les chiffrer, et inverse exactement ce processus pour les déchiffrer.

Générée par Claude Haiku 4.5