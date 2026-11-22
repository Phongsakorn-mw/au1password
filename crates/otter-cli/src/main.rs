use clap::{Parser, Subcommand};
use colored::Colorize;
use otter_model::{ItemPayload, ItemType, Vault, VaultItem};
use otter_storage::VaultStorage;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "otter", version = "0.1.0", about = "OtterVault - Personal Encrypted Linux Vault with Google Drive Sync")]
struct Cli {
    #[arg(short, long, help = "Path to encrypted vault file (default: ~/.local/share/otter-vault/vault.enc)")]
    vault: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new empty encrypted vault
    Init,

    /// List items stored in the vault
    List {
        #[arg(short, long, help = "Filter by category: login, note, image, file")]
        type_filter: Option<String>,
    },

    /// Add a new login credential
    AddLogin {
        #[arg(short, long)]
        title: String,
        #[arg(short, long)]
        username: String,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(long)]
        url: Option<String>,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
    },

    /// Add a secure note or markdown document
    AddNote {
        #[arg(short, long)]
        title: String,
        #[arg(short, long)]
        content: String,
        #[arg(long, value_delimiter = ',')]
        tags: Vec<String>,
    },

    /// Show details for a vault item by ID or title match
    Get {
        query: String,
        #[arg(short, long, help = "Reveal password in terminal output")]
        reveal: bool,
    },

    /// Inspect sync status and encryption metadata
    Status,
}

fn prompt_password(prompt: &str) -> String {
    if let Ok(env_pass) = std::env::var("OTTER_MASTER_PASSWORD") {
        return env_pass;
    }
    use std::io::{self, BufRead, Write};
    let _ = io::stdout().write_all(prompt.as_bytes());
    let _ = io::stdout().flush();

    let mut line = String::new();
    let stdin = io::stdin();
    if stdin.lock().read_line(&mut line).is_ok() {
        return line.trim_end_matches(['\r', '\n']).to_string();
    }
    rpassword::prompt_password(prompt).unwrap_or_default()
}

fn get_storage(custom_path: Option<PathBuf>) -> Result<VaultStorage, Box<dyn std::error::Error>> {
    if let Some(p) = custom_path {
        Ok(VaultStorage::new(p))
    } else {
        Ok(VaultStorage::default_location()?)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    let storage = get_storage(cli.vault)?;

    match cli.command {
        Commands::Init => {
            if storage.exists() {
                eprintln!("{}", format!("Vault already exists at {:?}", storage.path()).yellow());
                return Ok(());
            }

            println!("{}", "=== Initializing New OtterVault ===".cyan().bold());
            let pass1 = prompt_password("Enter Master Password: ");
            let pass2 = prompt_password("Confirm Master Password: ");

            if pass1 != pass2 {
                eprintln!("{}", "Error: Master passwords do not match!".red());
                std::process::exit(1);
            }
            if pass1.is_empty() {
                eprintln!("{}", "Error: Master password cannot be empty!".red());
                std::process::exit(1);
            }

            let vault = Vault::new();
            storage.save_vault(&vault, &pass1)?;
            println!("{}", format!("Successfully created vault at {:?}", storage.path()).green());
        }

        Commands::List { type_filter } => {
            if !storage.exists() {
                eprintln!("{}", "Vault not found. Run 'otter init' first.".yellow());
                return Ok(());
            }

            let pass = prompt_password("Enter Master Password: ");
            let vault = storage.load_vault(&pass)?;

            println!("{}", format!("=== OtterVault Items ({}) ===", vault.items.len()).cyan().bold());
            let mut count = 0;

            for item in &vault.items {
                let matches_filter = match &type_filter {
                    Some(f) => match f.to_lowercase().as_str() {
                        "login" => item.item_type() == ItemType::Login,
                        "note" => item.item_type() == ItemType::Note,
                        "image" => item.item_type() == ItemType::Image,
                        "file" => item.item_type() == ItemType::File,
                        _ => true,
                    },
                    None => true,
                };

                if !matches_filter {
                    continue;
                }
                count += 1;

                let type_badge = match item.item_type() {
                    ItemType::Login => "[LOGIN]".blue(),
                    ItemType::Note => "[NOTE ]".green(),
                    ItemType::Image => "[IMAGE]".yellow(),
                    ItemType::File => "[FILE ]".magenta(),
                };

                let detail = match &item.payload {
                    ItemPayload::Login(l) => format!("user: {}", l.username),
                    ItemPayload::Note(_) => "note document".into(),
                    ItemPayload::Image(img) => format!("image: {}", img.filename),
                    ItemPayload::File(f) => format!("file: {} ({} bytes)", f.filename, f.size_bytes),
                };

                println!("{} {} - {} ({})", type_badge, item.title.bold(), detail, item.id);
            }

            if count == 0 {
                println!("{}", "No matching items found.".dimmed());
            }
        }

        Commands::AddLogin { title, username, password, url, tags } => {
            let pass = prompt_password("Enter Master Password: ");
            let mut vault = storage.load_vault(&pass)?;

            let item_password = match password {
                Some(p) => p,
                None => prompt_password(&format!("Enter secret password for {}: ", title)),
            };
            let new_item = VaultItem::new_login(title, username, item_password, url, tags);
            let item_title = new_item.title.clone();
            vault.add_item(new_item);

            storage.save_vault(&vault, &pass)?;
            println!("{}", format!("Added credential '{}' to vault.", item_title).green());
        }

        Commands::AddNote { title, content, tags } => {
            let pass = prompt_password("Enter Master Password: ");
            let mut vault = storage.load_vault(&pass)?;

            let new_item = VaultItem::new_note(title, content, tags);
            let item_title = new_item.title.clone();
            vault.add_item(new_item);

            storage.save_vault(&vault, &pass)?;
            println!("{}", format!("Added secure note '{}' to vault.", item_title).green());
        }

        Commands::Get { query, reveal } => {
            let pass = prompt_password("Enter Master Password: ");
            let vault = storage.load_vault(&pass)?;

            let item = vault.items.iter().find(|i| {
                i.id.to_string() == query || i.title.to_lowercase().contains(&query.to_lowercase())
            });

            match item {
                Some(i) => {
                    println!("{}", format!("=== {} ===", i.title).cyan().bold());
                    println!("ID: {}", i.id);
                    println!("Type: {:?}", i.item_type());
                    println!("Updated: {}", i.updated_at);
                    println!("Tags: {:?}", i.tags);

                    match &i.payload {
                        ItemPayload::Login(l) => {
                            println!("Username: {}", l.username.bold());
                            if reveal {
                                println!("Password: {}", l.password.red().bold());
                            } else {
                                println!("Password: {}", "•••••••••••••••• (pass --reveal to show)".dimmed());
                            }
                            if let Some(url) = &l.url {
                                println!("URL: {}", url);
                            }
                        }
                        ItemPayload::Note(n) => {
                            println!("\nContent:\n{}", n.content);
                        }
                        ItemPayload::Image(img) => {
                            println!("Filename: {}", img.filename);
                            println!("MIME: {}", img.mime_type);
                            println!("Checksum: {}", img.checksum_sha256);
                        }
                        ItemPayload::File(f) => {
                            println!("Filename: {}", f.filename);
                            println!("Size: {} bytes", f.size_bytes);
                            println!("Checksum: {}", f.checksum_sha256);
                        }
                    }
                }
                None => {
                    eprintln!("{}", format!("Item matching '{}' not found", query).red());
                }
            }
        }

        Commands::Status => {
            if !storage.exists() {
                println!("{}", "Vault status: Not initialized.".yellow());
                return Ok(());
            }

            let envelope = storage.read_envelope()?;
            println!("{}", "=== OtterVault Storage Status ===".cyan().bold());
            println!("Path: {:?}", storage.path());
            println!("Version: {}", envelope.version);
            println!("Format: {}", envelope.format);
            println!("KDF: {} (iterations: {})", envelope.kdf.algorithm, envelope.kdf.iterations);
            println!("Cipher: {}", envelope.cipher.algorithm);
            println!("Encrypted items count: {}", envelope.meta.item_count);
            println!("Last modified timestamp: {}", envelope.meta.last_modified);
            println!("Google Drive appDataFolder status: Ready for sync");
        }
    }

    Ok(())
}
