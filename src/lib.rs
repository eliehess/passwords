#![windows_subsystem = "windows"]

pub mod db {
    use std::{path, error::Error};
    use sqlite;
    use super::encryption;

    static DB_LOCATION: &str = "passwords.db";

    pub struct Database {
        connection: sqlite::Connection,
        encryption: encryption::Encryption
    }

    impl Database {
        pub fn new(path: &path::PathBuf, encryption: encryption::Encryption) -> Result<Database, String> {
            let connection = match sqlite::open(path.join(DB_LOCATION)) {
                Ok(c) => c,
                Err(e) => return Err(format!("Unable to connect to database: {}", e))
            };

            let db = Database { connection, encryption };

            match db.connection.execute("CREATE TABLE IF NOT EXISTS passwords (name TEXT, password TEXT, PRIMARY KEY (name))") {
                Ok(()) => Ok(db),
                Err(e) => Err(format!("Unable to initialize database: {}", e))
            }
        }

        pub fn add_password(&self, name: &str, password: &str) -> Result<(), Box<dyn Error>> {
            let enc_password = hex::encode(self.encryption.encrypt(password)?);
            Ok(self.connection.execute(format!("INSERT INTO passwords VALUES ('{}', '{}')", name, enc_password))?)
        }
        
        pub fn get_password(&self, name: &str, password: &str) -> Result<Vec<String>, Box<dyn Error>> {
            let mut statement = self.connection.prepare("SELECT password FROM passwords WHERE name = ?")?;
        
            statement.bind(1, name)?;
        
            let mut fin: Vec<String> = Vec::new();
        
            while let sqlite::State::Row = statement.next()? {
                fin.push(self.encryption.decrypt(&hex::decode(statement.read::<String>(0)?)?, &password)?);
            }
        
            Ok(fin)
        }
        
        pub fn remove_password(&self, name: &str) -> sqlite::Result<()> {
            self.connection.execute(format!("DELETE FROM passwords WHERE name = '{}'", name))
        }
        
        pub fn get_all_passwords(&self, password: &str) -> Result<Vec<String>, Box<dyn Error>> {
            let mut statement = self.connection.prepare("SELECT name, password FROM passwords ORDER BY name ASC")?;
        
            let mut fin: Vec<String> = Vec::new();
        
            while let sqlite::State::Row = statement.next()? {
                let name = statement.read::<String>(0)?;
                let password = self.encryption.decrypt(&hex::decode(statement.read::<String>(1)?)?, &password)?;
                fin.push(format!("{}: {}", name, password));
            }
        
            Ok(fin)
        }

        pub fn get_all_names(&self) -> Result<Vec<String>, Box<dyn Error>> {
            let mut statement = self.connection.prepare("SELECT name FROM passwords ORDER BY name ASC")?;
        
            let mut fin: Vec<String> = Vec::new();
        
            while let sqlite::State::Row = statement.next()? {
                fin.push(format!("{}", statement.read::<String>(0)?));
            }
        
            Ok(fin)
        }
    }
}

pub mod encryption {
    use openssl::{symm::Cipher, rsa::{Padding, Rsa}};
    use std::{fs, path, result, io, error::Error};
    use super::utils;
    
    static PUBLIC_KEY: &str = "public.key";
    static PRIVATE_KEY: &str = "private.key";
    static PASSWORD_HASH: &str = "password.hash";

    pub struct Encryption {
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        password_hash: String
    }

    impl Encryption {
        pub fn use_existing(path: &path::PathBuf) -> Result<Encryption, Box<dyn Error>> {
            if do_keys_exist(&path) {
                let public_key = utils::read_file(&path.join(PUBLIC_KEY))?;
                let private_key = utils::read_file(&path.join(PRIVATE_KEY))?;
                let password_hash = String::from_utf8(utils::read_file(&path.join(PASSWORD_HASH))?)?;

                Ok(Encryption { public_key, private_key, password_hash })
            } else {
                Err(Box::new(io::Error::new(io::ErrorKind::Other, "Keys don't exist")))
            }
        }

        pub fn make_new(path: &path::PathBuf, password: &str) -> Result<Encryption, Box<dyn Error>> {
            let keypair = Rsa::generate(2048)?;
            let public_key = keypair.public_key_to_pem_pkcs1()?;
            let private_key = keypair.private_key_to_pem_passphrase(Cipher::aes_256_cbc(), password.as_bytes())?;
            let password_hash = utils::hash(&password);
            
            if !path.is_dir() {
                fs::create_dir_all(&path)?;
            }
    
            fs::write(path.join(PUBLIC_KEY), &public_key)?;
            fs::write(path.join(PRIVATE_KEY), &private_key)?;
            fs::write(path.join(PASSWORD_HASH), &password_hash)?;
            Ok(Encryption { public_key, private_key, password_hash })
        }

        pub fn check_password(&self, password: &str) -> result::Result<(), String> {
            if utils::hash(password) == self.password_hash {
                match Rsa::private_key_from_pem_passphrase(&self.private_key, password.as_bytes()) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("Password hash corrupted"))
                }
            } else {
                Err(String::from("Incorrect password"))
            }
        }

        pub fn encrypt(&self, text: &str) -> Result<Vec<u8>, openssl::error::ErrorStack> {
            let pubkey = Rsa::public_key_from_pem_pkcs1(&self.public_key)?;
            let mut encrypted = vec![0; pubkey.size() as usize];
            pubkey.public_encrypt(text.as_bytes(), &mut encrypted, Padding::PKCS1)?;
            Ok(encrypted)
        }
    
        pub fn decrypt(&self, text: &Vec<u8>, password: &str) -> Result<String, Box<dyn Error>> {
            let privkey = Rsa::private_key_from_pem_passphrase(&self.private_key, password.as_bytes())?; 
            let mut decrypted = vec![0; privkey.size() as usize];
            let len = privkey.private_decrypt(&text, &mut decrypted, Padding::PKCS1)?;
            Ok(String::from_utf8(decrypted[..len].to_vec())?)
        }
    }

    fn do_keys_exist(path: &path::PathBuf) -> bool {
        path.join(PUBLIC_KEY).exists() && 
        path.join(PRIVATE_KEY).exists() && 
        path.join(PASSWORD_HASH).exists()
    }
}

pub mod utils {
    use std::{fs, path, io::{self, Read, Write}};
    use sha2::{Sha256, Digest};
    use rpassword;
    use clipboard_win::Clipboard;

    pub fn read_file(filename: &path::PathBuf) -> io::Result<Vec<u8>> {
        let mut file = fs::File::open(filename)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }

    pub fn print_and_flush(output: impl AsRef<str>) -> io::Result<()> {
        print!("{}", output.as_ref());
        io::stdout().flush()
    }
    
    pub fn read_input() -> io::Result<String> {
        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        Ok(input.trim().to_string())
    }
    
    pub fn read_password() -> io::Result<String> {
        rpassword::read_password()
    }

    pub fn hash(input: impl AsRef<[u8]>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input);
        hex::encode(hasher.finalize())
    }

    pub fn set_clipboard(text: &str) -> io::Result<()> {
        Clipboard::new()?.set_string(text)
    }
}
