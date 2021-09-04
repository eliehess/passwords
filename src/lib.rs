pub mod db {
    use sqlite;
    use std::{result, path};
    use super::encryption;

    static DB_LOCATION: &str = "passwords.db";

    pub struct Database {
        connection: sqlite::Connection,
        encryption: encryption::Encryption
    }

    impl Database {
        pub fn new(path: &path::PathBuf, encryption: encryption::Encryption) -> result::Result<Database, String> {
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

        pub fn add_password(&self, name: &str, password: &str) -> sqlite::Result<()> {
            let enc_password = hex::encode(self.encryption.encrypt(password));
            self.connection.execute(format!("INSERT INTO passwords VALUES ('{}', '{}')", name, enc_password))
        }
        
        pub fn get_password(&self, name: &str, password: &str) -> sqlite::Result<Vec<String>> {
            let mut statement = self.connection.prepare("SELECT password FROM passwords WHERE name = ?")?;
        
            statement.bind(1, name)?;
        
            let mut fin: Vec<String> = Vec::new();
        
            while let sqlite::State::Row = statement.next()? {
                fin.push(self.encryption.decrypt(&hex::decode(statement.read::<String>(0)?).unwrap(), &password));
            }
        
            Ok(fin)
        }
        
        pub fn remove_password(&self, name: &str) -> sqlite::Result<()> {
            self.connection.execute(format!("DELETE FROM passwords WHERE name = '{}'", name))
        }
        
        pub fn get_all_passwords(&self, password: &str) -> sqlite::Result<Vec<String>> {
            let mut statement = self.connection.prepare("SELECT name, password FROM passwords ORDER BY name ASC")?;
        
            let mut fin: Vec<String> = Vec::new();
        
            while let sqlite::State::Row = statement.next()? {
                let name = statement.read::<String>(0)?;
                let password = self.encryption.decrypt(&hex::decode(statement.read::<String>(1)?).unwrap(), &password);
                fin.push(format!("{}: {}", name, password));
            }
        
            Ok(fin)
        }
    }
}

pub mod encryption {
    use openssl::rsa::{Padding, Rsa};
    use openssl::symm::Cipher;
    use std::{fs, path, result};
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
        pub fn use_existing(path: &path::PathBuf) -> Result<Encryption, String> {
            if do_keys_exist(&path) {
                let public_key = utils::read_file(&path.join(PUBLIC_KEY)).unwrap();
                let private_key = utils::read_file(&path.join(PRIVATE_KEY)).unwrap();
                let password_hash = String::from_utf8(utils::read_file(&path.join(PASSWORD_HASH)).unwrap()).unwrap();

                Ok(Encryption { public_key, private_key, password_hash })
            } else {
                Err(String::from("Keys don't exist"))
            }
        }

        pub fn make_new(path: &path::PathBuf, password: &str) -> Encryption {
            let keypair = Rsa::generate(2048).unwrap();
            let cipher = Cipher::aes_256_cbc();
            let public_key = keypair.public_key_to_pem_pkcs1().unwrap();
            let private_key = keypair.private_key_to_pem_passphrase(cipher, password.as_bytes()).unwrap();
            let password_hash = utils::hash(&password);
            
            if !path.is_dir() {
                fs::create_dir_all(&path).unwrap();
            }
    
            fs::write(path.join(PUBLIC_KEY), &public_key).unwrap();
            fs::write(path.join(PRIVATE_KEY), &private_key).unwrap();
            fs::write(path.join(PASSWORD_HASH), &password_hash).unwrap();
            Encryption { public_key, private_key, password_hash }
        }

        pub fn check_password(&self, password: &str) -> result::Result<(), String> {
            if utils::hash(password) == self.password_hash {
                match Rsa::private_key_from_pem_passphrase(&self.private_key, password.as_bytes()) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(String::from("Password hash corrupted"))
                }
            } else {
                Err(String::from("Passwords don't match"))
            }
        }

        pub fn encrypt(&self, text: &str) -> Vec<u8> {
            let pubkey = Rsa::public_key_from_pem_pkcs1(&self.public_key).unwrap();
            let mut encrypted = vec![0; pubkey.size() as usize];
            pubkey.public_encrypt(text.as_bytes(), &mut encrypted, Padding::PKCS1).unwrap();
            encrypted
        }
    
        pub fn decrypt(&self, text: &Vec<u8>, password: &str) -> String {
            let privkey = Rsa::private_key_from_pem_passphrase(&self.private_key, password.as_bytes()).unwrap(); 
            let mut decrypted = vec![0; privkey.size() as usize];
            let len = privkey.private_decrypt(&text, &mut decrypted, Padding::PKCS1).unwrap();
            return String::from_utf8(decrypted[..len].to_vec()).unwrap();
        }
    }

    fn do_keys_exist(path: &path::PathBuf) -> bool {
        path.join(PUBLIC_KEY).exists() && 
        path.join(PRIVATE_KEY).exists() && 
        path.join(PASSWORD_HASH).exists()
    }
}

pub mod utils {
    use std::{fs, path};
    use std::io::{self, Read, Write};
    use std::result;
    use rpassword;

    pub fn read_file(filename: &path::PathBuf) -> io::Result<Vec<u8>> {
        let mut file = fs::File::open(filename)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }

    pub fn print_and_flush(output: &str) {
        print!("{}", output);
        io::stdout().flush().expect("Unable to flush stdout");
    }
    
    pub fn read_input() -> result::Result<String, String> {
        let mut input = String::new();
        match io::stdin().read_line(&mut input) {
            Ok(_n) => Ok(input.trim().to_string()),
            Err(e) => Err(format!("Error reading input: {}", e))
        }
    }
    
    pub fn read_password() -> result::Result<String, String> {
        match rpassword::read_password() {
            Ok(result) => Ok(result),
            Err(e) => Err(format!("Error reading password: {}", e))
        }
    }
    
    pub fn hash(input: impl AsRef<[u8]>) -> String {
        use sha2::{Sha256, Digest};
    
        let mut hasher = Sha256::new();
        hasher.update(input);
        return hex::encode(hasher.finalize());
    }
}
