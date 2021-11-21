pub mod db {
    use std::{path, fs, io::{self, Read}};
    use sqlite;
    use snafu::{Snafu, ResultExt};
    use openssl::{symm::Cipher, rsa::{Padding, Rsa}};
    use sha2::{Sha256, Digest};

    static DB_LOCATION: &str = "passwords.db";
    static PUBLIC_KEY: &str = "public.key";
    static PRIVATE_KEY: &str = "private.key";
    static PASSWORD_HASH: &str = "password.hash";

    #[derive(Debug, Snafu)]
    pub enum DatabaseError {
        #[snafu(display("Authentication error: {}", message))]
        Authentication {
            message: String
        },

        #[snafu(display("File error: {}", message))]
        File {
            message: String
        },

        #[snafu(display("{}", source))]
        Io {
            source: io::Error
        },

        #[snafu(display("{}", source))]
        OpenSSL {
            source: openssl::error::ErrorStack
        },

        #[snafu(display("{}", source))]
        Utf8 {
            source: std::string::FromUtf8Error
        },

        #[snafu(display("{}", source))]
        SQLite {
            source: sqlite::Error
        },

        #[snafu(display("{}", source))]
        Hex {
            source: hex::FromHexError
        }
    }

    pub struct Database {
        connection: sqlite::Connection,
        encryption: Encryption,
        password: String
    }

    impl Database {
        pub fn add_password(&self, name: &str, password_to_add: &str) -> Result<(), DatabaseError> {
            let enc_password_to_add = hex::encode(self.encryption.encrypt(password_to_add).context(OpenSSL)?);

            let mut statement = self.connection.prepare("INSERT INTO passwords VALUES (?1, ?2)").context(SQLite)?;
            statement.bind(1, name).context(SQLite)?;
            statement.bind(2, enc_password_to_add.as_str()).context(SQLite)?;

            while let sqlite::State::Row = statement.next().context(SQLite)? {}
            
            Ok(())
        }
        
        pub fn get_password(&self, name: &str) -> Result<Vec<String>, DatabaseError> {
            let mut statement = self.connection.prepare("SELECT password FROM passwords WHERE name = ?").context(SQLite)?;
        
            statement.bind(1, name).context(SQLite)?;
        
            let mut fin: Vec<String> = Vec::new();
        
            while let sqlite::State::Row = statement.next().context(SQLite)? {
                fin.push(self.encryption.decrypt(&hex::decode(statement.read::<String>(0).context(SQLite)?).context(Hex)?, &self.password)?);
            }
        
            Ok(fin)
        }
        
        pub fn remove_password(&self, name: &str) -> sqlite::Result<()> {
            let mut statement = self.connection.prepare("DELETE FROM passwords WHERE name = ?")?;
            statement.bind(1, name)?;
            while let sqlite::State::Row = statement.next()? {}
            Ok(())
        }
        
        pub fn get_all_passwords(&self) -> Result<Vec<(String, String)>, DatabaseError> {
            let mut statement = self.connection.prepare("SELECT name, password FROM passwords ORDER BY name ASC").context(SQLite)?;
        
            let mut fin: Vec<(String, String)> = Vec::new();
        
            while let sqlite::State::Row = statement.next().context(SQLite)? {
                let name = statement.read::<String>(0).context(SQLite)?;
                let password = self.encryption.decrypt(&hex::decode(statement.read::<String>(1).context(SQLite)?).context(Hex)?, &self.password)?;
                fin.push((name, password));
            }
        
            Ok(fin)
        }

        pub fn get_all_names(&self) -> Result<Vec<String>, DatabaseError> {
            let mut statement = self.connection.prepare("SELECT name FROM passwords ORDER BY name ASC").context(SQLite)?;
        
            let mut fin: Vec<String> = Vec::new();
        
            while let sqlite::State::Row = statement.next().context(SQLite)? {
                fin.push(format!("{}", statement.read::<String>(0).context(SQLite)?));
            }
        
            Ok(fin)
        }
    }

    pub fn create_new(path: &path::PathBuf, password: &str) -> Result<Database, DatabaseError> {
        match db_exists(&path) {
            FileStatus::All => { return File { message: "Database already exists" }.fail(); },
            FileStatus::Some => { return File { message: "Database corrupted" }.fail(); },
            FileStatus::None => ()
        }

        let encryption = Encryption::create_new(path, password)?;

        let connection = sqlite::open(path.join(DB_LOCATION)).context(SQLite)?;

        let db = Database { connection, encryption, password: String::from(password) };

        db.connection.execute("CREATE TABLE IF NOT EXISTS passwords (name TEXT, password TEXT, PRIMARY KEY (name))").context(SQLite)?;

        Ok(db)
    }

    pub fn use_existing(path: &path::PathBuf, password: &str) -> Result<Database, DatabaseError> {
        match db_exists(&path) {
            FileStatus::All => (),
            FileStatus::Some => { return File { message: "Database corrupted" }.fail(); },
            FileStatus::None => { return File { message: "No database exists" }.fail(); }
        }

        let connection = sqlite::open(path.join(DB_LOCATION)).context(SQLite)?;

        let encryption = Encryption::use_existing(path, password)?;

        Ok(Database { connection, encryption, password: String::from(password) })
    }

    pub fn db_exists(path: &path::PathBuf) -> FileStatus {
        match Encryption::encryption_exists(path) {
            FileStatus::All => if path.join(DB_LOCATION).exists() { FileStatus::All } else { FileStatus::Some },
            FileStatus::Some => FileStatus::Some,
            FileStatus::None => if path.join(DB_LOCATION).exists() { FileStatus::Some } else { FileStatus::None} 
        }
    }

    pub fn delete(path: &path::PathBuf) -> io::Result<()> {
        Encryption::delete(path)?;
        fs::remove_file(path.join(DB_LOCATION))
    }

    pub enum FileStatus {
        All,
        Some,
        None
    }

    struct Encryption {
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        password_hash: String
    }

    impl Encryption {
        pub fn encrypt(&self, text: &str) -> Result<Vec<u8>, openssl::error::ErrorStack> {
            let pubkey = Rsa::public_key_from_pem_pkcs1(&self.public_key)?;
            let mut encrypted = vec![0; pubkey.size() as usize];
            pubkey.public_encrypt(text.as_bytes(), &mut encrypted, Padding::PKCS1)?;
            Ok(encrypted)
        }
    
        pub fn decrypt(&self, text: &Vec<u8>, password: &str) -> Result<String, DatabaseError> {
            let privkey = Rsa::private_key_from_pem_passphrase(&self.private_key, password.as_bytes()).context(OpenSSL)?; 
            let mut decrypted = vec![0; privkey.size() as usize];
            let len = privkey.private_decrypt(&text, &mut decrypted, Padding::PKCS1).context(OpenSSL)?;
            Ok(String::from_utf8(decrypted[..len].to_vec()).context(Utf8)?)
        }

        pub fn use_existing(path: &path::PathBuf, password: &str) -> Result<Encryption, DatabaseError> {
            match Encryption::encryption_exists(&path) {
                FileStatus::All => (),
                FileStatus::Some => { return  File { message: "Keys corrupted" }.fail(); },
                FileStatus::None => { return  File { message: "Keys don't exist" }.fail(); }
            }
    
            let public_key = read_file(&path.join(PUBLIC_KEY)).context(Io)?;
            let private_key = read_file(&path.join(PRIVATE_KEY)).context(Io)?;
            let password_hash = String::from_utf8(read_file(&path.join(PASSWORD_HASH)).context(Io)?).context(Utf8)?;
    
            let encryption = Encryption { public_key, private_key, password_hash };
    
            Encryption::check_password(&encryption, password)?;
    
            Ok(encryption)
        }
    
        pub fn create_new(path: &path::PathBuf, password: &str) -> Result<Encryption, DatabaseError> {
            match Encryption::encryption_exists(&path) {
                FileStatus::All => { return File { message: "Keys already exist" }.fail(); },
                FileStatus::Some => { return File { message: "Keys corrupted" }.fail(); },
                FileStatus::None => ()
            }
    
            let keypair = Rsa::generate(2048).context(OpenSSL)?;
            let public_key = keypair.public_key_to_pem_pkcs1().context(OpenSSL)?;
            let private_key = keypair.private_key_to_pem_passphrase(Cipher::aes_256_cbc(), password.as_bytes()).context(OpenSSL)?;
            let password_hash = hash(&password);
            
            if !path.is_dir() {
                fs::create_dir_all(&path).context(Io)?;
            }
    
            fs::write(path.join(PUBLIC_KEY), &public_key).context(Io)?;
            fs::write(path.join(PRIVATE_KEY), &private_key).context(Io)?;
            fs::write(path.join(PASSWORD_HASH), &password_hash).context(Io)?;
            Ok(Encryption { public_key, private_key, password_hash })
        }
    
        pub fn check_password(encryption: &Encryption, password: &str) -> Result<(), DatabaseError> {
            if hash(password) != encryption.password_hash {
                Authentication { message: "Incorrect password" }.fail()
            } else if let Err(_) = Rsa::private_key_from_pem_passphrase(&encryption.private_key, password.as_bytes()) {
                Authentication { message: "Password hash corrupted" }.fail()
            } else {
                Ok(())
            }
        }
    
        pub fn encryption_exists(path: &path::PathBuf) -> FileStatus {
            let count: u8 = path.join(PUBLIC_KEY).exists() as u8 + 
                path.join(PRIVATE_KEY).exists() as u8 + 
                path.join(PASSWORD_HASH).exists() as u8;
            match count {
                0 => FileStatus::None,
                1 | 2 => FileStatus::Some,
                3 => FileStatus::All,
                _ => panic!("This should never happen")
            }
        }
    
        pub fn delete(path: &path::PathBuf) -> io::Result<()> {
            fs::remove_file(path.join(PUBLIC_KEY))?;
            fs::remove_file(path.join(PRIVATE_KEY))?;
            fs::remove_file(path.join(PASSWORD_HASH))?;
            Ok(())
        }
    }

    fn hash(input: impl AsRef<[u8]>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input);
        hex::encode(hasher.finalize())
    }

    fn read_file(filename: &path::PathBuf) -> io::Result<Vec<u8>> {
        let mut file = fs::File::open(filename)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }
}