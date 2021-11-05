pub mod db {
    use std::error::Error;
    use std::{fmt, path, fs, io};
    use sqlite;

    static DB_LOCATION: &str = "passwords.db";

    pub struct Database {
        connection: sqlite::Connection,
        encryption: encryption::Encryption
    }

    impl Database {
        pub fn add_password(&self, name: &str, password: &str) -> Result<(), Box<dyn Error>> {
            let enc_password = hex::encode(self.encryption.encrypt(password)?);

            let mut statement = self.connection.prepare("INSERT INTO passwords VALUES (?1, ?2)")?;
            statement.bind(1, name)?;
            statement.bind(2, enc_password.as_str())?;

            while let sqlite::State::Row = statement.next()? {}
            
            Ok(())
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
            let mut statement = self.connection.prepare("DELETE FROM passwords WHERE name = ?")?;
            statement.bind(1, name)?;
            while let sqlite::State::Row = statement.next()? {}
            Ok(())
        }
        
        pub fn get_all_passwords(&self, password: &str) -> Result<Vec<(String, String)>, Box<dyn Error>> {
            let mut statement = self.connection.prepare("SELECT name, password FROM passwords ORDER BY name ASC")?;
        
            let mut fin: Vec<(String, String)> = Vec::new();
        
            while let sqlite::State::Row = statement.next()? {
                let name = statement.read::<String>(0)?;
                let password = self.encryption.decrypt(&hex::decode(statement.read::<String>(1)?)?, &password)?;
                fin.push((name, password));
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

    pub fn create_new(path: &path::PathBuf, password: &str) -> Result<Database, Box<dyn Error>> {
        match db_exists(&path) {
            FileStatus::All => { return Err(Box::new(FileError::new("Database already exists"))) },
            FileStatus::Some => { return Err(Box::new(FileError::new("Database corrupted"))) },
            FileStatus::None => ()
        }

        let connection = sqlite::open(path.join(DB_LOCATION))?;

        let encryption = encryption::create_new(path, password)?;

        let db = Database { connection, encryption };

        db.connection.execute("CREATE TABLE IF NOT EXISTS passwords (name TEXT, password TEXT, PRIMARY KEY (name))")?;

        Ok(db)
    }

    pub fn use_existing(path: &path::PathBuf, password: &str) -> Result<Database, Box<dyn Error>> {
        match db_exists(&path) {
            FileStatus::All => (),
            FileStatus::Some => { return Err(Box::new(FileError::new("Database corrupted"))) },
            FileStatus::None => { return Err(Box::new(FileError::new("No database exists"))) }
        }

        let connection = sqlite::open(path.join(DB_LOCATION))?;

        let encryption = encryption::use_existing(path, password)?;

        Ok(Database { connection, encryption })
    }

    pub fn db_exists(path: &path::PathBuf) -> FileStatus {
        match encryption::encryption_exists(path) {
            FileStatus::All => if path.join(DB_LOCATION).exists() { FileStatus::All } else { FileStatus::Some },
            FileStatus::Some => FileStatus::Some,
            FileStatus::None => if path.join(DB_LOCATION).exists() { FileStatus::Some } else { FileStatus::None} 
        }
    }

    pub fn delete(path: &path::PathBuf) -> io::Result<()> {
        encryption::delete(path)?;
        fs::remove_file(path.join(DB_LOCATION))
    }

    #[derive(Debug)]
    pub struct FileError {
        details: String
    }

    impl FileError {
        pub fn new(msg: &str) -> FileError {
            FileError { details: msg.to_string() }
        }
    }

    impl fmt::Display for FileError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.details)
        }
    }

    impl Error for FileError {
        fn description(&self) -> &str {
            &self.details
        }
    }

    #[derive(Debug)]
    pub struct AuthenticationError {
        details: String
    }

    impl AuthenticationError {
        pub fn new(msg: &str) -> AuthenticationError {
            AuthenticationError { details: msg.to_string() }
        }
    }

    impl fmt::Display for AuthenticationError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "{}", self.details)
        }
    }

    impl Error for AuthenticationError {
        fn description(&self) -> &str {
            &self.details
        }
    }

    pub enum FileStatus {
        All,
        Some,
        None
    }

    mod encryption {
        use std::{fs, path, result, io::{self, Read}, error::Error};
        use super::{FileError, AuthenticationError, FileStatus};
        use openssl::{symm::Cipher, rsa::{Padding, Rsa}};
        use sha2::{Sha256, Digest};
        
        static PUBLIC_KEY: &str = "public.key";
        static PRIVATE_KEY: &str = "private.key";
        static PASSWORD_HASH: &str = "password.hash";

        pub struct Encryption {
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
        
            pub fn decrypt(&self, text: &Vec<u8>, password: &str) -> Result<String, Box<dyn Error>> {
                let privkey = Rsa::private_key_from_pem_passphrase(&self.private_key, password.as_bytes())?; 
                let mut decrypted = vec![0; privkey.size() as usize];
                let len = privkey.private_decrypt(&text, &mut decrypted, Padding::PKCS1)?;
                Ok(String::from_utf8(decrypted[..len].to_vec())?)
            }
        }

        pub fn use_existing(path: &path::PathBuf, password: &str) -> Result<Encryption, Box<dyn Error>> {
            match encryption_exists(&path) {
                FileStatus::All => (),
                FileStatus::Some => { return Err(Box::new(FileError::new("Keys corrupted"))); },
                FileStatus::None => { return Err(Box::new(FileError::new("Keys don't exist"))); }
            }

            let public_key = read_file(&path.join(PUBLIC_KEY))?;
            let private_key = read_file(&path.join(PRIVATE_KEY))?;
            let password_hash = String::from_utf8(read_file(&path.join(PASSWORD_HASH))?)?;

            let encryption = Encryption { public_key, private_key, password_hash };

            check_password(&encryption, password)?;

            Ok(encryption)
        }

        pub fn create_new(path: &path::PathBuf, password: &str) -> Result<Encryption, Box<dyn Error>> {
            match encryption_exists(&path) {
                FileStatus::All => { return Err(Box::new(FileError::new("Keys already exist"))); },
                FileStatus::Some => { return Err(Box::new(FileError::new("Keys corrupted"))); },
                FileStatus::None => ()
            }

            let keypair = Rsa::generate(2048)?;
            let public_key = keypair.public_key_to_pem_pkcs1()?;
            let private_key = keypair.private_key_to_pem_passphrase(Cipher::aes_256_cbc(), password.as_bytes())?;
            let password_hash = hash(&password);
            
            if !path.is_dir() {
                fs::create_dir_all(&path)?;
            }

            fs::write(path.join(PUBLIC_KEY), &public_key)?;
            fs::write(path.join(PRIVATE_KEY), &private_key)?;
            fs::write(path.join(PASSWORD_HASH), &password_hash)?;
            Ok(Encryption { public_key, private_key, password_hash })
        }

        pub fn check_password(encryption: &Encryption, password: &str) -> result::Result<(), AuthenticationError> {
            if hash(password) == encryption.password_hash {
                match Rsa::private_key_from_pem_passphrase(&encryption.private_key, password.as_bytes()) {
                    Ok(_) => Ok(()),
                    Err(_) => Err(AuthenticationError::new("Password hash corrupted"))
                }
            } else {
                Err(AuthenticationError::new("Incorrect password"))
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
}