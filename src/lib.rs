pub mod db {
    use std::{path, fs, result, io::{self, Read}};
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

        #[snafu(display("Duplicate entry error: more than one entry for {}", entry))]
        DuplicateEntry {
            entry: String
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

    pub type Result<T> = result::Result<T, DatabaseError>;

    pub enum FileStatus {
        All,
        Some,
        None
    }

    pub struct Database {
        connection: sqlite::Connection,
        encryption: Encryption,
        password: String
    }

    impl Database {
        /// Adds a password to the database
        /// 
        /// ```rust
        /// database.add_password(&name_to_add, &password_to_add)?;
        /// ```
        pub fn add_password(&self, name_to_add: &str, password_to_add: &str) -> Result<()> {
            let enc_password_to_add = hex::encode(self.encryption.encrypt(password_to_add)?);

            let mut statement = self.connection.prepare("INSERT INTO passwords VALUES (?1, ?2)").context(SQLite)?;
            statement.bind(1, name_to_add).context(SQLite)?;
            statement.bind(2, enc_password_to_add.as_str()).context(SQLite)?;

            while let sqlite::State::Row = statement.next().context(SQLite)? {}
            
            Ok(())
        }
        
        /// Retrieves a password from the database. 
        /// Returns None if there was no password with the requested name,
        /// or Some if there was one.
        /// 
        /// ```rust
        /// let result = database.get_password(&name_to_get)?;
        /// 
        /// match result {
        ///     None => /* handle no entry found */,
        ///     Some(entry) => /* handle entry found */
        /// }
        /// ```
        pub fn get_password(&self, name_to_get: &str) -> Result<Option<String>> {
            let mut statement = self.connection.prepare("SELECT password FROM passwords WHERE name = ?").context(SQLite)?;
        
            statement.bind(1, name_to_get).context(SQLite)?;
        
            let mut results: Vec<String> = Vec::new();
        
            while let sqlite::State::Row = statement.next().context(SQLite)? {
                results.push(self.encryption.decrypt(&hex::decode(statement.read::<String>(0).context(SQLite)?).context(Hex)?, &self.password)?);
            }

            match results.len() {
                0 => Ok(None),
                1 => Ok(Some(results.get(0).unwrap().to_string())),
                _ => DuplicateEntry { entry: name_to_get }.fail()
            }
        }
        
        /// Removes a password from the database.
        /// 
        /// ```rust
        /// database.remove_password(&name_to_remove)?;
        /// ```
        pub fn remove_password(&self, name_to_remove: &str) -> sqlite::Result<()> {
            let mut statement = self.connection.prepare("DELETE FROM passwords WHERE name = ?")?;

            statement.bind(1, name_to_remove)?;

            while let sqlite::State::Row = statement.next()? {}

            Ok(())
        }

        /// Retrieves all name-password combinations from the database. 
        /// Returns a list of 2-tuples, where the first entry in each tuple is the name,
        /// and the second is the corresponding password.
        /// 
        /// ```rust
        /// let results = database.get_all_passwords()?;
        /// for (name, passsword) in results {
        ///     // handle names and passwords
        /// }
        /// ```
        pub fn get_all_passwords(&self) -> Result<Vec<(String, String)>> {
            let mut statement = self.connection.prepare("SELECT name, password FROM passwords ORDER BY name ASC").context(SQLite)?;
        
            let mut fin: Vec<(String, String)> = Vec::new();
        
            while let sqlite::State::Row = statement.next().context(SQLite)? {
                let name = statement.read::<String>(0).context(SQLite)?;
                let password = self.encryption.decrypt(&hex::decode(statement.read::<String>(1).context(SQLite)?).context(Hex)?, &self.password)?;
                fin.push((name, password));
            }
        
            Ok(fin)
        }

        /// Retrieves all names from the database, without their corresponding passwords.
        /// 
        /// ```rust
        /// let results = database.get_all_names()?;
        /// for name in results {
        ///     // handle each name
        /// }
        /// ```
        pub fn get_all_names(&self) -> Result<Vec<String>> {
            let mut statement = self.connection.prepare("SELECT name FROM passwords ORDER BY name ASC").context(SQLite)?;
        
            let mut fin: Vec<String> = Vec::new();
        
            while let sqlite::State::Row = statement.next().context(SQLite)? {
                fin.push(statement.read::<String>(0).context(SQLite)?);
            }
        
            Ok(fin)
        }

        /// Creates a new database instance. Fails with [`DatabaseError::File`](db::DatabaseError::File) if any files already exist,
        /// so you should probably call files_exist() first.
        /// 
        /// ```rust
        /// match db::Database::files_exist(&path) {
        ///     db::FileStatus::None => { db::Database::create_new(&path, &password)?; },
        ///     db::FileStatus::Some => /* handle some files have been deleted */,
        ///     db::FileStatus::All => /* handle database already exists */
        /// };
        /// ```
        pub fn create_new(path: &path::PathBuf, password: &str) -> Result<Database> {
            match Database::files_exist(&path) {
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
    
        /// Connects to an existing database instance. Fails with [`DatabaseError::File`](db::DatabaseError::File) if not all files exist,
        /// so you should probably call files_exist() first.
        /// 
        /// ```rust
        /// match db::Database::files_exist(&path) {
        ///     db::FileStatus::None => /* handle no files exist */,
        ///     db::FileStatus::Some => /* handle some files have been deleted */,
        ///     db::FileStatus::All => { 
        ///         let database = db::Database::use_existing(&path, &password)?;
        ///         // interact with database connection
        ///     }
        /// };
        /// ```
        pub fn use_existing(path: &path::PathBuf, password: &str) -> Result<Database> {
            match Database::files_exist(&path) {
                FileStatus::All => (),
                FileStatus::Some => { return File { message: "Database corrupted" }.fail(); },
                FileStatus::None => { return File { message: "No database exists" }.fail(); }
            }
    
            let connection = sqlite::open(path.join(DB_LOCATION)).context(SQLite)?;
    
            let encryption = Encryption::use_existing(path, password)?;
    
            Ok(Database { connection, encryption, password: String::from(password) })
        }
    
        /// Checks how many of the necessary configuration files exist and returns the appropriate file status.
        /// 
        /// ```rust
        /// match db::Database::files_exist(&data_dir) {
        ///     db::FileStatus::All => /* handle all files exist */,
        ///     db::FileStatus::Some => /* handle some files exist */,
        ///     db::FileStatus::None => /* handle no files exist */
        /// };
        /// ```
        pub fn files_exist(path: &path::PathBuf) -> FileStatus {
            match Encryption::encryption_exists(path) {
                FileStatus::All => if path.join(DB_LOCATION).exists() { FileStatus::All } else { FileStatus::Some },
                FileStatus::Some => FileStatus::Some,
                FileStatus::None => if path.join(DB_LOCATION).exists() { FileStatus::Some } else { FileStatus::None} 
            }
        }
    
        /// Deletes all database configuration files. 
        /// 
        /// WARNING: DOES NOT ASK FOR CONFIRMATION. CALLING THIS FUNCTION WILL IRREVERSIBLY DELETE CONFIGURATION
        /// 
        /// ```rust
        /// db::Database::delete(&path)?;
        /// ```
        pub fn delete(path: &path::PathBuf) -> io::Result<()> {
            Encryption::delete(path)?;
            fs::remove_file(path.join(DB_LOCATION))
        }
    }

    struct Encryption {
        public_key: Vec<u8>,
        private_key: Vec<u8>,
        password_hash: String
    }

    impl Encryption {
        pub fn encrypt(&self, text: &str) -> Result<Vec<u8>> {
            let pubkey = Rsa::public_key_from_pem_pkcs1(&self.public_key).context(OpenSSL)?;
            let mut encrypted = vec![0; pubkey.size() as usize];
            pubkey.public_encrypt(text.as_bytes(), &mut encrypted, Padding::PKCS1).context(OpenSSL)?;

            Ok(encrypted)
        }
    
        pub fn decrypt(&self, text: &Vec<u8>, password: &str) -> Result<String> {
            let privkey = Rsa::private_key_from_pem_passphrase(&self.private_key, password.as_bytes()).context(OpenSSL)?; 
            let mut decrypted = vec![0; privkey.size() as usize];
            let len = privkey.private_decrypt(&text, &mut decrypted, Padding::PKCS1).context(OpenSSL)?;

            Ok(String::from_utf8(decrypted[..len].to_vec()).context(Utf8)?)
        }
    
        pub fn check_password(&self, password: &str) -> Result<()> {
            if hash(password) != self.password_hash {
                Authentication { message: "Incorrect password" }.fail()
            } else if let Err(_) = Rsa::private_key_from_pem_passphrase(&self.private_key, password.as_bytes()) {
                Authentication { message: "Password hash corrupted" }.fail()
            } else {
                Ok(())
            }
        }
    
        pub fn create_new(path: &path::PathBuf, password: &str) -> Result<Encryption> {
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

        pub fn use_existing(path: &path::PathBuf, password: &str) -> Result<Encryption> {
            match Encryption::encryption_exists(&path) {
                FileStatus::All => (),
                FileStatus::Some => { return  File { message: "Keys corrupted" }.fail(); },
                FileStatus::None => { return  File { message: "Keys don't exist" }.fail(); }
            }
    
            let public_key = read_file(&path.join(PUBLIC_KEY)).context(Io)?;
            let private_key = read_file(&path.join(PRIVATE_KEY)).context(Io)?;
            let password_hash = String::from_utf8(read_file(&path.join(PASSWORD_HASH)).context(Io)?).context(Utf8)?;
    
            let encryption = Encryption { public_key, private_key, password_hash };

            encryption.check_password(password)?;
    
            Ok(encryption)
        }
    
        pub fn encryption_exists(path: &path::PathBuf) -> FileStatus {
            let count: u8 = path.join(PUBLIC_KEY).exists() as u8 + 
                path.join(PRIVATE_KEY).exists() as u8 + 
                path.join(PASSWORD_HASH).exists() as u8;
            match count {
                0 => FileStatus::None,
                1 | 2 => FileStatus::Some,
                3 => FileStatus::All,
                _ => panic!("Somehow added three booleans and got a number not between 0 and 3")
            }
        }
    
        pub fn delete(path: &path::PathBuf) -> io::Result<()> {
            fs::remove_file(path.join(PUBLIC_KEY))?;
            fs::remove_file(path.join(PRIVATE_KEY))?;
            fs::remove_file(path.join(PASSWORD_HASH))
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