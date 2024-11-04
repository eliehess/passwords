pub mod db {
    use openssl::{
        rsa::{Padding, Rsa},
        symm::Cipher,
    };
    use sha2::{Digest, Sha256};
    use snafu::{ResultExt, Snafu};
    use sqlite;
    use std::{fs, io, path, result};

    static DB_LOCATION: &str = "passwords.db";
    static PUBLIC_KEY: &str = "public.key";
    static PRIVATE_KEY: &str = "private.key";
    static PASSWORD_HASH: &str = "password.hash";

    #[derive(Debug, Snafu)]
    pub enum DatabaseError {
        #[snafu(display("Authentication error: {message}"))]
        Authentication { message: String },

        #[snafu(display("Application file error: {message}"))]
        ApplicationFile { message: String },

        #[snafu(display("Duplicate entry error: more than one entry for {entry}"))]
        DuplicateEntry { entry: String },

        #[snafu(display("{}", source))]
        Io { source: io::Error },

        #[snafu(display("{}", source))]
        OpenSSL { source: openssl::error::ErrorStack },

        #[snafu(display("{}", source))]
        Utf8 { source: std::string::FromUtf8Error },

        #[snafu(display("{}", source))]
        SQLite { source: sqlite::Error },

        #[snafu(display("{}", source))]
        Hex { source: hex::FromHexError },
    }

    pub type Result<T> = result::Result<T, DatabaseError>;

    pub enum FileStatus {
        All,
        Some,
        None,
    }

    pub struct Database {
        connection: sqlite::Connection,
        encryption: Encryption,
        password: String,
    }

    impl Database {
        /// Adds a password to the database
        ///
        /// ```rust
        /// database.add_password(&name_to_add, &password_to_add)?;
        /// ```
        pub fn add_password(&self, name_to_add: &str, password_to_add: &str) -> Result<()> {
            let enc_password_to_add = hex::encode(self.encryption.encrypt(password_to_add)?);

            let mut statement = self
                .connection
                .prepare("INSERT INTO passwords VALUES (:name, :password)")
                .context(SQLiteSnafu)?;
            statement
                .bind((":name", name_to_add))
                .context(SQLiteSnafu)?;
            statement
                .bind((":password", enc_password_to_add.as_str()))
                .context(SQLiteSnafu)?;

            while let sqlite::State::Row = statement.next().context(SQLiteSnafu)? {}

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
            let mut statement = self
                .connection
                .prepare("SELECT password FROM passwords WHERE name = :name")
                .context(SQLiteSnafu)?;

            statement
                .bind((":name", name_to_get))
                .context(SQLiteSnafu)?;

            let mut results: Vec<String> = Vec::new();

            while let sqlite::State::Row = statement.next().context(SQLiteSnafu)? {
                let encrypted_password =
                    hex::decode(statement.read::<String, usize>(0).context(SQLiteSnafu)?)
                        .context(HexSnafu)?;
                results.push(
                    self.encryption
                        .decrypt(&encrypted_password, &self.password)?,
                );
            }

            match results.len() {
                0 => Ok(None),
                1 => Ok(Some(results[0].clone())),
                _ => DuplicateEntrySnafu { entry: name_to_get }.fail(),
            }
        }

        /// Removes a password from the database.
        ///
        /// ```rust
        /// database.remove_password(&name_to_remove)?;
        /// ```
        pub fn remove_password(&self, name_to_remove: &str) -> sqlite::Result<()> {
            let mut statement = self
                .connection
                .prepare("DELETE FROM passwords WHERE name = :name")?;

            statement.bind((":name", name_to_remove))?;

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
            let mut statement = self
                .connection
                .prepare("SELECT name, password FROM passwords ORDER BY name ASC")
                .context(SQLiteSnafu)?;

            let mut fin: Vec<(String, String)> = Vec::new();

            while let sqlite::State::Row = statement.next().context(SQLiteSnafu)? {
                let name = statement.read::<String, usize>(0).context(SQLiteSnafu)?;
                let encrypted_password =
                    &hex::decode(statement.read::<String, usize>(1).context(SQLiteSnafu)?)
                        .context(HexSnafu)?;
                let password = self
                    .encryption
                    .decrypt(encrypted_password, &self.password)?;
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
            let mut statement = self
                .connection
                .prepare("SELECT name FROM passwords ORDER BY name ASC")
                .context(SQLiteSnafu)?;

            let mut fin: Vec<String> = Vec::new();

            while let sqlite::State::Row = statement.next().context(SQLiteSnafu)? {
                fin.push(statement.read::<String, usize>(0).context(SQLiteSnafu)?);
            }

            Ok(fin)
        }

        /// Creates a new database instance. Fails with [`DatabaseError::ApplicationFile`](db::DatabaseError::ApplicationFile)
        /// if any files already exist, so you should probably call `files_exist()` first.
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
                FileStatus::All => {
                    return ApplicationFileSnafu {
                        message: "Database already exists",
                    }
                    .fail();
                }
                FileStatus::Some => {
                    return ApplicationFileSnafu {
                        message: "Database corrupted",
                    }
                    .fail();
                }
                FileStatus::None => (),
            }

            let encryption = Encryption::create_new(path, password)?;

            let connection = sqlite::open(path.join(DB_LOCATION)).context(SQLiteSnafu)?;

            let db = Database {
                connection,
                encryption,
                password: String::from(password),
            };

            db.connection.execute("CREATE TABLE IF NOT EXISTS passwords (name TEXT, password TEXT, PRIMARY KEY (name))").context(SQLiteSnafu)?;

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
                FileStatus::Some => {
                    return ApplicationFileSnafu {
                        message: "Database corrupted",
                    }
                    .fail();
                }
                FileStatus::None => {
                    return ApplicationFileSnafu {
                        message: "No database exists",
                    }
                    .fail();
                }
            }

            let connection = sqlite::open(path.join(DB_LOCATION)).context(SQLiteSnafu)?;

            let encryption = Encryption::use_existing(path, password)?;

            Ok(Database {
                connection,
                encryption,
                password: String::from(password),
            })
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
                FileStatus::All => {
                    if let Ok(true) = path.join(DB_LOCATION).try_exists() {
                        FileStatus::All
                    } else {
                        FileStatus::Some
                    }
                }
                FileStatus::Some => FileStatus::Some,
                FileStatus::None => {
                    if let Ok(true) = path.join(DB_LOCATION).try_exists() {
                        FileStatus::Some
                    } else {
                        FileStatus::None
                    }
                }
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
        password_hash: String,
    }

    impl Encryption {
        pub fn encrypt(&self, text: &str) -> Result<Vec<u8>> {
            let pubkey = Rsa::public_key_from_pem_pkcs1(&self.public_key).context(OpenSSLSnafu)?;
            let mut encrypted = vec![0; pubkey.size() as usize];
            pubkey
                .public_encrypt(text.as_bytes(), &mut encrypted, Padding::PKCS1)
                .context(OpenSSLSnafu)?;

            Ok(encrypted)
        }

        pub fn decrypt(&self, text: &Vec<u8>, password: &str) -> Result<String> {
            let privkey =
                Rsa::private_key_from_pem_passphrase(&self.private_key, password.as_bytes())
                    .context(OpenSSLSnafu)?;
            let mut decrypted = vec![0; privkey.size() as usize];
            let len = privkey
                .private_decrypt(&text, &mut decrypted, Padding::PKCS1)
                .context(OpenSSLSnafu)?;

            Ok(String::from_utf8(decrypted[..len].to_vec()).context(Utf8Snafu)?)
        }

        pub fn check_password(&self, password: &str) -> Result<()> {
            if hash(password) != self.password_hash {
                AuthenticationSnafu {
                    message: "Incorrect password",
                }
                .fail()
            } else if let Err(_) =
                Rsa::private_key_from_pem_passphrase(&self.private_key, password.as_bytes())
            {
                AuthenticationSnafu {
                    message: "Password hash corrupted",
                }
                .fail()
            } else {
                Ok(())
            }
        }

        pub fn create_new(path: &path::PathBuf, password: &str) -> Result<Encryption> {
            match Encryption::encryption_exists(&path) {
                FileStatus::All => {
                    return ApplicationFileSnafu {
                        message: "Keys already exist",
                    }
                    .fail();
                }
                FileStatus::Some => {
                    return ApplicationFileSnafu {
                        message: "Keys corrupted",
                    }
                    .fail();
                }
                FileStatus::None => (),
            }

            let keypair = Rsa::generate(2048).context(OpenSSLSnafu)?;
            let public_key = keypair.public_key_to_pem_pkcs1().context(OpenSSLSnafu)?;
            let private_key = keypair
                .private_key_to_pem_passphrase(Cipher::aes_256_cbc(), password.as_bytes())
                .context(OpenSSLSnafu)?;
            let password_hash = hash(&password);

            if !path.is_dir() {
                fs::create_dir_all(&path).context(IoSnafu)?;
            }

            fs::write(path.join(PUBLIC_KEY), &public_key).context(IoSnafu)?;
            fs::write(path.join(PRIVATE_KEY), &private_key).context(IoSnafu)?;
            fs::write(path.join(PASSWORD_HASH), &password_hash).context(IoSnafu)?;

            Ok(Encryption {
                public_key,
                private_key,
                password_hash,
            })
        }

        pub fn use_existing(path: &path::PathBuf, password: &str) -> Result<Encryption> {
            match Encryption::encryption_exists(&path) {
                FileStatus::All => (),
                FileStatus::Some => {
                    return ApplicationFileSnafu {
                        message: "Keys corrupted",
                    }
                    .fail();
                }
                FileStatus::None => {
                    return ApplicationFileSnafu {
                        message: "Keys don't exist",
                    }
                    .fail();
                }
            }

            let public_key = fs::read(&path.join(PUBLIC_KEY)).context(IoSnafu)?;
            let private_key = fs::read(&path.join(PRIVATE_KEY)).context(IoSnafu)?;
            let password_hash =
                String::from_utf8(fs::read(&path.join(PASSWORD_HASH)).context(IoSnafu)?)
                    .context(Utf8Snafu)?;

            let encryption = Encryption {
                public_key,
                private_key,
                password_hash,
            };

            encryption.check_password(password)?;

            Ok(encryption)
        }

        pub fn encryption_exists(path: &path::PathBuf) -> FileStatus {
            let mut num_files: u8 = 0;
            for filename in [PUBLIC_KEY, PRIVATE_KEY, PASSWORD_HASH] {
                if let Ok(true) = path.join(filename).try_exists() {
                    num_files += 1
                }
            }
            match num_files {
                0 => FileStatus::None,
                1 | 2 => FileStatus::Some,
                3 => FileStatus::All,
                _ => panic!("Somehow there are more than three configuration files"),
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
}
