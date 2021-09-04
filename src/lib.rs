pub mod db {
    use sqlite;
    use std::result;
    use super::encryption;

    pub struct Database {
        connection: sqlite::Connection
    }

    impl Database {
        pub fn new() -> result::Result<Database, String> {
            let connection = match sqlite::open("passwords.db") {
                Ok(c) => c,
                Err(e) => return Err(format!("Unable to create database connection: {}", e))
            };
            let db = Database { connection };
            match db.init() {
                Ok(()) => (),
                Err(e) => return Err(format!("Unable to initialize database connection: {}", e))
            };
            Ok(db)
        }

        fn init(&self) -> sqlite::Result<()> {
            self.connection.execute("CREATE TABLE IF NOT EXISTS passwords (name TEXT, password TEXT, PRIMARY KEY (name))")
        }

        pub fn add_password(&self, name: &str, password: &str) -> sqlite::Result<()> {
            let enc_password = hex::encode(encryption::encrypt(password));
            self.connection.execute(format!("INSERT INTO passwords VALUES ('{}', '{}')", name, enc_password))
        }
        
        pub fn get_password(&self, name: &str, password: &str) -> sqlite::Result<Vec<String>> {
            let mut statement = self.connection.prepare("SELECT password FROM passwords WHERE name = ?")?;
        
            statement.bind(1, name)?;
        
            let mut fin: Vec<String> = Vec::new();
        
            while let sqlite::State::Row = statement.next()? {
                fin.push(encryption::decrypt(&hex::decode(statement.read::<String>(0)?).unwrap(), &password));
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
                let password = encryption::decrypt(&hex::decode(statement.read::<String>(1)?).unwrap(), &password);
                fin.push(format!("{}: {}", name, password));
            }
        
            Ok(fin)
        }
    }
}

mod encryption {
    use openssl::rsa::{Padding, Rsa};
    use std::fs;
    use std::io::Read;

    pub fn encrypt(text: &str) -> Vec<u8> {
        let pubkey = Rsa::public_key_from_pem_pkcs1(&read_file("pubkey.txt").unwrap()).unwrap();
        let mut encrypted = vec![0; pubkey.size() as usize];
        pubkey.public_encrypt(text.as_bytes(), &mut encrypted, Padding::PKCS1).unwrap();
        encrypted
    }

    pub fn decrypt(text: &Vec<u8>, password: &str) -> String {
        let privkey = Rsa::private_key_from_pem_passphrase(&read_file("privkey.txt").unwrap(), password.as_bytes()).unwrap(); 
        let mut decrypted = vec![0; privkey.size() as usize];
        let len = privkey.private_decrypt(&text, &mut decrypted, Padding::PKCS1).unwrap();
        return String::from_utf8(decrypted[..len].to_vec()).unwrap();
    }

    fn read_file(filename: &str) -> std::io::Result<Vec<u8>> {
        let mut file = fs::File::open(filename)?;
        let mut data = Vec::new();
        file.read_to_end(&mut data)?;
        Ok(data)
    }
}