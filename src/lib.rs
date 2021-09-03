pub mod hash {
    use sha2::{Sha256, Digest};
    
    pub fn hash(input: impl AsRef<[u8]>) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input);
        return hasher
            .finalize()
            .into_iter()
            .map(|x| if x < 16 { format!("0{:x}", x) } else { format!("{:x}", x) })
            .collect();
    }
}

pub mod db {
    use sqlite;
    use std::result;

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
            self.connection.execute(format!("INSERT INTO passwords VALUES ('{}', '{}')", name, password))
        }
        
        pub fn get_password(&self, name: &str) -> sqlite::Result<Vec<String>> {
            let mut statement = self.connection.prepare("SELECT password FROM passwords WHERE name = ?")?;
        
            statement.bind(1, name)?;
        
            let mut fin: Vec<String> = Vec::new();
        
            while let sqlite::State::Row = statement.next()? {
                fin.push(statement.read::<String>(0)?);
            }
        
            Ok(fin)
        }
        
        pub fn remove_password(&self, name: &str) -> sqlite::Result<()> {
            self.connection.execute(format!("DELETE FROM passwords WHERE name = '{}'", name))
        }
        
        pub fn get_all_passwords(&self) -> sqlite::Result<Vec<String>> {
            let mut statement = self.connection.prepare("SELECT name, password FROM passwords ORDER BY name ASC")?;
        
            let mut fin: Vec<String> = Vec::new();
        
            while let sqlite::State::Row = statement.next()? {
                let name = statement.read::<String>(0)?;
                let password = statement.read::<String>(1)?;
                fin.push(format!("{}: {}", name, password));
            }
        
            Ok(fin)
        }
    }
}