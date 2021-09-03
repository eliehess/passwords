use std::io::{self, Write};
use std::result;
use passwords::hash;
use rpassword;
use sqlite;

fn main() -> result::Result<(), String> {
    print_and_flush("Enter password: ")?;

    let password = read_password()?;

    let hashed_password = hash::hash(password);

    if hashed_password.as_str() != "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" {
        return Err(String::from("Incorrect password"));
    }

    println!("Correct password");

    let connection = get_db_connection("passwords.db")?;

    init_db(&connection)?;

    print_and_flush("Enter option: ")?;

    let option = read_input()?;

    match option.as_str() {
        "add" => {
            print_and_flush("Enter name of password to add: ")?;
            let name = read_input()?;

            print_and_flush("Enter password to add: ")?;
            let password = read_password()?;
            
            print_and_flush("Confirm password to add: ")?;
            let password_confirm = read_password()?;

            if password != password_confirm {
                return Err(String::from("Passwords don't match. Aborting."));
            }

            match add_password(&connection, &name, &password) {
                Ok(()) => { println!("Added password for {}!", name) },
                Err(e) => { return Err(format!("Error adding database entry: {}", e)); }
            };
        },
        "get" => {
            println!("Enter name of password to get: ");

            let name = read_input()?;

            let results = match get_password(&connection, &name) {
                Ok(res) => res,
                Err(e) => { return Err(format!("Error getting database entry: {}", e)); }
            };

            if results.len() == 0 {
                return Err(format!("No results found for name {}", name));
            }

            for result in results {
                println!("password for {}: {}", name, result);
            }
        },
        "all" => { 
            print_and_flush("Are you sure you want to get all passwords? They will be printed to the console. y/N: ")?;
            let confirm = read_input()?;
            match confirm.as_str() {
                "y" | "Y" => { 
                    let results = match get_all_passwords(&connection) {
                        Ok(res) => res,
                        Err(e) => { return Err(format!("Error getting all passwords: {}", e)); }
                    };

                    if results.len() == 0 {
                        return Err(format!("No passwords found"));
                    }
        
                    for result in results {
                        println!("{}", result);
                    }
                },
                _ => { println!("Cancelling retrieving all passwords"); }
            };
        },
        "remove" => {
            println!("Enter name of password to remove:");
            let name = read_input()?;

            println!("Are you sure you want to remove? y/N: ");
            let confirm = read_input()?;

            match confirm.as_str() {
                "y" | "Y" => { 
                    match remove_password(&connection, &name) {
                        Ok(()) => { println!("Successfully removed password for {}", name); },
                        Err(e) => { return Err(format!("Error removing password: {}", e)); }
                    };
                },
                _ => { println!("Cancelling removal"); }
            };
        },
        _ => { return Err(format!("Invalid option. Supported options: add, get, all, remove")); }
    };

    Ok(())
}

fn add_password(connection: &sqlite::Connection, name: &str, password: &str) -> sqlite::Result<()> {
    connection.execute(format!("INSERT INTO passwords VALUES ('{}', '{}')", name, password))?;
    Ok(())
}

fn remove_password(connection: &sqlite::Connection, name: &str) -> sqlite::Result<()> {
    connection.execute(format!("DELETE FROM passwords WHERE name = '{}'", name))?;
    Ok(())
}

fn get_password(connection: &sqlite::Connection, name: &str) -> sqlite::Result<Vec<String>> {
    let mut statement = connection.prepare("SELECT password FROM passwords WHERE name = ?")?;

    statement.bind(1, name)?;

    let mut fin: Vec<String> = Vec::new();

    while let sqlite::State::Row = statement.next()? {
        fin.push(statement.read::<String>(0)?);
    }

    Ok(fin)
}

fn get_all_passwords(connection: &sqlite::Connection) -> sqlite::Result<Vec<String>> {
    let mut statement = connection.prepare("SELECT name, password FROM passwords ORDER BY name ASC")?;

    let mut fin: Vec<String> = Vec::new();

    while let sqlite::State::Row = statement.next()? {
        let name = statement.read::<String>(0)?;
        let password = statement.read::<String>(1)?;
        fin.push(format!("{}: {}", name, password));
    }

    Ok(fin)
}

fn read_input() -> result::Result<String, String> {
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_n) => Ok(input.trim().to_string()),
        Err(e) => Err(format!("Error reading input: {}", e))
    }
}

fn print_and_flush(output: &str) -> result::Result<(), String> {
    print!("{}", output);

    match io::stdout().flush() {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("Error flushing stdout: {}", e))
    }
}

fn get_db_connection(location: &str) -> result::Result<sqlite::Connection, String> {
    match sqlite::open(location) {
        Ok(file) => Ok(file),
        Err(e) => Err(format!("Error connecting to database: {}", e))
    }
}

fn init_db(connection: &sqlite::Connection) -> result::Result<(), String> {
    match connection.execute("CREATE TABLE IF NOT EXISTS passwords (name TEXT, password TEXT, PRIMARY KEY (name))") {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("Error initializing database: {}", e))
    }
}

fn read_password() -> result::Result<String, String> {
    match rpassword::read_password() {
        Ok(result) => Ok(result),
        Err(e) => Err(format!("Error reading input: {}", e))
    }
}
