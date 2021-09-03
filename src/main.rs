use std::io::{self, Write};
use passwords::hash::hash;
use rpassword;
use sqlite;

fn main() {
    print!("Enter password: ");

    match io::stdout().flush() {
        Ok(()) => (),
        Err(e) => { eprintln!("Error flushing stdout: {}", e); return; }
    };

    let password = match rpassword::read_password() {
        Ok(input) => input,
        Err(e) => { eprintln!("Error reading input: {}", e); return; }
    };

    let hashed_password = hash(password);

    if hashed_password.as_str() != "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" {
        println!("Incorrect password");
        return;
    }

    println!("Correct password");

    let connection = match sqlite::open("passwords.db") {
        Ok(file) => file,
        Err(e) => { eprintln!("Error connecting to database: {}", e); return; }
    };

    match connection.execute("CREATE TABLE IF NOT EXISTS passwords (name TEXT, password TEXT, PRIMARY KEY (name))") {
        Ok(()) => (),
        Err(e) => { eprintln!("Error creating table: {}", e); return; }
    };

    print!("Enter option: ");
    match io::stdout().flush() {
        Ok(()) => (),
        Err(e) => { eprintln!("Error flushing stdout: {}", e); return; }
    };

    let option = match read_input() {
        Ok(input) => input,
        Err(e) => { eprintln!("Error reading input: {}", e); return; }
    };

    match option.as_str() {
        "add" => {
            println!("Enter name of password to add:");
            let name = match read_input() {
                Ok(input) => input,
                Err(e) => { eprintln!("Error reading input: {}", e); return; }
            };

            println!("Enter password to add:");
            let password = match read_input() {
                Ok(input) => input,
                Err(e) => { eprintln!("Error reading input: {}", e); return; }
            };
            
            println!("Confirm password to add:");
            let password_confirm = match read_input() {
                Ok(input) => input,
                Err(e) => { eprintln!("Error reading input: {}", e); return; }
            };

            if password != password_confirm {
                println!("Passwords don't match. Aborting.");
                return;
            }

            match add_password(&connection, &name, &password) {
                Ok(()) => { println!("Added password for {}!", name) },
                Err(e) => { eprintln!("Error adding database entry: {}", e); return; }
            };
        },
        "get" => {
            println!("Enter name of password to get:");

            let name = match read_input() {
                Ok(input) => input,
                Err(e) => { eprintln!("Error reading input: {}", e); return; }
            };

            let results = match get_password(&connection, &name) {
                Ok(res) => res,
                Err(e) => { eprintln!("Error getting database entry: {}", e); return; }
            };

            if results.len() == 0 {
                println!("No results found for name {}", name);
                return;
            }

            for result in results {
                println!("password for {}: {}", name, result);
            }
        },
        "all" => { 
            println!("Are you sure you want to get all passwords? They will be printed to the console. y/N: ");
            let confirm = match read_input() {
                Ok(input) => input,
                Err(e) => { eprintln!("Error reading input: {}", e); return; }
            };

            match confirm.as_str() {
                "y" | "Y" => { 
                    let results = match get_all_passwords(&connection) {
                        Ok(res) => res,
                        Err(e) => { eprintln!("Error getting all passwords: {}", e); return; }
                    };

                    if results.len() == 0 {
                        println!("No passwords found");
                        return;
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
            let name = match read_input() {
                Ok(input) => input,
                Err(e) => { eprintln!("Error reading input: {}", e); return; }
            };

            println!("Are you sure you want to remove? y/N: ");
            let confirm = match read_input() {
                Ok(input) => input,
                Err(e) => { eprintln!("Error reading input: {}", e); return; }
            };

            match confirm.as_str() {
                "y" | "Y" => { 
                    match remove_password(&connection, &name) {
                        Ok(()) => { println!("Successfully removed password for {}", name); },
                        Err(e) => { eprintln!("Error removing password: {}", e); return; }
                    };
                },
                _ => { println!("Cancelling removal"); }
            };
        },
        _ => { println!("Invalid option. Supported options: add, get, all, remove"); return; }
    }
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

fn read_input() -> io::Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}
