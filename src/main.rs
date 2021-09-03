use std::io::{self, Write};
use std::result;
use passwords::{hash, db};
use rpassword;

fn main() -> result::Result<(), String> {
    print_and_flush("Enter password: ")?;

    let password = read_password()?;

    let hashed_password = hash::hash(password);

    if hashed_password.as_str() != "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8" {
        return Err(String::from("Incorrect password"));
    }

    println!("Correct password");

    print_and_flush("Enter option: ")?;

    let option = read_input()?;

    let db = db::Database::new()?;

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

            match db.add_password(&name, &password) {
                Ok(()) => println!("Added password for {}!", name),
                Err(e) => return Err(format!("Error adding database entry: {}", e))
            };
        },
        "get" => {
            print_and_flush("Enter name of password to get: ")?;

            let name = read_input()?;

            let results = match db.get_password(&name) {
                Ok(res) => res,
                Err(e) => return Err(format!("Error getting database entry: {}", e))
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
                    let results = match db.get_all_passwords() {
                        Ok(res) => res,
                        Err(e) => return Err(format!("Error getting all passwords: {}", e))
                    };

                    if results.len() == 0 {
                        return Err(format!("No passwords found"));
                    }
        
                    for result in results {
                        println!("{}", result);
                    }
                },
                _ => println!("Cancelling retrieving all passwords")
            };
        },
        "remove" => {
            println!("Enter name of password to remove:");
            let name = read_input()?;

            println!("Are you sure you want to remove? y/N: ");
            let confirm = read_input()?;

            match confirm.as_str() {
                "y" | "Y" => { 
                    match db.remove_password(&name) {
                        Ok(()) => println!("Successfully removed password for {}", name),
                        Err(e) => return Err(format!("Error removing password: {}", e))
                    };
                },
                _ => { println!("Cancelling removal"); }
            };
        },
        _ => return Err(format!("Invalid option. Supported options: add, get, all, remove"))
    };

    Ok(())
}

fn print_and_flush(output: &str) -> result::Result<(), String> {
    print!("{}", output);

    match io::stdout().flush() {
        Ok(()) => Ok(()),
        Err(e) => Err(format!("Error flushing stdout: {}", e))
    }
}

fn read_input() -> result::Result<String, String> {
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(_n) => Ok(input.trim().to_string()),
        Err(e) => Err(format!("Error reading input: {}", e))
    }
}

fn read_password() -> result::Result<String, String> {
    match rpassword::read_password() {
        Ok(result) => Ok(result),
        Err(e) => Err(format!("Error reading password: {}", e))
    }
}
