use std::{result, env};
use passwords::{db, encryption, utils::*};

fn main() -> result::Result<(), String> {
    let data_dir = env::current_exe().unwrap().parent().unwrap().join(".data");

    let encryption = match encryption::Encryption::use_existing(&data_dir) {
        Ok(x) => x,
        Err(_e) => {
            println!("Welcome! It looks like you haven't set up this application yet.");

            print_and_flush("Before continuing, please choose a password: ");
            let init_password = read_password()?;

            print_and_flush("Please confirm your password: ");
            let confirm_init_password = read_password()?;

            if init_password == confirm_init_password {
                println!("Awesome! You're ready to go.");
                encryption::Encryption::make_new(&data_dir, &init_password)
            } else {
                return Err(String::from("Whoops! Your passwords don't match"));
            }
        }
    };

    print_and_flush("Enter password: ");

    let password = read_password()?;

    if !encryption.is_correct_password(&password) {
        return Err(String::from("Incorrect password"));
    }

    print_and_flush("Enter option (add, get, all, remove): ");

    let option = read_input()?;

    let db = db::Database::new(&data_dir, encryption)?;

    match option.as_str() {
        "add" => {
            print_and_flush("Enter name of password to add: ");
            let name_to_add = read_input()?;

            print_and_flush("Enter password to add: ");
            let password_to_add = read_password()?;
            
            print_and_flush("Confirm password to add: ");
            let password_confirm = read_password()?;

            if password_to_add != password_confirm {
                return Err(String::from("Passwords don't match"));
            }

            match db.add_password(&name_to_add, &password_to_add) {
                Ok(()) => println!("Added password for {}!", name_to_add),
                Err(e) => return Err(format!("Error adding database entry: {}", e))
            };
        },
        "get" => {
            print_and_flush("Enter name of password to get: ");

            let name_to_get = read_input()?;

            let results = match db.get_password(&name_to_get, &password) {
                Ok(res) => res,
                Err(e) => return Err(format!("Error getting database entry: {}", e))
            };

            if results.len() == 0 {
                return Err(format!("No results found for name {}", name_to_get));
            }

            for result in results {
                println!("password for {}: {}", name_to_get, result);
            }
        },
        "all" => { 
            print_and_flush("Are you sure you want to get all passwords? They will be printed to the console. y/N: ");
            let confirm = read_input()?;
            match confirm.as_str() {
                "y" | "Y" => { 
                    let results = match db.get_all_passwords(&password) {
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
            let name_to_remove = read_input()?;

            println!("Are you sure you want to remove? y/N: ");
            let confirm = read_input()?;

            match confirm.as_str() {
                "y" | "Y" => {
                    match db.remove_password(&name_to_remove) {
                        Ok(()) => println!("Successfully removed password for {}", name_to_remove),
                        Err(e) => return Err(format!("Error removing password: {}", e))
                    };
                },
                _ => println!("Cancelling removal")
            };
        },
        _ => return Err(format!("Invalid option. Supported options: add, get, all, remove"))
    };

    Ok(())
}
