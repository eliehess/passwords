use std::{result::Result, env, error::Error};
use passwords::{db, encryption, utils::*};

fn main() -> Result<(), Box<dyn Error>> {
    let data_dir = env::current_exe()?.parent().unwrap().join(".data");

    let encryption = match encryption::Encryption::use_existing(&data_dir) {
        Ok(enc) => enc,
        Err(_e) => {
            println!("Welcome! It looks like you haven't set up this application yet.");

            let password = loop {
                print_and_flush("Please choose a master password: ");
                let init_password = read_password()?;
    
                print_and_flush("Please confirm your master password: ");
                let confirm_init_password = read_password()?;
    
                if init_password == confirm_init_password {
                    break init_password;
                }

                println!("Your passwords don't match. Please try again.");
            };

            match encryption::Encryption::make_new(&data_dir, &password) {
                Ok(enc) => {
                    println!("Awesome! You're ready to go.");
                    enc
                },
                Err(e) => {
                    println!("Something went wrong when initializing application: {}", e);
                    return Ok(())
                }
            }
        }
    };

    print_and_flush("Enter master password: ");
    let password = read_password()?;

    encryption.check_password(&password)?;

    let db = db::Database::new(&data_dir, encryption)?;

    loop {
        print_and_flush("Enter option (add, get, all, remove): ");
        let option = read_input()?;

        match option.as_str() {
            "add" => {
                print_and_flush("Enter name of password to add: ");
                let name_to_add = read_input()?;

                let password_to_add = loop {
                    print_and_flush(format!("Enter password to add for {}: ", name_to_add));
                    let password_to_add = read_password()?;
                    
                    print_and_flush(format!("Confirm password to add for {}: ", name_to_add));
                    let password_confirm = read_password()?;

                    if password_to_add == password_confirm {
                        break password_to_add;
                    }

                    println!("The passwords don't match. Please try again.");
                };

                match db.add_password(&name_to_add, &password_to_add) {
                    Ok(()) => println!("Added password for {}!", name_to_add),
                    Err(e) => println!("Unable to add password for {}: {}", name_to_add, e)
                };

                break;
            },
            "get" => {
                print_and_flush("Enter name of password to get: ");

                let name_to_get = read_input()?;

                let results = match db.get_password(&name_to_get, &password) {
                    Ok(res) => res,
                    Err(e) => {
                        println!("Unable to get password for {}: {}", name_to_get, e);
                        break;
                    }
                };

                match results.len() {
                    0 => println!("No passwords found for {}", name_to_get),
                    1 => println!("{}", results.get(0).unwrap()),
                    _ => println!("Somehow there's more than one entry for {}", name_to_get)
                }

                break;
            },
            "all" => { 
                print_and_flush("Are you sure you want to get all passwords? They will be printed to the console. y/N: ");
                let confirm = read_input()?;
                match confirm.as_str() {
                    "y" | "Y" => { 
                        let results = match db.get_all_passwords(&password) {
                            Ok(res) => res,
                            Err(e) => {
                                println!("Unable to get all passwords: {}", e);
                                break;
                            }
                        };

                        if results.len() == 0 {
                            println!("No passwords found");
                        } else {
                            for result in results {
                                println!("{}", result);
                            }
                        }
                    },
                    _ => println!("Cancelling retrieving all passwords")
                };
                
                break;
            },
            "remove" => {
                println!("Enter name of password to remove:");
                let name_to_remove = read_input()?;

                println!("Are you sure you want to remove password for {}? y/N: ", name_to_remove);
                let confirm = read_input()?;

                match confirm.as_str() {
                    "y" | "Y" => {
                        match db.remove_password(&name_to_remove) {
                            Ok(()) => println!("Successfully removed password for {}", name_to_remove),
                            Err(e) => {
                                println!("Unable to remove password for {}: {}", name_to_remove, e);
                                return Ok(());
                            }
                        };
                    },
                    _ => println!("Cancelling removal")
                };

                break;
            },
            _ => println!("Invalid option. Supported options: add, get, all, remove")
        };
    }

    Ok(())
}
