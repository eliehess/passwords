use std::{result::Result, env, path, error::Error};
use passwords::{db, encryption, utils::*};

fn main() -> Result<(), Box<dyn Error>> {
    let data_dir = env::current_exe()?.parent().unwrap().join(".data");

    let encryption = match encryption::Encryption::use_existing(&data_dir) {
        Ok(enc) => enc,
        Err(_e) => handle_encryption_setup(&data_dir)?
    };

    print_and_flush("Enter master password: ")?;
    let password = read_password()?;

    encryption.check_password(&password)?;

    let database = db::Database::new(&data_dir, encryption)?;

    handle_options(&database, &password)
}

fn handle_encryption_setup(path: &path::PathBuf) -> Result<encryption::Encryption, Box<dyn Error>> {
    println!("Welcome! It looks like you haven't set up this application yet.");

    let password = loop {
        print_and_flush("Please choose a master password: ")?;
        let init_password = read_password()?;

        print_and_flush("Please confirm your master password: ")?;
        let confirm_init_password = read_password()?;

        if init_password == confirm_init_password {
            break init_password;
        }

        println!("Your passwords don't match. Please try again.");
    };

    let enc = encryption::Encryption::make_new(&path, &password)?;
    println!("Awesome! You're ready to go.");
    
    Ok(enc)
}

fn handle_options(database: &db::Database, password: &str) -> Result<(), Box<dyn Error>> {
    print_and_flush("Enter option (add, get, all, remove): ")?;
    let option = read_input()?;

    match option.as_str() {
        "add" => handle_add(&database),
        "get" => handle_get(&database, &password),
        "all" => handle_all(&database, &password),
        "remove" => handle_remove(&database),
        _ => {
            println!("Invalid option");
            handle_options(database, password)
        }
    }
}

fn handle_add(database: &db::Database) -> Result<(), Box<dyn Error>> {
    print_and_flush("Enter name of password to add: ")?;
    let name_to_add = read_input()?;

    let password_to_add = loop {
        print_and_flush(format!("Enter password to add for {}: ", name_to_add))?;
        let password_to_add = read_password()?;
        
        print_and_flush(format!("Confirm password to add for {}: ", name_to_add))?;
        let password_confirm = read_password()?;

        if password_to_add == password_confirm {
            break password_to_add;
        }

        println!("The passwords don't match. Please try again.");
    };

    database.add_password(&name_to_add, &password_to_add)?;
    println!("Added password for {}!", name_to_add);

    Ok(())
}

fn handle_get(database: &db::Database, password: &str) -> Result<(), Box<dyn Error>> {
    print_and_flush("Enter name of password to get: ")?;

    let name_to_get = read_input()?;

    let results = database.get_password(&name_to_get, &password)?;

    match results.len() {
        0 => println!("No passwords found for {}", name_to_get),
        1 => println!("{}", results.get(0).unwrap()),
        _ => println!("Somehow there's more than one entry for {}", name_to_get)
    };

    Ok(())
}

fn handle_all(database: &db::Database, password: &str) -> Result<(), Box<dyn Error>> {
    print_and_flush("Are you sure you want to get all passwords? They will be printed to the console. y/N: ")?;
    let confirm = read_input()?;

    match confirm.as_str() {
        "y" | "Y" => { 
            let results = database.get_all_passwords(&password)?;

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

    Ok(())
}

fn handle_remove(database: &db::Database) -> Result<(), Box<dyn Error>> {
    println!("Enter name of password to remove:");
    let name_to_remove = read_input()?;

    println!("Are you sure you want to remove password for {}? y/N: ", name_to_remove);
    let confirm = read_input()?;

    match confirm.as_str() {
        "y" | "Y" => {
            database.remove_password(&name_to_remove)?;
            println!("Successfully removed password for {}", name_to_remove);
        },
        _ => println!("Removal cancelled - no data was affected")
    };

    Ok(())
}
