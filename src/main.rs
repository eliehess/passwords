use std::{env, path, result::Result, error::Error};
use passwords::{db, encryption, utils::{print_and_flush, read_password, read_input, set_clipboard}};

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage_and_exit();
    }

    match args[1].as_str() {
        "add" => handle_add(&args)?,
        "get" => handle_get(&args)?,
        "all" => handle_all(&args)?,
        "remove" => handle_remove(&args)?,
        "setup" => handle_setup(&args)?,
        "help" => handle_help(),
        _ =>  print_usage_and_exit()
    }; 

    Ok(())
}

fn handle_help() {
    println!("passwords is a command-line password manager. It supports the following options:");
    println!("add <name>");
    println!("\tAdds a new entry for the given name. Fails if an entry for that name already exists (it'll tell you when this happens).");
    println!("get <name>");
    println!("\tRetrieves an entry for the given name and copies it to your clipboard. Fails if no entry for that name exists (it'll tell you when this happens, too).");
    println!("remove <name>");
    println!("\tRemoves an entry for the given name. Fails if no entry for that name exists (you get the idea).");
    println!("all");
    println!("\tRetrieves all name-password pairs and copies them in alphabetical order to your clipboard.");
    println!("setup");
    println!("\tPerforms all of the initial setup necessary to ensure data is secure.");
    println!("help");
    println!("\tDisplays this message");
}

fn handle_setup(args: &Vec<String>) -> Result<(), Box<dyn Error>> {
    check_args(args.len(), 2);

    let path = get_data_directory()?;

    print_and_flush("Welcome! ")?;

    match encryption::Encryption::use_existing(&path) {
        Ok(_) => {
            print_and_flush("It looks like you already have a config ready to go. Are you sure you want to overwrite it? This will clear the stored data. y/N ")?;
            let confirm = read_input()?;
            match confirm.as_str() {
                "y" | "Y" => (),
                _ => {
                    println!("Aborting setup");
                    return Ok(());
                }
            };
        },
        Err(_) => ()
    };

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

    encryption::Encryption::make_new(&path, &password)?;
    println!("Awesome! You're ready to go.");

    Ok(())
}

fn handle_add(args: &Vec<String>) -> Result<(), Box<dyn Error>> {
    check_args(args.len(), 3);
    let name_to_add = &args[2];

    let (database, password) = prepare_db_and_password()?;

    let results = database.get_password(&name_to_add, &password)?;

    match results.len() {
        0 => {
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
        },
        1 => println!("There's already an entry for {} in the database", name_to_add),
        _ => panic!("Somehow there's more than one entry for {}", name_to_add)
    };

    Ok(())
}

fn handle_get(args: &Vec<String>) -> Result<(), Box<dyn Error>> {
    check_args(args.len(), 3);
    let name_to_get = &args[2];

    let (database, password) = prepare_db_and_password()?;

    let results = database.get_password(&name_to_get, &password)?;

    match results.len() {
        0 => println!("No password found for {}", name_to_get),
        1 => {
            set_clipboard(results.get(0).unwrap())?;
            println!("Copied password for {} to clipboard", name_to_get);
        }
        _ => panic!("Somehow there's more than one entry for {}", name_to_get)
    };

    Ok(())
}

fn handle_all(args: &Vec<String>) -> Result<(), Box<dyn Error>> {
    check_args(args.len(), 2);

    let (database, password) = prepare_db_and_password()?;

    print_and_flush("Are you sure you want to get all passwords? They will be copied to your clipboard. y/N: ")?;
    let confirm = read_input()?;

    match confirm.as_str() {
        "y" | "Y" => { 
            let results = database.get_all_passwords(&password)?;

            if results.len() == 0 {
                println!("No passwords found");
            } else {
                set_clipboard(&results.join("\n"))?;
                println!("Copied all passwords to clipboard");
            }
        },
        _ => println!("Cancelling retrieving all passwords")
    };

    Ok(())
}

fn handle_remove(args: &Vec<String>) -> Result<(), Box<dyn Error>> {
    check_args(args.len(), 3);
    let name_to_remove = &args[2];

    let (database, password) = prepare_db_and_password()?;

    let results = database.get_password(&name_to_remove, &password)?;

    match results.len() {
        0 => println!("You haven't saved a password for {}", name_to_remove),
        1 => {
            print_and_flush(format!("Are you sure you want to remove password for {}? y/N: ", name_to_remove))?;
            let confirm = read_input()?;

            match confirm.as_str() {
                "y" | "Y" => {
                    database.remove_password(&name_to_remove)?;
                    println!("Successfully removed password for {}", name_to_remove);
                },
                _ => println!("Removal cancelled - no data was affected")
            };
        },
        _ => panic!("Somehow there's more than one entry for {}", name_to_remove)
    };

    Ok(())
}

fn prepare_db_and_password() -> Result<(db::Database, String), Box<dyn Error>> {
    let data_dir = get_data_directory()?;

    let encryption = match encryption::Encryption::use_existing(&data_dir) {
        Ok(enc) => enc,
        Err(_) => {
            println!("It looks like you haven't set up this application yet. Please run passwords setup to get started");
            std::process::exit(0);
        }
    };

    print_and_flush("Enter master password: ")?;
    let password = read_password()?;

    encryption.check_password(&password)?;

    let database = db::Database::new(&data_dir, encryption)?;

    Ok((database, password))
}

fn check_args(args_len: usize, target: usize) {
    if args_len != target {
        print_usage_and_exit();
    }
}

fn print_usage_and_exit() {
    println!("Command not understood. Run passwords help for help");
    std::process::exit(0);
}

fn get_data_directory() -> Result<path::PathBuf, Box<dyn Error>> {
    Ok(env::current_exe()?.parent().expect("executables are always in a folder").join(".data"))
}
