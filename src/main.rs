use std::{env, path, io::{self, Write}, result::Result, error::Error};
use passwords::db;
use rpassword;
use clipboard_win::Clipboard;

fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();

    match args.get(1) {
        Some(s) => match s.as_str() {
            "add" => handle_add(&args)?,
            "get" => handle_get(&args)?,
            "all" => handle_all(&args)?,
            "remove" => handle_remove(&args)?,
            "list" => handle_list(&args)?,
            "setup" => handle_setup(&args)?,
            "help" => handle_help(),
            _ => { println!("Option not understood. Run passwords help for help") }
        },
        None => { println!("Please enter an option. Run passwords help for help") }
    }

    Ok(())
}

macro_rules! exit {
    ($($x:expr),*) => {{
        println!($($x),*);
        std::process::exit(0);
    }};
}

macro_rules! print_and_flush {
    ($($x:expr),*) => {
        print!($($x),*);
        io::stdout().flush().unwrap();
    };
}

fn handle_help() {
    println!("passwords is a command-line password manager. It supports the following options:");
    println!("setup");
    println!("\tPerforms all of the initial setup necessary to secure data. Must be run once when this program is first used.");
    println!("add <name>");
    println!("\tAdds a new entry for the given name. Fails if an entry for that name already exists (it'll tell you when this happens).");
    println!("get <name>");
    println!("\tRetrieves an entry for the given name and copies it to the clipboard. Fails if no entry for that name exists (it'll tell you when this happens, too).");
    println!("remove <name>");
    println!("\tRemoves an entry for the given name. Fails if no entry for that name exists (you get the idea).");
    println!("all");
    println!("\tRetrieves all name-password pairs and copies them in alphabetical order to the clipboard.");
    println!("list");
    println!("\tRetrieves all names (no passwords) and prints them to the console");
    println!("help");
    println!("\tDisplays this message");
}

fn handle_setup(args: &Vec<String>) -> Result<(), Box<dyn Error>> {
    if args.len() != 2 {
        exit!("setup takes no arguments");
    }

    let path = get_data_directory()?;

    print_and_flush!("Welcome! ");

    match db::Database::files_exist(&path) {
        db::FileStatus::None => (),
        db::FileStatus::Some => {
            print_and_flush!("It looks like some configuration files are missing. Are you sure you want to overwrite the ones that remain? This will clear the stored data. y/N ");
            match read_input()?.as_str() {
                "y" | "Y" => db::Database::delete(&path)?,
                _ => exit!("Aborting setup")
            }
        },
        db::FileStatus::All => {
            print_and_flush!("It looks like you already have a config ready to go. Are you sure you want to overwrite it? This will clear the stored data. y/N ");
            match read_input()?.as_str() {
                "y" | "Y" => db::Database::delete(&path)?,
                _ => exit!("Aborting setup")
            };
        }
    };

    let password = loop {
        print_and_flush!("Please choose a master password: ");
        let init_password = rpassword::read_password()?;

        print_and_flush!("Please confirm your master password: ");
        let confirm_init_password = rpassword::read_password()?;

        if init_password == confirm_init_password {
            break init_password;
        }

        println!("Your passwords don't match. Please try again.");
    };

    db::Database::create_new(&path, &password)?;
    println!("Awesome! You're ready to go.");

    Ok(())
}

fn handle_add(args: &Vec<String>) -> Result<(), Box<dyn Error>> {
    if args.len() != 3 {
        exit!("add takes one argument");
    }

    let name_to_add = &args[2];

    let database = prepare_db_and_password()?;

    let result = database.get_password(&name_to_add)?;

    match result {
        None => {
            let password_to_add = loop {
                print_and_flush!("Enter password to add for {}: ", name_to_add);
                let password_to_add = rpassword::read_password()?;
                
                print_and_flush!("Confirm password to add for {}: ", name_to_add);
                let password_confirm = rpassword::read_password()?;
        
                if password_to_add == password_confirm {
                    break password_to_add;
                }
        
                println!("The passwords don't match. Please try again.");
            };
        
            database.add_password(&name_to_add, &password_to_add)?;
            println!("Added password for {}!", name_to_add);
        },
        Some(_) => println!("You've already saved a password for {}", name_to_add)
    };

    Ok(())
}

fn handle_get(args: &Vec<String>) -> Result<(), Box<dyn Error>> {
    if args.len() != 3 {
        exit!("get takes one argument");
    }

    let name_to_get = &args[2];

    let database = prepare_db_and_password()?;

    let result = database.get_password(&name_to_get)?;

    match result {
        None => println!("You haven't saved a password for {}", name_to_get),
        Some(res) => {
            Clipboard::new()?.set_string(&res)?;
            println!("Copied password for {} to clipboard", name_to_get);
        }
    }

    Ok(())
}

fn handle_all(args: &Vec<String>) -> Result<(), Box<dyn Error>> {
    if args.len() != 2 {
       exit!("all takes no arguments");
    }

    let database = prepare_db_and_password()?;

    print_and_flush!("Are you sure you want to get all passwords? They will be copied to your clipboard. y/N: ");

    match read_input()?.as_str() {
        "y" | "Y" => { 
            let results = database.get_all_passwords()?;

            if results.len() == 0 {
                println!("No passwords found");
            } else {
                let mut joined = String::new();
                for result in results {
                    joined += format!("{}: {}\n", result.0, result.1).as_str();
                }
                Clipboard::new()?.set_string(joined.as_str())?;
                println!("Copied all passwords to clipboard");
            }
        },
        _ => println!("Cancelling retrieving all passwords")
    };

    Ok(())
}

fn handle_remove(args: &Vec<String>) -> Result<(), Box<dyn Error>> {
    if args.len() != 3 {
        exit!("remove takes one argument");
    }

    let name_to_remove = &args[2];

    let database = prepare_db_and_password()?;

    let result = database.get_password(&name_to_remove)?;

    match result {
        None => println!("You haven't saved a password for {}", name_to_remove),
        Some(_) => {
            print_and_flush!("Are you sure you want to remove password for {}? y/N: ", name_to_remove);

            match read_input()?.as_str() {
                "y" | "Y" => {
                    database.remove_password(&name_to_remove)?;
                    println!("Successfully removed password for {}", name_to_remove);
                },
                _ => println!("Removal cancelled - no data was affected")
            };
        }
    };

    Ok(())
}

fn handle_list(args: &Vec<String>) -> Result<(), Box<dyn Error>> {
    if args.len() != 2 {
        exit!("list takes no arguments");
    }

    let database = prepare_db_and_password()?;

    let results = database.get_all_names()?;

    match results.len() {
        0 => println!("No entries found"),
        _ => println!("{}", results.join("\n"))
    };

    Ok(())
}

fn prepare_db_and_password() -> Result<db::Database, Box<dyn Error>> {
    let data_dir = get_data_directory()?;

    match db::Database::files_exist(&data_dir) {
        db::FileStatus::All => (),
        db::FileStatus::Some => exit!("It looks like some configuration files are missing. Please run passwords setup to get started."),
        db::FileStatus::None => exit!("It looks like you haven't set up this application yet. Please run passwords setup to get started.")
    };

    print_and_flush!("Enter master password: ");
    let password = rpassword::read_password()?;

    let database = match db::Database::use_existing(&data_dir, &password) {
        Ok(db) => db,
        Err(e) => match e {
            db::DatabaseError::Authentication { message } => exit!("An error occurred during authentication: {}", message),
            db::DatabaseError::File { message } => exit!("An error occurred with the application files: {}", message),
            _ => { return Err(Box::new(e)); }
        }
    };

    Ok(database)
}

fn get_data_directory() -> io::Result<path::PathBuf> {
    Ok(env::current_exe()?.parent().expect("executables are always in a folder").join(".data"))
}

fn read_input() -> io::Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}
