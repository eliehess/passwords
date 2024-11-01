use clipboard_win::Clipboard;
use passwords::db;
use rpassword;
use std::{
    env,
    error::Error,
    io::{self, Write},
    path,
    result::Result,
};

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

fn main() {
    match do_main(env::args().collect()) {
        Ok(s) => println!("{}", s),
        Err(e) => eprintln!("{}", e),
    }
}

fn do_main(args: Vec<String>) -> Result<String, Box<dyn Error>> {
    Ok(match args.get(1) {
        Some(s) => match s.as_str() {
            "add" => handle_add(args.get(2))?,
            "get" => handle_get(args.get(2))?,
            "remove" => handle_remove(args.get(2))?,
            "all" => handle_all()?,
            "list" => handle_list()?,
            "setup" => handle_setup()?,
            "help" => handle_help(),
            _ => "Option not understood. Run passwords help for help".to_string(),
        },
        None => "Please enter an option. Run passwords help for help".to_string(),
    })
}

fn handle_help() -> String {
    "passwords is a command-line password manager. It supports the following options:\n\
    setup\n\
    \tPerforms all of the initial setup necessary to secure data. Must be run once when this program is first used.\n\
    add <name>\n\
    \tPrompts the user for a password to add for the given name, then adds them as a new entry. Fails if an entry for that name already exists (it'll tell you when this happens).\n\
    get <name>\n\
    \tRetrieves an entry for the given name and copies it to the clipboard. Fails if no entry for that name exists (it'll tell you when this happens, too).\n\
    remove <name>\n\
    \tRemoves an entry for the given name. Fails if no entry for that name exists (you get the idea).\n\
    all\n\
    \tRetrieves all name-password pairs and copies them in alphabetical order to the clipboard.\n\
    list\n\
    \tRetrieves all names (no passwords) and prints them to the console in alphabetical order\n\
    help\n\
    \tDisplays this message".to_string()
}

fn handle_setup() -> Result<String, Box<dyn Error>> {
    let path = get_data_directory()?;

    print_and_flush!("Welcome! ");

    match db::Database::files_exist(&path) {
        db::FileStatus::None => (),
        db::FileStatus::Some => {
            print_and_flush!("It looks like some configuration files are missing. Are you sure you want to overwrite the ones that remain? This will clear the stored data. y/N ");
            match read_input()?.as_str() {
                "y" | "Y" => db::Database::delete(&path)?,
                _ => exit!("Aborting setup"),
            }
        }
        db::FileStatus::All => {
            print_and_flush!("It looks like you already have a config ready to go. Are you sure you want to overwrite it? This will clear the stored data. y/N ");
            match read_input()?.as_str() {
                "y" | "Y" => db::Database::delete(&path)?,
                _ => exit!("Aborting setup"),
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

    Ok("Awesome! You're ready to go.".to_string())
}

fn handle_add(maybe_name_to_add: Option<&String>) -> Result<String, Box<dyn Error>> {
    let Some(name_to_add) = maybe_name_to_add else {
        return Ok("add takes one argument".to_string());
    };

    let database = prepare_db_and_password()?;

    match database.get_password(&name_to_add)? {
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

            database.add_password(name_to_add, &password_to_add)?;
            Ok(format!("Added password for {}!", name_to_add))
        }
        Some(_) => Ok(format!(
            "You've already saved a password for {}",
            name_to_add
        )),
    }
}

fn handle_get(maybe_name_to_get: Option<&String>) -> Result<String, Box<dyn Error>> {
    let Some(name_to_get) = maybe_name_to_get else {
        return Ok("get takes one argument".to_string());
    };

    let database = prepare_db_and_password()?;

    match database.get_password(name_to_get)? {
        None => Ok(format!("You haven't saved a password for {}", name_to_get)),
        Some(res) => {
            Clipboard::new()?.set_string(&res)?;
            Ok(format!("Copied password for {} to clipboard", name_to_get))
        }
    }
}

fn handle_all() -> Result<String, Box<dyn Error>> {
    let database = prepare_db_and_password()?;

    print_and_flush!(
        "Are you sure you want to get all passwords? They will be copied to your clipboard. y/N: "
    );

    match read_input()?.as_str() {
        "y" | "Y" => {
            let results = database.get_all_passwords()?;

            if results.len() == 0 {
                Ok("No passwords found".to_string())
            } else {
                let mut joined = String::new();
                for (name, password) in results {
                    joined += format!("{}: {}\n", name, password).as_str();
                }
                Clipboard::new()?.set_string(joined.as_str())?;
                Ok("Copied all passwords to clipboard".to_string())
            }
        }
        _ => Ok("Cancelling retrieving all passwords".to_string()),
    }
}

fn handle_remove(maybe_name_to_remove: Option<&String>) -> Result<String, Box<dyn Error>> {
    let Some(name_to_remove) = maybe_name_to_remove else {
        return Ok("remove takes one argument".to_string());
    };

    let database = prepare_db_and_password()?;

    match database.get_password(name_to_remove)? {
        None => Ok(format!(
            "You haven't saved a password for {}",
            name_to_remove
        )),
        Some(_) => {
            print_and_flush!(
                "Are you sure you want to remove password for {}? y/N: ",
                name_to_remove
            );

            match read_input()?.as_str() {
                "y" | "Y" => {
                    database.remove_password(name_to_remove)?;
                    Ok(format!(
                        "Successfully removed password for {}",
                        name_to_remove
                    ))
                }
                _ => Ok("Removal cancelled - no data was affected".to_string()),
            }
        }
    }
}

fn handle_list() -> Result<String, Box<dyn Error>> {
    let database = prepare_db_and_password()?;

    let results = database.get_all_names()?;

    match results.len() {
        0 => Ok("No entries found".to_string()),
        _ => Ok(format!("{}", results.join("\n"))),
    }
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
            db::DatabaseError::Authentication { message } => {
                exit!("An error occurred during authentication: {}", message)
            }
            db::DatabaseError::File { message } => {
                exit!("An error occurred with the application files: {}", message)
            }
            _ => {
                return Err(Box::new(e));
            }
        },
    };

    Ok(database)
}

fn get_data_directory() -> io::Result<path::PathBuf> {
    Ok(env::current_exe()?
        .parent()
        .expect("executables are always in a folder")
        .join(".data"))
}

fn read_input() -> io::Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}
