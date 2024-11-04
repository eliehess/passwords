use clipboard_win;
use passwords::db::{Database, FileStatus};
use rpassword;
use std::{
    env,
    error::Error,
    io::{self, Write},
    path,
};

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
            _ => handle_help(),
        },
        None => handle_help(),
    })
}

fn handle_help() -> String {
    "passwords is a command-line password manager. It supports the following options:\n\
    setup\n\
    \tPerforms all of the initial setup necessary to secure data.\n\
    \tMust be run once when this program is first used.\n\
    add <name>\n\
    \tPrompts the user for a password to add for the given name, then adds them as a new entry.\n\
    \tFails if an entry for that name already exists (it'll tell you when this happens).\n\
    get <name>\n\
    \tRetrieves an entry for the given name and copies it to the clipboard.\n\
    \tFails if no entry for that name exists (it'll tell you when this happens, too).\n\
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

    match Database::files_exist(&path) {
        FileStatus::None => (),
        FileStatus::Some => {
            if confirm_with_user("It looks like some configuration files are missing. Are you sure you want to overwrite the ones that remain? This will clear the stored data.")? {
               Database::delete(&path)?;
                println!("Previous configuration cleared.");
            } else {
                return Err("Aborting setup".into());
            }
        }
        FileStatus::All => {
            if confirm_with_user("It looks like you already have a config ready to go. Are you sure you want to overwrite it? This will clear the stored data.")? {
                Database::delete(&path)?;
                println!("Previous configuration cleared.");
            } else {
                return Err("Aborting setup".into());
            }
        }
    };

    let password = loop {
        let init_password = rpassword::prompt_password("Please choose a master password: ")?;

        let confirm_init_password =
            rpassword::prompt_password("Please confirm your master password: ")?;

        if init_password == confirm_init_password {
            break init_password;
        }

        println!("Your passwords don't match. Please try again.");
    };

    Database::create_new(&path, &password)?;

    Ok("Awesome! You're ready to go.".to_string())
}

fn handle_add(maybe_name_to_add: Option<&String>) -> Result<String, Box<dyn Error>> {
    let Some(name_to_add) = maybe_name_to_add else {
        return Err("Usage: passwords add <name>".into());
    };

    let database = prepare_db_and_password()?;

    if let Some(_) = database.get_password(name_to_add)? {
        return Err(format!("You've already saved a password for {name_to_add}").into());
    };

    let password_to_add = loop {
        let password_to_add =
            rpassword::prompt_password(format!("Enter password to add for {name_to_add}: "))?;

        let password_confirm =
            rpassword::prompt_password(format!("Confirm password to add for {name_to_add}: "))?;

        if password_to_add == password_confirm {
            break password_to_add;
        }

        println!("The passwords don't match. Please try again.");
    };

    database.add_password(name_to_add, &password_to_add)?;

    Ok(format!("Added password for {name_to_add}"))
}

fn handle_get(maybe_name_to_get: Option<&String>) -> Result<String, Box<dyn Error>> {
    let Some(name_to_get) = maybe_name_to_get else {
        return Err("Usage: passwords get <name>".into());
    };

    let database = prepare_db_and_password()?;

    match database.get_password(name_to_get)? {
        None => Ok(format!("You haven't saved a password for {name_to_get}")),
        Some(res) => match clipboard_win::set_clipboard_string(&res) {
            Ok(()) => Ok(format!("Copied password for {name_to_get} to clipboard")),
            Err(e) => Err(format!("{e}").into()),
        },
    }
}

fn handle_all() -> Result<String, Box<dyn Error>> {
    let database = prepare_db_and_password()?;

    if !confirm_with_user(
        "Are you sure you want to get all passwords? They will be copied to your clipboard.",
    )? {
        return Ok("Cancelling retrieving all passwords".to_string());
    }

    let results = database.get_all_passwords()?;

    if results.len() == 0 {
        return Ok("No passwords found".to_string());
    }

    let mut joined = String::new();
    for (name, password) in results {
        joined += format!("{name}: {password}\n").as_str();
    }
    match clipboard_win::set_clipboard_string(joined.as_str()) {
        Ok(()) => Ok("Copied all passwords to clipboard".to_string()),
        Err(e) => Err(format!("{e}").into()),
    }
}

fn handle_remove(maybe_name_to_remove: Option<&String>) -> Result<String, Box<dyn Error>> {
    let Some(name_to_remove) = maybe_name_to_remove else {
        return Err("Usage: passwords remove <name>".into());
    };

    let database = prepare_db_and_password()?;

    if let None = database.get_password(name_to_remove)? {
        return Err(format!("You haven't saved a password for {name_to_remove}").into());
    }

    if confirm_with_user(&format!(
        "Are you sure you want to remove password for {name_to_remove}?"
    ))? {
        database.remove_password(name_to_remove)?;
        Ok(format!(
            "Successfully removed password for {name_to_remove}"
        ))
    } else {
        Ok("Removal cancelled - no data was affected".to_string())
    }
}

fn handle_list() -> Result<String, Box<dyn Error>> {
    let database = prepare_db_and_password()?;

    let results = database.get_all_names()?;

    match results.len() {
        0 => Ok("No entries found".to_string()),
        _ => Ok(results.join("\n")),
    }
}

fn prepare_db_and_password() -> Result<Database, Box<dyn Error>> {
    let data_dir = get_data_directory()?;

    match Database::files_exist(&data_dir) {
        FileStatus::All => (),
        FileStatus::Some => return Err("It looks like some configuration files are missing. Please run passwords setup to get started.".into()),
        FileStatus::None => return Err("It looks like you haven't set up this application yet. Please run passwords setup to get started.".into()),
    };

    let password = rpassword::prompt_password("Enter master password: ")?;

    Ok(Database::use_existing(&data_dir, &password)?)
}

fn get_data_directory() -> io::Result<path::PathBuf> {
    Ok(env::current_exe()?
        .parent()
        .expect("executables are always in a folder")
        .join(".data"))
}

fn confirm_with_user(message: &str) -> io::Result<bool> {
    print_and_flush!("{message} y/N: ");
    Ok(read_input()?.eq_ignore_ascii_case("Y"))
}

fn read_input() -> io::Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}
