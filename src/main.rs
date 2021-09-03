use std::io::{self, Write};
use passwords::hash::hash;
use rpassword;

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
}

/*fn read_input() -> io::Result<String> {
    let mut input = String::new();
    io::stdin().read_line(&mut input)?;
    Ok(input.trim().to_string())
}*/