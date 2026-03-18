use argon2::Argon2;

#[derive(Debug)]
pub enum PswdMErrors {
    HashFailed
}

pub fn derive_key(password: &[u8], salt: [u8; 32]) -> Result<[u8; 32], PswdmErrors> {
    let mut key = [0u8; 32];

    let cipher = Argon2::default();

    match cipher.hash_password_into(password, &salt, &mut key) {
        Ok(_) => {
            println!("Successfully hashed password");
            return Ok(key)
        },
        Err(_) => {
            eprintln!("Failed to hash password!!!");
            return Err(PswdMErrors::HashFailed)
        }
    };
}