use argon2::Argon2;

#[derive(Debug)]
pub enum pswdm_errors {
    hash_failed
}

pub fn derive_key(password: &[u8], salt: [u8; 32]) -> Result<[u8; 32], pswdm_errors> {
    let mut key = [0u8; 32];

    let cipher = Argon2::default();

    match cipher.hash_password_into(password, &salt, &mut key) {
        Ok(_) => {
            println!("Successfully hashed password");
            return Ok(key)
        },
        Err(_) => {
            eprintln!("Failed to hash password!!!")
            return Err(pswdm_errors::hash_failed)
        }
    };
}