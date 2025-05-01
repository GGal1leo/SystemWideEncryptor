extern crate walkdir;

use bincode::{config::standard, serde::encode_to_vec};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use std::collections::HashMap;
use std::fs::File;
use std::fs::remove_file;
use std::io;
use std::io::prelude::*;
use std::iter;

use std::path::{Path, PathBuf};
use walkdir::WalkDir; // Add this near other imports

use rand::distr::Alphanumeric;
use rand::{Rng, rng};

use aes_gcm_siv::aead::{Aead, KeyInit};
use aes_gcm_siv::{Aes256GcmSiv, Nonce as AES_Nonce};

use serde::{Deserialize, Serialize};

//Struct to store ciphertext, nonce and ciphertext.len() in file and to read it from file
#[derive(Serialize, Deserialize, PartialEq, Debug)]
struct Cipher {
    len: usize,
    rand_string: String,
    ciphertext: Vec<u8>,
}

//type to simplify information from keyfile
type Keyfile = (String, HashMap<String, String>, bool);

//const CHUNK_SIZE: usize = 1 * 1024 * 1024; // 1 MiB

// const CHUNK_SIZE: usize = 128; // The size of the chunks you wish to split the stream into.

pub fn exit(code: i32) -> ! {
    std::process::exit(code);
}

fn main() {
    //let password: &str = "testpasstestpasstestpasstestpass";
    let files = WalkDir::new("./testcase");
    for entry in files.into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file() {
            let path = entry.path();
            // encrypt the file
            let (_, keymap, _) = create_new_keyfile().expect("Failed to create keyfile");
            encrypt_file(keymap, path).expect("Failed to encrypt file");
            //save_file(ciphertext, path).expect("Failed to save file");
        }
    }
}

pub fn encrypt_file(
    keymap_plaintext: HashMap<String, String>,
    path: &Path,
) -> Result<(), Box<dyn std::error::Error>> {
    println!("Encrypting file {:?}", path);
    if keymap_plaintext.is_empty() {
        panic!("No keys available. Please first add a key.")
    }
    println!("Encrypting file: please enter file path  ");
    let path = path.to_path_buf();
    println!("Encrypting file: {:?}", path);

    let new_filename = PathBuf::from(
        path.clone()
            .into_os_string()
            .into_string()
            .expect("Unable to parse filename!")
            + r#".crpt"#,
    );

    println!("Existing keynames");
    for entry in keymap_plaintext.keys() {
        println!("{}", entry)
    }
    let cleartext = read_file(&path)?;
    println!("Please provide keyname to encrypt: ");
    let answer = "tralalerotralala";
    let key = keymap_plaintext.get(answer).expect("No key with that name");
    let ciphertext = encrypt_aes(cleartext, key)?;

    save_file(ciphertext, &new_filename)?;
    // delete original file
    remove_file(&path)?;

    Ok(())
}

pub fn read_file(path: &Path) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut f = File::open(path)?;
    let mut buffer: Vec<u8> = Vec::new();

    // read the whole file
    f.read_to_end(&mut buffer)?;
    //println!("{:?}", from_utf8(&buffer)?);
    Ok(buffer)
}

pub fn encrypt_aes(cleartext: Vec<u8>, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let aead = Aes256GcmSiv::new_from_slice(key.as_bytes())?;
    //generate random nonce
    let mut rng = rng();
    let rand_string: String = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(12)
        .collect();
    let nonce = AES_Nonce::from_slice(rand_string.as_bytes());
    let ciphertext: Vec<u8> = aead
        .encrypt(nonce, cleartext.as_ref())
        .expect("encryption failure!");

    println!("Ciphertext: {:?}", ciphertext);
    //ciphertext_to_send includes the length of the ciphertext (to confirm upon decryption), the nonce (needed to decrypt) and the actual ciphertext
    let ciphertext_to_send = Cipher {
        len: ciphertext.len(),
        rand_string,
        ciphertext,
    };
    //serialize using bincode. Facilitates storing in file.
    let encoded: Vec<u8> =
        bincode::serde::encode_to_vec(&ciphertext_to_send, bincode::config::standard())?;
    Ok(encoded)
}

pub fn save_file(data: Vec<u8>, path: &Path) -> std::io::Result<()> {
    let mut file = File::create(path)?;
    file.write_all(&data)?;
    Ok(())
}

pub fn create_new_keyfile() -> Result<Keyfile, Box<dyn std::error::Error>> {
    //Enter a password to encrypt key.file
    // println!("Please enter a password (length > 8) to encrypt the keyfile: ");

    let password = "daddyplease".to_string();
    let mut file = File::create("key.file")?;
    //println!("Please choose name for new key: ");
    //Ask for a name to be associated with the new key
    let key_name = "tralalerotralala";
    let mut key = String::new();
    let mut rng = rng();
    let key_rand: String = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(32)
        .collect();
    key.push_str(&key_rand);
    let mut new_key_map = HashMap::new();

    new_key_map.insert(key_name.to_string(), key);

    let encoded: Vec<u8> = encrypt_hashmap(
        new_key_map.clone().into_iter().collect(), // Convert HashMap<&str, _> to HashMap<String, _>
        &password,
    )?;

    file.write_all(&encoded)?;
    Ok((password, new_key_map, true))
}

pub fn encrypt_hashmap(
    keymap_plaintext: HashMap<String, String>,
    password: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let encoded: Vec<u8> =
        bincode::serde::encode_to_vec(&keymap_plaintext, bincode::config::standard())?;

    //encrypt Hashmap with keys
    let mut rng = rng();
    let rand_string: String = iter::repeat(())
        .map(|()| rng.sample(Alphanumeric))
        .map(char::from)
        .take(24)
        .collect();
    let nonce = XNonce::from_slice(rand_string.as_bytes());
    let hashed_password = blake3::hash(password.trim().as_bytes());
    let key = Key::from_slice(hashed_password.as_bytes());
    let aead = XChaCha20Poly1305::new(key);
    let ciphertext: Vec<u8> = aead
        .encrypt(nonce, encoded.as_ref())
        .expect("encryption failure!");
    let ciphertext_to_send = Cipher {
        len: ciphertext.len(),
        rand_string,
        ciphertext,
    };
    let encoded: Vec<u8> =
        bincode::serde::encode_to_vec(&ciphertext_to_send, bincode::config::standard())?;
    Ok(encoded)
}
