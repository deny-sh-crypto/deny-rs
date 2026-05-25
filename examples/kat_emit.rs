use deny_sh::derive_key;

fn main() {
    let salt = [0xAAu8; 32];
    let key = derive_key("password1", "password2", &salt);
    println!("{}", hex::encode(key));
}
