use aes_crate::Aes128;
use cfb8::cipher::{AsyncStreamCipher, KeyIvInit};

type Aes128Cfb8Enc = cfb8::Encryptor<Aes128>;
type Aes128Cfb8Dec = cfb8::Decryptor<Aes128>;

/// CFB8 encrypt using hardware AES-NI.
/// key: original 16-byte key (not expanded), iv: 16 bytes.
pub fn native_cfb8_encrypt(key: &Vec<u8>, iv: &Vec<u8>, plaintext: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    if key.len() < 16 || iv.len() < 16 { return (plaintext.clone(), iv.clone()); }
    let mut buf = plaintext.clone();
    let enc = Aes128Cfb8Enc::new(key[..16].into(), iv[..16].into());
    enc.encrypt(&mut buf);
    let new_iv = if buf.len() >= 16 {
        buf[buf.len()-16..].to_vec()
    } else {
        let mut v = iv[..16].to_vec();
        let start = 16 - buf.len();
        v.copy_within(buf.len()..16, 0);
        v[start..].copy_from_slice(&buf);
        v
    };
    (buf, new_iv)
}

/// CFB8 decrypt using hardware AES-NI.
pub fn native_cfb8_decrypt(key: &Vec<u8>, iv: &Vec<u8>, ciphertext: &Vec<u8>) -> (Vec<u8>, Vec<u8>) {
    if key.len() < 16 || iv.len() < 16 { return (ciphertext.clone(), iv.clone()); }
    let new_iv = if ciphertext.len() >= 16 {
        ciphertext[ciphertext.len()-16..].to_vec()
    } else {
        let mut v = iv[..16].to_vec();
        let start = 16 - ciphertext.len();
        v.copy_within(ciphertext.len()..16, 0);
        v[start..].copy_from_slice(ciphertext);
        v
    };
    let mut buf = ciphertext.clone();
    let dec = Aes128Cfb8Dec::new(key[..16].into(), iv[..16].into());
    dec.decrypt(&mut buf);
    (buf, new_iv)
}
