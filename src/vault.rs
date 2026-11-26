//! Encrypted on-disk client state. Argon2id derives the key; the AEAD comes from the
//! audited crypto provider. Protects a stolen file, not a compromised running device.

use crate::{err, Client, Res, SUITE};
use argon2::{Algorithm, Argon2, Params, Version};
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::Provider;
use openmls_traits::{crypto::OpenMlsCrypto, random::OpenMlsRand, types::AeadType, OpenMlsProvider};
use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, path::Path};
use zeroize::Zeroizing;

const MAGIC: &[u8; 8] = b"TALKVLT1";
const HEADER: usize = 8 + 16 + 12;

fn derive(pass: &str, salt: &[u8]) -> Res<Zeroizing<[u8; 32]>> {
    let params = Params::new(64 * 1024, 3, 1, Some(32)).map_err(err)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(pass.as_bytes(), salt, key.as_mut()).map_err(err)?;
    Ok(key)
}

fn put(w: &mut Vec<u8>, b: &[u8]) {
    w.extend((b.len() as u32).to_be_bytes());
    w.extend(b);
}

struct Reader<'a>(&'a [u8]);
impl<'a> Reader<'a> {
    fn bytes(&mut self) -> Res<&'a [u8]> {
        if self.0.len() < 4 { return Err("corrupt vault".into()); }
        let n = u32::from_be_bytes(self.0[..4].try_into().unwrap()) as usize;
        if self.0.len() < 4 + n { return Err("corrupt vault".into()); }
        let (v, rest) = self.0[4..].split_at(n);
        self.0 = rest;
        Ok(v)
    }
    fn text(&mut self) -> Res<String> {
        String::from_utf8(self.bytes()?.to_vec()).map_err(err)
    }
    fn count(&mut self) -> Res<usize> {
        let b = self.bytes()?;
        Ok(u32::from_be_bytes(b.try_into().map_err(err)?) as usize)
    }
}

/// Secure random bytes from the audited crypto provider.
pub fn random_bytes<const N: usize>() -> Res<[u8; N]> {
    Provider::new().map_err(err)?.rand().random_array().map_err(err)
}

/// Derives a file key from a passphrase.
pub fn derive_key(passphrase: &str, salt: &[u8; 16]) -> Res<Zeroizing<[u8; 32]>> {
    derive(passphrase, salt)
}

/// Encrypts to an owner-only file, replacing it atomically.
pub fn seal_file(path: &Path, key: &[u8; 32], salt: &[u8; 16], plain: &[u8]) -> Res<()> {
    let provider = Provider::new().map_err(err)?;
    let nonce: [u8; 12] = provider.rand().random_array().map_err(err)?;
    let mut out = Vec::with_capacity(HEADER + plain.len() + 16);
    out.extend(MAGIC);
    out.extend(salt);
    out.extend(nonce);
    let sealed = provider.crypto()
        .aead_encrypt(AeadType::ChaCha20Poly1305, key, plain, &nonce, &out[..HEADER])
        .map_err(err)?;
    out.extend(sealed);
    let tmp = path.with_extension("tmp");
    // A leftover temporary file could have wider permissions, so it is replaced, never reused.
    let _ = fs::remove_file(&tmp);
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(&tmp).map_err(err)?;
    f.write_all(&out).map_err(err)?;
    f.sync_all().map_err(err)?;
    fs::rename(&tmp, path).map_err(err)
}

/// Opens a sealed file. Returns the key and salt for later saves, and the contents.
pub fn open_file(path: &Path, passphrase: &str) -> Res<(Zeroizing<[u8; 32]>, [u8; 16], Zeroizing<Vec<u8>>)> {
    let data = fs::read(path).map_err(err)?;
    if data.len() < HEADER + 16 || &data[..8] != MAGIC { return Err("not a Talk vault".into()); }
    let salt: [u8; 16] = data[8..24].try_into().map_err(err)?;
    let key = derive(passphrase, &salt)?;
    let provider = Provider::new().map_err(err)?;
    let plain = provider.crypto()
        .aead_decrypt(AeadType::ChaCha20Poly1305, key.as_ref(), &data[HEADER..], &data[24..36], &data[..HEADER])
        .map_err(|_| "wrong passphrase or damaged vault".to_string())?;
    Ok((key, salt, Zeroizing::new(plain)))
}

impl Client {
    /// This client's complete state, for storing inside an encrypted file.
    pub fn export_state(&self) -> Res<Zeroizing<Vec<u8>>> {
        let mut plain = Zeroizing::new(Vec::new());
        put(&mut plain, self.name.as_bytes());
        put(&mut plain, self.signer.public());
        put(&mut plain, &(self.contacts.len() as u32).to_be_bytes());
        for (n, k) in &self.contacts { put(&mut plain, n.as_bytes()); put(&mut plain, k); }
        put(&mut plain, self.group.as_ref().map(|g| g.group_id().as_slice()).unwrap_or(&[]));
        put(&mut plain, &(self.held.len() as u32).to_be_bytes());
        for h in &self.held { put(&mut plain, h); }
        put(&mut plain, &(self.reinvites_used.len() as u32).to_be_bytes());
        for h in &self.reinvites_used { put(&mut plain, h); }
        put(&mut plain, &(self.reinvite_counts.len() as u32).to_be_bytes());
        for (n, c) in &self.reinvite_counts { put(&mut plain, n.as_bytes()); put(&mut plain, &[*c]); }
        // The library's own serializer is test-only, so its public map is written directly.
        let values = self.provider.storage().values.read().map_err(err)?;
        put(&mut plain, &(values.len() as u32).to_be_bytes());
        for (k, v) in values.iter() { put(&mut plain, k); put(&mut plain, v); }
        Ok(plain)
    }

    pub fn import_state(plain: &[u8]) -> Res<Self> {
        Self::restore(Provider::new().map_err(err)?, plain)
    }

    pub fn save(&self, path: &Path, passphrase: &str) -> Res<()> {
        let plain = self.export_state()?;
        let salt: [u8; 16] = self.provider.rand().random_array().map_err(err)?;
        let key = derive(passphrase, &salt)?;
        seal_file(path, &key, &salt, &plain)
    }

    pub fn load(path: &Path, passphrase: &str) -> Res<Self> {
        let (_key, _salt, plain) = open_file(path, passphrase)?;
        Self::import_state(&plain)
    }

    fn restore(provider: Provider, plain: &[u8]) -> Res<Self> {
        let mut r = Reader(plain);
        let name = r.text()?;
        let public = r.bytes()?.to_vec();
        let mut c = Self::empty(&name, provider, None)?;
        for _ in 0..r.count()? { let n = r.text()?; let k = r.bytes()?.to_vec(); c.contacts.insert(n, k); }
        let group_id = r.bytes()?.to_vec();
        for _ in 0..r.count()? { c.held.push_back(r.bytes()?.to_vec()); }
        for _ in 0..r.count()? { c.reinvites_used.insert(r.bytes()?.to_vec()); }
        for _ in 0..r.count()? {
            let n = r.text()?;
            let v = *r.bytes()?.first().ok_or("corrupt vault")?;
            c.reinvite_counts.insert(n, v);
        }
        {
            let mut values = c.provider.storage().values.write().map_err(err)?;
            values.clear();
            for _ in 0..r.count()? {
                let k = r.bytes()?.to_vec();
                let v = r.bytes()?.to_vec();
                values.insert(k, v);
            }
        }
        if !r.0.is_empty() { return Err("corrupt vault".into()); }
        c.signer = SignatureKeyPair::read(c.provider.storage(), &public, SUITE.signature_algorithm())
            .ok_or("signing key missing from vault")?;
        c.credential.signature_key = c.signer.public().into();
        if !group_id.is_empty() {
            c.group = MlsGroup::load(c.provider.storage(), &GroupId::from_slice(&group_id)).map_err(err)?;
            if c.group.is_none() { return Err("group missing from vault".into()); }
        }
        Ok(c)
    }
}
