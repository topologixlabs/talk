//! A private test certificate authority. It exists only for local tests.

use rcgen::{BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer, KeyPair};
use std::collections::HashMap;
use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, path::Path};

/// Writes a private key readable only by its owner, replacing any older copy.
pub fn write_private(path: &Path, data: &[u8]) -> Res<()> {
    let _ = fs::remove_file(path);
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(path).map_err(err)?;
    f.write_all(data).map_err(err)
}

pub type Res<T> = Result<T, String>;
fn err<E: std::fmt::Debug>(e: E) -> String { format!("{e:?}") }

/// What a client needs to reach the relay.
#[derive(Clone)]
pub struct ClientTls {
    pub ca_der: Vec<u8>,
    pub cert_der: Option<Vec<u8>>,
    pub key_der: Option<Vec<u8>>,
}

impl ClientTls {
    pub fn without_certificate(&self) -> Self {
        Self { ca_der: self.ca_der.clone(), cert_der: None, key_der: None }
    }
    pub fn save(&self, dir: &Path, name: &str) -> Res<()> {
        fs::write(dir.join("ca.der"), &self.ca_der).map_err(err)?;
        fs::write(dir.join(format!("{name}.crt")), self.cert_der.as_ref().ok_or("no certificate")?).map_err(err)?;
        write_private(&dir.join(format!("{name}.key")), self.key_der.as_ref().ok_or("no key")?)
    }
    pub fn load(dir: &Path, name: &str) -> Res<Self> {
        Ok(Self {
            ca_der: fs::read(dir.join("ca.der")).map_err(err)?,
            cert_der: Some(fs::read(dir.join(format!("{name}.crt"))).map_err(err)?),
            key_der: Some(fs::read(dir.join(format!("{name}.key"))).map_err(err)?),
        })
    }
}

pub struct TestPki {
    issuer: Issuer<'static, KeyPair>,
    pub ca_der: Vec<u8>,
    pub server_cert: Vec<u8>,
    pub server_key: Vec<u8>,
    /// Exact client certificate -> account name.
    pub accounts: HashMap<Vec<u8>, String>,
}

impl TestPki {
    pub fn new() -> Res<Self> {
        Self::for_names(&["localhost"])
    }

    /// A test authority whose relay certificate is valid for these names or addresses.
    pub fn for_names(names: &[&str]) -> Res<Self> {
        let ca_key = KeyPair::generate().map_err(err)?;
        let mut ca = CertificateParams::new(Vec::<String>::new()).map_err(err)?;
        ca.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca.distinguished_name.push(DnType::CommonName, "Talk prototype test CA");
        let ca_der = ca.self_signed(&ca_key).map_err(err)?.der().to_vec();
        let issuer = Issuer::new(ca, ca_key);
        let server_key = KeyPair::generate().map_err(err)?;
        let mut server = CertificateParams::new(names.iter().map(|n| n.to_string()).collect::<Vec<_>>()).map_err(err)?;
        server.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server_cert = server.signed_by(&server_key, &issuer).map_err(err)?.der().to_vec();
        Ok(Self { issuer, ca_der, server_cert, server_key: server_key.serialize_der(), accounts: HashMap::new() })
    }

    /// Issues a login certificate and registers the account.
    pub fn issue(&mut self, name: &str) -> Res<ClientTls> {
        let tls = self.issue_unregistered(name)?;
        self.accounts.insert(tls.cert_der.clone().unwrap(), name.to_string());
        Ok(tls)
    }

    /// A correctly signed certificate that has no account on the relay.
    pub fn issue_unregistered(&self, name: &str) -> Res<ClientTls> {
        let key = KeyPair::generate().map_err(err)?;
        let mut p = CertificateParams::new(Vec::<String>::new()).map_err(err)?;
        p.distinguished_name.push(DnType::CommonName, name);
        p.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let cert = p.signed_by(&key, &self.issuer).map_err(err)?.der().to_vec();
        Ok(ClientTls { ca_der: self.ca_der.clone(), cert_der: Some(cert), key_der: Some(key.serialize_der()) })
    }
}
