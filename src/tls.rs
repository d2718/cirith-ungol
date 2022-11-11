/*! All the stuff necessary to build a TLS listener. */

use std::{fs::File, io::BufReader, net::SocketAddr, path::Path, sync::Arc};

use hyper::server::conn::AddrIncoming;
use rustls_pemfile::Item;
use tls_listener::TlsListener;
use tokio_rustls::{
    rustls::{server::ServerConfig, Certificate, PrivateKey},
    TlsAcceptor,
};

pub fn make_listener<C, K>(
    cert_file: C,
    key_file: K,
    addr: &SocketAddr,
) -> Result<TlsListener<AddrIncoming, TlsAcceptor>, String>
where
    C: AsRef<Path>,
    K: AsRef<Path>,
{
    let cert_path = cert_file.as_ref();
    let key_path = key_file.as_ref();

    log::trace!(
        "make_server_config( {}, {} ) called.",
        cert_path.display(),
        key_path.display()
    );

    let certs: Vec<Certificate> = {
        let cert_file = File::open(cert_path).map_err(|e| {
            format!(
                "Error opening TLS cert file {}: {}",
                cert_path.display(),
                &e
            )
        })?;
        let mut cert_reader = BufReader::new(cert_file);
        rustls_pemfile::certs(&mut cert_reader)
            .map_err(|e| {
                format!(
                    "Error reading TLS cert file {}: {}",
                    cert_path.display(),
                    &e
                )
            })?
            .into_iter()
            .map(Certificate)
            .collect()
    };

    let key: PrivateKey = {
        let key_file = File::open(key_path)
            .map_err(|e| format!("Error opening TLS key file {}: {}", key_path.display(), &e))?;
        let mut key_reader = BufReader::new(key_file);
        match rustls_pemfile::read_one(&mut key_reader)
            .map_err(|e| format!("Error reading TLS key file {}: {}", key_path.display(), &e))?
        {
            Some(Item::RSAKey(v)) | Some(Item::PKCS8Key(v)) | Some(Item::ECKey(v)) => PrivateKey(v),
            _ => {
                return Err(format!(
                    "TLS key file {} does not contain a recognizable private key.",
                    key_path.display()
                ));
            }
        }
    };

    let cfg = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| format!("Error generating TLS configuration: {}", &e))?;
    let acceptor: TlsAcceptor = Arc::new(cfg).into();
    let incoming =
        AddrIncoming::bind(addr).map_err(|e| format!("Error binding to {}: {}", addr, &e))?;

    Ok(TlsListener::new(acceptor, incoming))
}
