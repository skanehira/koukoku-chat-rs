use std::io::prelude::*;
use std::net::TcpStream;
use std::sync::Arc;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
        rustls::OwnedTrustAnchor::from_subject_spki_name_constraints(
            ta.subject,
            ta.spki,
            ta.name_constraints,
        )
    }));

    let config = rustls::ClientConfig::builder()
        .with_safe_defaults()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let koukoku = "koukoku.shadan.open.ad.jp";
    let mut conn = rustls::ClientConnection::new(Arc::new(config), koukoku.try_into()?)?;
    let mut sock = TcpStream::connect(format!("{}:992", koukoku))?;
    let mut stream = rustls::Stream::new(&mut conn, &mut sock);

    stream.write_all(b"nobody")?;

    let mut line = String::new();
    let mut buf = std::io::BufReader::new(stream);

    loop {
        if buf.read_line(&mut line)? == 0 {
            break;
        }
        println!("{}", line);
        line.clear();
    }

    Ok(())
}
