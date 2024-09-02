use std::{
    io::{BufReader, Cursor},
    sync::Arc,
    time::Duration,
};

use pki_types::ServerName;
use rustls::{server::WebPkiClientVerifier, ClientConfig, RootCertStore, ServerConfig};
use rustls_pemfile::{certs, private_key};
use tokio::{
    io::{split, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::watch,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

pub fn make_configs() -> (ServerConfig, ClientConfig) {
    const ROOT: &str = include_str!("certs/root.pem");
    const CHAIN: &str = include_str!("certs/chain.pem");
    const EE_KEY: &str = include_str!("certs/end.key");

    let mut client_root_cert_store = RootCertStore::empty();
    let mut roots = BufReader::new(Cursor::new(ROOT));
    for root in certs(&mut roots) {
        client_root_cert_store.add(root.unwrap()).unwrap();
    }
    let client_root_cert_store = Arc::new(client_root_cert_store);
    let cert = certs(&mut BufReader::new(Cursor::new(CHAIN)))
        .map(|result| result.unwrap())
        .collect();
    let key = private_key(&mut BufReader::new(Cursor::new(EE_KEY)))
        .unwrap()
        .unwrap();
    let client_cert_verifier = WebPkiClientVerifier::builder(client_root_cert_store.clone())
        .build()
        .unwrap();

    let sconfig = ServerConfig::builder()
        .with_client_cert_verifier(client_cert_verifier)
        .with_single_cert(cert, key.into())
        .unwrap();

    let cconfig = ClientConfig::builder()
        .with_root_certificates(client_root_cert_store)
        .with_no_client_auth();

    (sconfig, cconfig)
}

async fn spawn_collector() -> (ClientConfig, u16, watch::Receiver<Vec<u8>>) {
    let (server, client) = make_configs();

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let (tx, rx) = watch::channel(Vec::new());

    let acceptor = TlsAcceptor::from(Arc::new(server));

    tokio::spawn(collect_loop(listener, acceptor, tx));

    (client, port, rx)
}

async fn collect_loop(listener: TcpListener, acceptor: TlsAcceptor, store: watch::Sender<Vec<u8>>) {
    loop {
        let Ok((stream, _peer_addr)) = listener.accept().await else {
            continue;
        };
        let accept_fut = acceptor.accept(stream);

        let stream = match timeout(Duration::from_millis(250), accept_fut).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(err)) => {
                eprintln!("refused TLS connection (handshake): {err}");
                continue;
            }
            Err(err) => {
                eprintln!("refused TLS connection (elapsed): {err}");
                continue;
            }
        };

        let (mut read, _write) = split(stream);
        let mut buf: [u8; 1] = [0];
        while let Ok(_) = read.read_exact(&mut buf).await {
            store.send_modify(|store| store.push(buf[0]));
        }
    }
}

#[tokio::test]
async fn connect_to_mtls_without_client_cert() {
    let (client, port, mut store) = spawn_collector().await;
    let tls_connector = TlsConnector::from(Arc::new(client));

    let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let mut tls = tls_connector
        .connect(ServerName::try_from("foobar.com".to_string()).unwrap(), tcp)
        .await
        .unwrap(); // I'd expect to fail the test here

    tls.write(b"123").await.unwrap();

    let wait_for = store.wait_for(|store| store.len() >= 3);
    timeout(Duration::from_millis(500), wait_for)
        .await
        .unwrap()
        .unwrap();
    let received = store.borrow_and_update();
    assert_eq!(&[b'1', b'2', b'3'], received.as_slice());
}
