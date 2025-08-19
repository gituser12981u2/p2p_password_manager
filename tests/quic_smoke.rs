use p2p_password_manager::node::Node;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::time::timeout;

#[tokio::test(flavor = "current_thread")]
async fn quic_roundtrip_smoke() -> Result<(), Box<dyn std::error::Error>> {
    let a_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let b_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    let a = Node::new(a_addr).await?;
    let b = Node::new(b_addr).await?;

    // Start a minimal accept loop on node B (echo server)
    let ep = b.endpoint().clone(); // Endpoint is Clone
    let _echo = tokio::spawn(async move {
        // Accept connections one by one
        while let Some(connecting) = ep.accept().await {
            tokio::spawn(async move {
                match connecting.await {
                    Ok(conn) => {
                        // Handle BiDi streams
                        while let Ok(Some((mut send, mut recv))) = conn.accept_bi().await.map(Some)
                        {
                            if let Ok(msg) = recv.read_to_end(64 * 1024).await {
                                let _ = send.write_all(&msg).await;
                                let _ = send.finish();
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Connection error: {}", e);
                    }
                }
            });
        }
    });

    // A connects to B
    let conn = a.connect_to(b.local_address(), b.certificate_der()).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let payload = b"hello over quic";
    send.write_all(payload).await?;
    send.finish()?;
    let echoed = timeout(Duration::from_secs(3), recv.read_to_end(64 * 1024)).await??;
    assert_eq!(&echoed[..], payload);

    Ok(())
}
