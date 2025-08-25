use p2p_password_manager::node::Node;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    time::Duration,
};
use tokio::time::timeout;

#[tokio::test(flavor = "current_thread")]
async fn quic_roundtrip_smoke() -> anyhow::Result<()> {
    let a_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
    let b_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

    let a = Node::new(a_addr).await?;
    let b = Node::new(b_addr).await?;
    b.spawn_echo_server();

    let conn = a.connect_to_spki(b.local_address(), b.spki_pin()).await?;
    let (mut send, mut recv) = conn.open_bi().await?;
    let payload = b"hello over quic";
    send.write_all(payload).await?;
    send.finish()?;
    let echoed = timeout(Duration::from_secs(3), recv.read_to_end(64 * 1024)).await??;
    assert_eq!(&echoed[..], payload);

    Ok(())
}
