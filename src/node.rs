use ed25519_dalek::{
    Signature as Ed25519Signature, SigningKey, VerifyingKey, VerifyingKey as Ed25519VerifyingKey,
    pkcs8::EncodePrivateKey,
};
use quinn::crypto::rustls::QuicClientConfig;
use quinn::{ClientConfig, Endpoint, ServerConfig, TransportConfig};
use rcgen::string::Ia5String;
use rcgen::{Certificate as RcgenCert, CertificateParams, KeyPair, SanType};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::{Error as RustlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use std::{collections::HashMap, net::SocketAddr, sync::Arc};
use tokio::sync::RwLock;
use x509_parser::prelude::FromDer;
use x509_parser::prelude::X509Certificate;

/// Represents a peer node in the P2P network
pub struct PeerInfo {
    /// Ed25519 public key for peer identification
    pub public_key: VerifyingKey,
    /// Last known socket address of the peer
    pub address: Option<SocketAddr>,
    /// Optional metadata about the peer (device name, etc.)
    pub metadata: HashMap<String, String>,
}

/// Main node structure
pub struct Node {
    #[allow(dead_code)]
    /// Ed25519 signing key for this node: private key
    signing_key: SigningKey,

    /// Ed25519 verifying key for this node: public key
    pub verifying_key: VerifyingKey,

    /// QUIC endpoint for both client and server connections
    endpoint: Endpoint,

    /// Connected peers mapped by their public keys
    peers: Arc<RwLock<HashMap<VerifyingKey, PeerInfo>>>,

    /// Node's self-signed certificate in DER format
    cert_der: Vec<u8>,

    /// Node's listening address
    local_addr: SocketAddr,
}

impl Node {
    /// Creates a new node with a generated Ed25519 key pair
    // TODO: Discuss switching from ring to aws-lc-rs
    pub async fn new(bind_addr: SocketAddr) -> Result<Self, Box<dyn std::error::Error>> {
        // Generate Ed25519 key pair
        let mut csprng = rand::rngs::OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();

        // Initialize QUIC endpoint
        let (endpoint, cert_der) =
            Self::create_endpoint(bind_addr, &signing_key, &verifying_key).await?;
        let local_addr = endpoint.local_addr()?;

        Ok(Node {
            signing_key,
            verifying_key,
            endpoint,
            peers: Arc::new(RwLock::new(HashMap::new())),
            cert_der,
            local_addr,
        })
    }

    pub async fn connect_to(
        &self,
        peer_addr: SocketAddr,
        peer_cert_der: &[u8],
    ) -> Result<quinn::Connection, Box<dyn std::error::Error>> {
        // Compute the expected SPKI pin from the peer's certificate
        let pin = spki_sha256_ed25519(peer_cert_der)
            .map_err(|e| format!("Failed to compute SPKI pin: {}", e))?;
        let verifier = Arc::new(SpkiPinVerifier {
            expected_spki_sha256: pin,
        });

        let tls = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();

        let crypto = QuicClientConfig::try_from(Arc::new(tls))?;
        let client_config = ClientConfig::new(Arc::new(crypto));
        let connecting = self
            .endpoint
            .connect_with(client_config, peer_addr, "p2p")?;
        Ok(connecting.await?)
    }

    /// Creates and configures a QUIC endpoint
    async fn create_endpoint(
        bind_addr: SocketAddr,
        signing_key: &SigningKey,
        verifying_key: &VerifyingKey,
    ) -> Result<(Endpoint, Vec<u8>), Box<dyn std::error::Error>> {
        // Export ed25519_dalek key pair to PKCS#8 DER
        let pkcs8_doc = signing_key.to_pkcs8_der()?; // SecretDocument (zeroizes on drop)

        // Build rcgen KeyPair from that PKCS#8
        let pkcs8_der = PrivatePkcs8KeyDer::from(pkcs8_doc.as_bytes().to_vec());
        let key_pair = KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_der, &rcgen::PKCS_ED25519)?;

        // Generate self-signed certificate for QUIC
        let mut params = CertificateParams::default();

        // Put pubkey in to CN
        let vk_hex = hex::encode(verifying_key.as_bytes());
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, vk_hex);

        // Add DNS SAN
        params
            .subject_alt_names
            .push(SanType::DnsName(Ia5String::try_from("p2p")?));

        // Server config
        let cert: RcgenCert = params.self_signed(&key_pair)?;
        let cert_der: CertificateDer<'static> = CertificateDer::from(cert.der().to_vec());

        // Rustls private key (same as PKCS#8 DER)
        let key_der: PrivateKeyDer<'static> = pkcs8_der.into(); // convert to PrivateKeyDer

        let mut server_config = ServerConfig::with_single_cert(vec![cert_der.clone()], key_der)?;

        let mut transport_config = TransportConfig::default();
        transport_config.max_concurrent_uni_streams(0_u8.into());
        transport_config.max_concurrent_bidi_streams(100_u8.into());
        server_config.transport = Arc::new(transport_config);

        // Pin cert
        let roots = rustls::RootCertStore::empty();
        let tls_default = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();

        let crypto_default = QuicClientConfig::try_from(Arc::new(tls_default))?;
        let client_config = ClientConfig::new(Arc::new(crypto_default));

        // TODO: Add custom ALPN

        let mut endpoint = Endpoint::server(server_config, bind_addr)?;
        endpoint.set_default_client_config(client_config);

        Ok((endpoint, cert_der.as_ref().to_vec()))
    }

    /// Gets the node's public key
    pub fn public_key(&self) -> &VerifyingKey {
        &self.verifying_key
    }

    /// Gets the node's local address
    pub fn local_address(&self) -> SocketAddr {
        self.local_addr
    }

    /// Adds a peer to the node's peer list
    pub async fn add_peer(&self, peer_info: PeerInfo) {
        let mut peers = self.peers.write().await;
        peers.insert(peer_info.public_key, peer_info);
    }

    /// Removes a peer from the node's peer list
    pub async fn remove_peer(&self, public_key: &VerifyingKey) -> Option<PeerInfo> {
        let mut peers = self.peers.write().await;
        peers.remove(public_key)
    }

    /// Gets the QUIC endpoint
    pub fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    /// Gets the node's self-signed certificate in DER format
    pub fn certificate_der(&self) -> &[u8] {
        &self.cert_der
    }
}

/// Extract SPKI bytes from a DER certificate and SHA-256 hash it
fn spki_sha256_ed25519(
    cert_der: &[u8],
) -> Result<[u8; 32], Box<dyn std::error::Error + Send + Sync>> {
    let (_, cert) = X509Certificate::from_der(cert_der)
        .map_err(|e| format!("Failed to parse certificate: {}", e))?;

    let spki_der = cert.tbs_certificate.subject_pki.raw;

    let mut hasher = Sha256::new();
    hasher.update(spki_der);
    Ok(hasher.finalize().into())
}

#[derive(Debug)]
struct SpkiPinVerifier {
    expected_spki_sha256: [u8; 32],
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let presented = spki_sha256_ed25519(end_entity.as_ref())
            .map_err(|e| RustlsError::General(format!("spki parse/hash: {e}")))?;
        if presented == self.expected_spki_sha256 {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(RustlsError::General("SPKI pin mismatch".into()))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
        Err(RustlsError::General("TLS1.2 disabled".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, RustlsError> {
        if dss.scheme != SignatureScheme::ED25519 {
            return Err(RustlsError::General(
                "Only Ed25519 signatures are supported".into(),
            ));
        }

        // Extract Ed25519 public key bytes from cert SPKI and make it &[u8; 32]
        let (_, parsed) = X509Certificate::from_der(cert.as_ref())
            .map_err(|e| RustlsError::General(format!("x509 parse: {e}")))?;
        let pubkey_bytes_cow = parsed.tbs_certificate.subject_pki.subject_public_key.data;
        let pubkey_slice: &[u8] = &pubkey_bytes_cow;
        let pubkey_array: &[u8; 32] = pubkey_slice
            .try_into()
            .map_err(|_| RustlsError::General("Invalid Ed25519 public key length".into()))?;

        let vk = Ed25519VerifyingKey::from_bytes(pubkey_array)
            .map_err(|_| RustlsError::General("Invalid Ed25519 public key".into()))?;

        let sig = Ed25519Signature::try_from(dss.signature())
            .map_err(|_| RustlsError::General("Invalid Ed25519 signature".into()))?;

        vk.verify_strict(message, &sig)
            .map_err(|_| RustlsError::General("Ed25519 verify failed".into()))?;

        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}
