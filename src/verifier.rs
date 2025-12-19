use crate::error::{Error, Result};
use async_trait::async_trait;

/// Block header information needed for timestamp verification
pub struct BlockHeader {
    /// Merkle root of the block
    pub merkle_root: [u8; 32],
    /// Block timestamp (Unix epoch)
    pub time: u32,
}

/// Trait for Bitcoin block verification backends
///
/// Implementations provide access to Bitcoin blockchain data
/// required for verifying `OpenTimestamps` proofs.
#[async_trait]
pub trait BlockVerifier: Send + Sync {
    /// Fetch block header at specified height
    ///
    /// # Arguments
    /// * `height` - Block height to fetch
    ///
    /// # Errors
    /// Returns error if block cannot be fetched or parsed
    async fn get_block_header(&self, height: u32) -> Result<BlockHeader>;
}

/// Electrum-based block verifier (default backend)
///
/// Uses Electrum protocol to verify timestamps against Bitcoin blockchain.
#[cfg(feature = "electrum")]
pub struct ElectrumVerifier {
    server: String,
}

#[cfg(feature = "electrum")]
impl ElectrumVerifier {
    /// Create new Electrum verifier
    ///
    /// # Arguments
    /// * `server` - Optional Electrum server URL. Defaults to Blockstream's public server.
    ///
    /// # Example
    /// ```rust,ignore
    /// let verifier = ElectrumVerifier::new(None); // Use default
    /// let verifier = ElectrumVerifier::new(Some("tcp://localhost:50001".to_string())); // Custom
    /// ```
    #[must_use]
    pub fn new(server: Option<String>) -> Self {
        Self {
            server: server.unwrap_or_else(|| "tcp://electrum.blockstream.info:50001".to_string()),
        }
    }
}

#[cfg(feature = "electrum")]
#[async_trait]
impl BlockVerifier for ElectrumVerifier {
    async fn get_block_header(&self, height: u32) -> Result<BlockHeader> {
        use electrum_client::ElectrumApi;

        // electrum-client is synchronous, wrap in spawn_blocking for async context
        let server = self.server.clone();
        let header = tokio::task::spawn_blocking(move || {
            let client = electrum_client::Client::new(&server)
                .map_err(|e| Error::Verification(format!("Failed to connect to Electrum: {e}")))?;

            client
                .block_header(height as usize)
                .map_err(|e| Error::Verification(format!("Failed to fetch block header: {e}")))
        })
        .await
        .map_err(|e| Error::Verification(format!("Task join error: {e}")))??;

        // Convert merkle root to byte array
        // Bitcoin displays hashes in reverse (little-endian display, internal big-endian)
        let merkle_root_bytes = header.merkle_root.to_string();
        let mut merkle_root = [0u8; 32];

        // Parse hex string to bytes
        hex::decode_to_slice(merkle_root_bytes.as_bytes(), &mut merkle_root)
            .map_err(|e| Error::Verification(format!("Failed to decode merkle root: {e}")))?;

        // Reverse bytes for internal representation (Bitcoin internal byte order)
        merkle_root.reverse();

        Ok(BlockHeader { merkle_root, time: header.time })
    }
}

/// Esplora-based block verifier
///
/// Uses Esplora HTTP API to verify timestamps against Bitcoin blockchain.
#[cfg(feature = "esplora")]
#[allow(dead_code)]
pub struct EsploraVerifier {
    client: esplora_client::r#async::AsyncClient<esplora_client::r#async::DefaultSleeper>,
}

#[cfg(feature = "esplora")]
#[allow(dead_code)]
impl EsploraVerifier {
    /// Create new Esplora verifier
    ///
    /// # Arguments
    /// * `url` - Optional Esplora server URL. Defaults to Blockstream's public API.
    ///
    /// # Example
    /// ```rust,ignore
    /// let verifier = EsploraVerifier::new(None); // Use default
    /// let verifier = EsploraVerifier::new(Some("https://blockstream.info/api".to_string())); // Custom
    /// ```
    ///
    /// # Errors
    /// Returns error if client cannot be created
    pub fn new(url: Option<String>) -> Result<Self> {
        let base_url = url.unwrap_or_else(|| "https://blockstream.info/api".to_string());
        let builder = esplora_client::Builder::new(&base_url);
        let client = esplora_client::r#async::AsyncClient::from_builder(builder)
            .map_err(|e| Error::Verification(format!("Failed to create Esplora client: {e}")))?;
        Ok(Self { client })
    }
}

#[cfg(feature = "esplora")]
#[async_trait]
impl BlockVerifier for EsploraVerifier {
    async fn get_block_header(&self, height: u32) -> Result<BlockHeader> {
        use bitcoin_hashes::Hash;

        // Get block hash at height
        let block_hash = self
            .client
            .get_block_hash(height)
            .await
            .map_err(|e| Error::Verification(format!("Failed to fetch block hash: {e}")))?;

        // Get block header
        let header = self
            .client
            .get_header_by_hash(&block_hash)
            .await
            .map_err(|e| Error::Verification(format!("Failed to fetch block header: {e}")))?;

        // Extract merkle root bytes
        let merkle_root = *header.merkle_root.as_byte_array();

        Ok(BlockHeader { merkle_root, time: header.time })
    }
}

/// Bitcoin Core RPC-based block verifier
///
/// Uses Bitcoin Core RPC to verify timestamps against local Bitcoin node.
#[cfg(feature = "rpc")]
#[allow(dead_code)]
pub struct RpcVerifier {
    url: String,
    user: Option<String>,
    password: Option<String>,
}

#[cfg(feature = "rpc")]
#[allow(dead_code)]
impl RpcVerifier {
    /// Create new RPC verifier
    ///
    /// # Arguments
    /// * `url` - Optional Bitcoin Core RPC URL. Defaults to localhost:8332.
    /// * `user` - Optional RPC username
    /// * `password` - Optional RPC password
    ///
    /// # Example
    /// ```rust,ignore
    /// let verifier = RpcVerifier::new(None, None, None); // Use defaults
    /// let verifier = RpcVerifier::new(
    ///     Some("http://localhost:8332".to_string()),
    ///     Some("user".to_string()),
    ///     Some("pass".to_string())
    /// );
    /// ```
    #[must_use]
    pub fn new(url: Option<String>, user: Option<String>, password: Option<String>) -> Self {
        Self { url: url.unwrap_or_else(|| "http://localhost:8332".to_string()), user, password }
    }
}

#[cfg(feature = "rpc")]
#[async_trait]
impl BlockVerifier for RpcVerifier {
    async fn get_block_header(&self, height: u32) -> Result<BlockHeader> {
        use bitcoin_hashes::Hash;
        use bitcoincore_rpc::{Auth, Client, RpcApi};

        // bitcoincore-rpc is synchronous, wrap in spawn_blocking for async context
        let url = self.url.clone();
        let auth = match (&self.user, &self.password) {
            (Some(u), Some(p)) => Auth::UserPass(u.clone(), p.clone()),
            _ => Auth::None,
        };

        let header = tokio::task::spawn_blocking(move || {
            let client = Client::new(&url, auth).map_err(|e| {
                Error::Verification(format!("Failed to connect to Bitcoin Core RPC: {e}"))
            })?;

            // Get block hash at height
            let block_hash = client
                .get_block_hash(height as u64)
                .map_err(|e| Error::Verification(format!("Failed to fetch block hash: {e}")))?;

            // Get block header
            let header = client
                .get_block_header(&block_hash)
                .map_err(|e| Error::Verification(format!("Failed to fetch block header: {e}")))?;

            Ok::<_, Error>((header.merkle_root, header.time))
        })
        .await
        .map_err(|e| Error::Verification(format!("Task join error: {e}")))?;

        let (merkle_root, time) = header?;

        Ok(BlockHeader { merkle_root: *merkle_root.as_byte_array(), time })
    }
}
