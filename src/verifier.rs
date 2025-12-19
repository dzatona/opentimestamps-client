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
            server: server
                .unwrap_or_else(|| "tcp://electrum.blockstream.info:50001".to_string()),
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

        Ok(BlockHeader {
            merkle_root,
            time: header.time,
        })
    }
}
