use crate::error::{Error, Result};
use log::{debug, info};
use reqwest::Client;
use std::time::Duration;

/// Default calendar servers for `OpenTimestamps`
pub const DEFAULT_CALENDARS: &[&str] = &[
    "https://a.pool.opentimestamps.org",
    "https://b.pool.opentimestamps.org",
    "https://a.pool.eternitywall.com",
];

/// HTTP client for interacting with `OpenTimestamps` calendar servers
///
/// Calendar servers accept SHA256 digests and return pending attestations
/// that can later be upgraded to Bitcoin-confirmed attestations.
pub struct CalendarClient {
    client: Client,
}

impl CalendarClient {
    /// Create a new calendar client with specified timeout
    ///
    /// # Arguments
    ///
    /// * `timeout` - Maximum time to wait for HTTP requests
    ///
    /// # Errors
    ///
    /// Returns error if the HTTP client cannot be initialized
    pub fn new(timeout: Duration) -> Result<Self> {
        let client = Client::builder()
            .timeout(timeout)
            .user_agent("rust-opentimestamps-client/0.1.0")
            .build()?;

        Ok(Self { client })
    }

    /// Submit a digest to a calendar server
    ///
    /// Sends a POST request to `{calendar_url}/digest` with the raw 32-byte
    /// SHA256 digest as the request body.
    ///
    /// # Arguments
    ///
    /// * `calendar_url` - Base URL of the calendar server
    /// * `digest` - 32-byte SHA256 digest to timestamp
    ///
    /// # Returns
    ///
    /// Raw binary timestamp response bytes containing the pending attestation
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - HTTP request fails
    /// - Server returns non-success status code
    /// - Response body cannot be read
    pub async fn submit(&self, calendar_url: &str, digest: &[u8]) -> Result<Vec<u8>> {
        let url = format!("{calendar_url}/digest");
        debug!("Submitting digest to {url}");

        let response = self
            .client
            .post(&url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(digest.to_vec())
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(Error::Calendar(format!(
                "Calendar {} returned status {}",
                calendar_url,
                response.status()
            )));
        }

        let bytes = response.bytes().await?;
        info!("Received {} bytes from {}", bytes.len(), calendar_url);

        Ok(bytes.to_vec())
    }

    /// Get a completed timestamp for a commitment
    ///
    /// Used during the upgrade process to fetch a Bitcoin-confirmed attestation
    /// for a previously submitted commitment.
    ///
    /// Sends a GET request to `{calendar_url}/timestamp/{hex_commitment}`.
    ///
    /// # Arguments
    ///
    /// * `calendar_url` - Base URL of the calendar server
    /// * `commitment` - The commitment hash to query
    ///
    /// # Returns
    ///
    /// - `Ok(Some(bytes))` - Timestamp data if available
    /// - `Ok(None)` - Timestamp not yet available (still pending)
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - HTTP request fails
    /// - Server returns error status (other than 404)
    /// - Response body cannot be read
    pub async fn get_timestamp(
        &self,
        calendar_url: &str,
        commitment: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        let hex_commitment = hex::encode(commitment);
        let url = format!("{calendar_url}/timestamp/{hex_commitment}");
        debug!("Fetching timestamp from {url}");

        let response = self.client.get(&url).send().await?;

        if response.status() == reqwest::StatusCode::NOT_FOUND {
            debug!("Timestamp not yet available at {calendar_url}");
            return Ok(None);
        }

        if !response.status().is_success() {
            return Err(Error::Calendar(format!(
                "Calendar {} returned status {}",
                calendar_url,
                response.status()
            )));
        }

        let bytes = response.bytes().await?;
        info!("Received {} bytes from {}", bytes.len(), calendar_url);

        Ok(Some(bytes.to_vec()))
    }

    /// Submit digest to multiple calendars, return first successful response
    ///
    /// Tries each calendar in sequence until one succeeds. If `calendar_urls`
    /// is empty, uses `DEFAULT_CALENDARS`.
    ///
    /// # Arguments
    ///
    /// * `calendar_urls` - List of calendar server URLs to try
    /// * `digest` - 32-byte SHA256 digest to timestamp
    ///
    /// # Returns
    ///
    /// Raw binary timestamp response bytes from the first successful calendar
    ///
    /// # Errors
    ///
    /// Returns error if all calendars fail. The error from the last calendar
    /// attempt is returned.
    pub async fn submit_to_calendars(
        &self,
        calendar_urls: &[String],
        digest: &[u8],
    ) -> Result<Vec<u8>> {
        let urls: Vec<&str> = if calendar_urls.is_empty() {
            DEFAULT_CALENDARS.to_vec()
        } else {
            calendar_urls.iter().map(String::as_str).collect()
        };

        let mut last_error = None;

        for url in &urls {
            info!("Submitting to calendar {url}");
            match self.submit(url, digest).await {
                Ok(response) => return Ok(response),
                Err(e) => {
                    log::warn!("Calendar {url} failed: {e}");
                    last_error = Some(e);
                }
            }
        }

        Err(last_error.unwrap_or_else(|| Error::Calendar("No calendars available".into())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_calendars_not_empty() {
        assert_eq!(DEFAULT_CALENDARS.len(), 3);
    }

    #[test]
    fn test_calendar_client_creation() {
        let timeout = Duration::from_secs(10);
        let client = CalendarClient::new(timeout);
        assert!(client.is_ok());
    }

    #[test]
    fn test_hex_encoding() {
        let commitment = vec![0u8; 32];
        let hex = hex::encode(&commitment);
        assert_eq!(hex.len(), 64);
        assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    }
}
