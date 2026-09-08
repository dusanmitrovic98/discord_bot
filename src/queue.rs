use crate::{AegisError, Result};
use reqwest::{multipart, Client};
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::sleep;
use tracing::{info, warn};

#[derive(Debug, Deserialize)]
pub struct ClassifierConfidence {
    pub safe: f64,
    pub nsfw: f64,
}

#[derive(Debug, Deserialize)]
pub struct ClassifierResponse {
    pub status: String,
    pub is_safe: bool,
    pub processing_time: String,
    pub confidence: ClassifierConfidence,
}

#[derive(Debug)]
pub struct ScanTask {
    pub user_id: u64,
    pub guild_id: u64,
    pub image_url: String,
    pub image_bytes: Vec<u8>,
    pub response_tx: tokio::sync::oneshot::Sender<Result<ClassifierResponse>>,
}

#[derive(Clone)]
pub struct ResilientClassifierClient {
    client: Client,
    endpoint: String,
}

impl ResilientClassifierClient {
    pub fn new(endpoint: String) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(45)) // Render free-tier cold-start latency buffer
            .pool_idle_timeout(Duration::from_secs(60))
            .build()
            .expect("Reqwest HTTP client must initialize");

        Self { client, endpoint }
    }

    /// Single request invocation with retry backoff for cold starts.
    pub async fn classify_image(&self, image_bytes: Vec<u8>) -> Result<ClassifierResponse> {
        let mut retries = 3;
        let mut backoff = Duration::from_millis(1500);

        loop {
            let part = multipart::Part::bytes(image_bytes.clone())
                .file_name("image.jpg")
                .mime_str("image/jpeg")
                .map_err(|e| AegisError::SupervisorError(e.to_string()))?;

            let form = multipart::Form::new().part("file", part);

            match self
                .client
                .post(&self.endpoint)
                .multipart(form)
                .send()
                .await
            {
                Ok(resp) if resp.status().is_success() => {
                    let parsed = resp.json::<ClassifierResponse>().await?;
                    return Ok(parsed);
                }
                Ok(resp) => {
                    warn!("Classifier returned status {}. Retrying...", resp.status());
                }
                Err(err) => {
                    warn!(
                        "Failed contacting classifier API (Cold start?): {}. Retries left: {}",
                        err, retries
                    );
                }
            }

            if retries == 0 {
                return Err(AegisError::SupervisorError(
                    "Exhausted retries connecting to SFW Classifier API".into(),
                ));
            }

            retries -= 1;
            sleep(backoff).await;
            backoff *= 2; // Exponential backoff
        }
    }

    /// Background Keep-Alive pinger to mitigate Render's 15-minute sleep state.
    pub fn spawn_keep_alive(self: Arc<Self>) {
        tokio::spawn(async move {
            loop {
                sleep(Duration::from_secs(600)).await; // Every 10 minutes
                let _ = self
                    .client
                    .get(&self.endpoint.replace("/api/classify", "/"))
                    .send()
                    .await;
                info!("Dispatched keep-alive ping to SFW Classifier on Render");
            }
        });
    }
}

/// Bounded MPSC Queue to enforce sequential execution and protect the 512MB RAM single core on Render.
pub struct BoundedScanQueue {
    sender: mpsc::Sender<ScanTask>,
}

impl BoundedScanQueue {
    pub fn new(capacity: usize, client: Arc<ResilientClassifierClient>) -> Self {
        // Strict upper limit (NASA Rule 2)
        let (tx, mut rx) = mpsc::channel::<ScanTask>(capacity);

        // Single consumer task guarantees strictly 1 request at a time to Render
        tokio::spawn(async move {
            info!("Bounded Scan Worker initialized. Concurrency locked to 1.");
            while let Some(task) = rx.recv().await {
                let outcome = client.classify_image(task.image_bytes).await;
                let _ = task.response_tx.send(outcome);
            }
        });

        Self { sender: tx }
    }

    pub async fn submit(&self, task: ScanTask) -> Result<()> {
        self.sender
            .try_send(task)
            .map_err(|_| AegisError::QueueSaturated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_bounded_queue_saturation_protection() {
        let client = Arc::new(ResilientClassifierClient::new("http://127.0.0.1:9".into()));
        // Capacity strictly capped at 2
        let queue = BoundedScanQueue::new(2, client);

        for _ in 0..2 {
            let (tx, _rx) = tokio::sync::oneshot::channel();
            let task = ScanTask {
                user_id: 1,
                guild_id: 1,
                image_url: "".into(),
                image_bytes: vec![0u8; 10],
                response_tx: tx,
            };
            assert!(queue.submit(task).await.is_ok());
        }

        // 3rd item must fail immediately, preventing memory leaks
        let (tx, _rx) = tokio::sync::oneshot::channel();
        let overflow_task = ScanTask {
            user_id: 2,
            guild_id: 1,
            image_url: "".into(),
            image_bytes: vec![0u8; 10],
            response_tx: tx,
        };
        assert!(matches!(
            queue.submit(overflow_task).await,
            Err(AegisError::QueueSaturated)
        ));
    }
}
