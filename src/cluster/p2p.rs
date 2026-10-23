//! # Peer-to-Peer Liveness Gossip & Health Sentry
//!
//! Conducts direct randomized HTTPS probes (45-75s) to the leader's `/health/liveness`.
//! Upon 3 consecutive failures (5s socket timeout), triggers Fast-Path failover.

use rand::Rng;
use reqwest::Client;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, warn};

use crate::cluster::lease::LeaseManager;

pub static IS_GATEWAY_HEALTHY: AtomicBool = AtomicBool::new(false);

pub struct P2pLivenessSentry {
    client: Client,
    lease_mgr: Arc<LeaseManager>,
}

impl P2pLivenessSentry {
    pub fn new(lease_mgr: Arc<LeaseManager>) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(5))
            .connect_timeout(Duration::from_secs(3))
            .pool_idle_timeout(Duration::from_secs(30))
            .build()
            .expect("Reqwest P2P client initialization failed");

        Self { client, lease_mgr }
    }

    /// Computes randomized probe jitter (45s to 75s) to prevent thundering herds.
    pub fn calculate_jittered_interval() -> Duration {
        let mut rng = rand::thread_rng();
        let secs = rng.gen_range(45..=75);
        Duration::from_secs(secs)
    }

    /// Single probe invocation against target URL.
    pub async fn probe_endpoint(&self, target_url: &str) -> bool {
        let endpoint = format!("{}/health/liveness", target_url.trim_end_matches('/'));
        match self.client.get(&endpoint).send().await {
            Ok(resp) => resp.status().is_success(),
            Err(e) => {
                warn!("Liveness probe failed for {}: {}", endpoint, e);
                false
            }
        }
    }

    /// Standby probe supervisor: checks leader health, triggers fast-path takeover on 3 strikes.
    pub async fn supervise_leader(&self, dead_leader_tx: tokio::sync::mpsc::Sender<String>) {
        let mut consecutive_failures = 0;

        loop {
            tokio::time::sleep(Self::calculate_jittered_interval()).await;

            let lease = match self.lease_mgr.fetch_current_lease().await {
                Ok(Some(l)) => l,
                _ => continue,
            };

            // If we are already the leader, standby probes are not needed
            if lease.leader_id == self.lease_mgr.instance_id() {
                consecutive_failures = 0;
                continue;
            }

            if lease.leader_url.is_empty() {
                continue;
            }

            if self.probe_endpoint(&lease.leader_url).await {
                consecutive_failures = 0;
            } else {
                consecutive_failures += 1;
                warn!(
                    "⚠️ [P2P WARNING] Leader '{}' failed {} probe(s)",
                    lease.leader_id, consecutive_failures
                );

                if consecutive_failures >= 3 {
                    error!(
                        "🚨 [P2P CRITICAL] Leader '{}' confirmed DEAD after 3 probes! Initiating Fast-Path...",
                        lease.leader_id
                    );
                    let _ = dead_leader_tx.send(lease.leader_id.clone()).await;
                    consecutive_failures = 0;
                }
            }
        }
    }
}
