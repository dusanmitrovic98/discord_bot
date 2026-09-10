pub mod bot;
pub mod config;
pub mod crypto;
pub mod db;
pub mod gatekeeper;
pub mod media;
pub mod pipeline;
pub mod plugin_engine;
pub mod queue;
pub mod supervisor;
pub mod web;
pub mod whitelist;

use thiserror::Error;

#[derive(Error, Debug)]
pub enum AegisError {
    #[error("Cryptographic verification failed: {0}")]
    CryptoError(String),

    #[error("Database error: {0}")]
    DatabaseError(#[from] mongodb::error::Error),

    #[error("Network/Classifier error: {0}")]
    NetworkError(#[from] reqwest::Error),

    #[error("Supervisor error: {0}")]
    SupervisorError(String),

    #[error("Plugin engine error: {0}")]
    PluginError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Payload rejected: size exceeds maximum bound of {0} bytes")]
    PayloadTooLarge(usize),

    #[error("Queue saturation / backpressure drop")]
    QueueSaturated,

    #[error("Regular expression validation failed: {0}")]
    RegexError(#[from] regex::Error),
}

pub type Result<T> = std::result::Result<T, AegisError>;
