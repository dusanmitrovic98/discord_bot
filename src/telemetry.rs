//! # In-Memory Real-Time Telemetry & Log Buffer
//!
//! Provides a thread-safe circular ring buffer (max 500 lines) capturing live
//! application logs from both the supervisor and the piped child bot core.

use serde::Serialize;
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

#[derive(Clone, Debug, Serialize)]
pub struct LiveLogEntry {
    pub timestamp: String,
    pub level: String,
    pub target: String,
    pub message: String,
}

#[derive(Clone)]
pub struct LogBuffer {
    buffer: Arc<RwLock<VecDeque<LiveLogEntry>>>,
    max_capacity: usize,
}

impl LogBuffer {
    pub fn new(max_capacity: usize) -> Self {
        Self {
            buffer: Arc::new(RwLock::new(VecDeque::with_capacity(max_capacity))),
            max_capacity,
        }
    }

    pub fn get_entries(&self) -> Vec<LiveLogEntry> {
        let guard = self.buffer.read().unwrap();
        guard.iter().cloned().collect()
    }

    pub fn push(&self, entry: LiveLogEntry) {
        let mut guard = self.buffer.write().unwrap();
        if guard.len() >= self.max_capacity {
            guard.pop_front();
        }
        guard.push_back(entry);
    }

    /// Parses raw stdout lines from the child core process and ingests them into the live buffer
    pub fn push_raw_line(&self, raw: &str) {
        let now = chrono::Utc::now().to_rfc3339();
        let mut level = "INFO";
        if raw.contains("ERROR") {
            level = "ERROR";
        } else if raw.contains("WARN") {
            level = "WARN";
        } else if raw.contains("DEBUG") {
            level = "DEBUG";
        }

        let mut target = "bot_core";
        if let Some(start) = raw.find("aegis_bastion::") {
            if let Some(end) = raw[start..].find(':') {
                target = &raw[start..start + end];
            }
        }

        self.push(LiveLogEntry {
            timestamp: now,
            level: level.to_string(),
            target: target.to_string(),
            message: raw.to_string(),
        });
    }
}

struct MessageVisitor(String);

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{:?}", value).trim_matches('"').to_string();
        } else if self.0.is_empty() {
            self.0 = format!("{}={:?}", field.name(), value);
        } else {
            self.0.push_str(&format!(" {}={:?}", field.name(), value));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.0 = value.to_string();
        } else {
            self.0.push_str(&format!(" {}={}", field.name(), value));
        }
    }
}

impl<S: Subscriber> Layer<S> for LogBuffer {
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = MessageVisitor(String::new());
        event.record(&mut visitor);

        let metadata = event.metadata();
        let level_str = match *metadata.level() {
            Level::ERROR => "ERROR",
            Level::WARN => "WARN",
            Level::INFO => "INFO",
            Level::DEBUG => "DEBUG",
            Level::TRACE => "TRACE",
        };

        let now = chrono::Utc::now().to_rfc3339();
        self.push(LiveLogEntry {
            timestamp: now,
            level: level_str.to_string(),
            target: metadata.target().to_string(),
            message: visitor.0,
        });
    }
}
