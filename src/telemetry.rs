//! # In-Memory Real-Time Telemetry & Log Buffer
//!
//! Provides a thread-safe circular ring buffer (max 500 lines) capturing live
//! application logs from both the supervisor and child core, with ANSI escape stripping.

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

    /// Strips ANSI escape sequences (e.g. [2m, [0m, [32m) from terminal streams
    fn strip_ansi(input: &str) -> String {
        let mut out = String::with_capacity(input.len());
        let mut in_escape = false;
        for c in input.chars() {
            if c == '\x1B' {
                in_escape = true;
            } else if in_escape {
                if c == 'm' || c == 'K' || c == 'H' || c == 'J' {
                    in_escape = false;
                }
            } else {
                out.push(c);
            }
        }
        out
    }

    /// Ingests raw stdout lines from child core process, strips ANSI codes, and extracts metadata
    pub fn push_raw_line(&self, raw: &str) {
        let clean = Self::strip_ansi(raw);
        let now = chrono::Utc::now().to_rfc3339();

        let mut level = "INFO";
        if clean.contains("ERROR") {
            level = "ERROR";
        } else if clean.contains("WARN") {
            level = "WARN";
        } else if clean.contains("DEBUG") {
            level = "DEBUG";
        }

        let mut target = "bot_core";
        if let Some(start) = clean.find("aegis_bastion::") {
            if let Some(end) = clean[start..].find(':') {
                target = &clean[start..start + end];
            }
        }

        self.push(LiveLogEntry {
            timestamp: now,
            level: level.to_string(),
            target: target.to_string(),
            message: clean,
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
        let clean_msg = LogBuffer::strip_ansi(&visitor.0);
        self.push(LiveLogEntry {
            timestamp: now,
            level: level_str.to_string(),
            target: metadata.target().to_string(),
            message: clean_msg,
        });
    }
}
