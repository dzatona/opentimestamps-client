#![allow(clippy::multiple_crate_versions)]

pub mod calendar;
pub mod error;
// Future modules (commented for now):
// pub mod verifier;
// pub mod commands;

pub use calendar::{CalendarClient, DEFAULT_CALENDARS};
pub use error::{Error, Result};
