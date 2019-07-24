#![feature(async_await, bind_by_move_pattern_guards)]
#![deny(unsafe_code)]
#![warn(
    missing_docs,
    nonstandard_style,
    rust_2018_idioms,
    future_incompatible,
    missing_debug_implementations
)]

//! An asynchronous library for discovering, notifying and subscibing to devices and services on a network.
//!
//! SSDP stands for Simple Service Discovery Protocol and it is a protocol that
//! distributes messages across a local network for devices and services to
//! discover each other. SSDP can most commonly be found in devices that implement
//! `UPnP` as it is used as the discovery mechanism for that standard.

/// SSDP Error types
pub mod error;
/// Methods and structs for dealing with searching devices
pub mod search;
/// Methods and structs for dealing with subscribing to devices
pub mod subscribe;

pub use error::Error;
pub use search::{search, SearchTarget};
pub use subscribe::subscribe;

#[macro_export]
#[doc(hidden)]
macro_rules! parse_headers {
    ( $response:expr => $($header:ident),+ ) => { {
        let mut response = $response.split("\r\n");
        if let Some(status) = response.next() {
            let status = status.trim_start_matches("HTTP/1.1 ");
            let status_code = status.chars().take_while(|x| x.is_numeric())
                .collect::<String>().parse::<u32>().map_err(|_| crate::Error::ParseHTTPError)?;
            if status_code != 200 {
                return Err(crate::Error::HTTPError(status_code));
            }
        } else {
            return Err(crate::Error::ParseHTTPError);
        }
        let headers = response.filter_map(|l| {
            let mut split = l.splitn(2, ':');
            match (split.next(), split.next()) {
                (Some(header), Some(value)) => Some((header, value.trim())),
                _ => None,
            }
        });
        $(let mut $header: Option<&str> = None;)*

        for (header, value) in headers {
            $(if header.eq_ignore_ascii_case(stringify!($header)) {
                $header = Some(value);
            })else*
        }

        ($($header.ok_or(crate::Error::MissingHeader(stringify!($header)))?),*)
    } }
}
