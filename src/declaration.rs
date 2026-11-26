//! What a Location of this technology is configured with: its declaration,
//! which `Configured` reads, built with the crate's `declaration` feature
//! alone and the code behind the default (ADR-0064, amendments 2026-10-22
//! and 2026-11-26), for the library the surfaces load to carry (open
//! problem 48).

use xcore::settings::{Applies, Kind, Presence, Setting, Settings};

/// Every setting a Location takes beyond its address, where a Receive
/// Location listens as the outstation — `0.0.0.0:20000` the standard port;
/// a Send Location connects as the master to the target its route gives.
pub const SETTINGS: &Settings = &Settings {
    technology: env!("CARGO_PKG_NAME"),
    settings: &[
        Setting {
            name: "source",
            kind: Kind::Integer {
                minimum: 0,
                maximum: 65_535,
            },
            presence: Presence::Required,
            meaning: "The master's own link address, which its frames come from.",
            applies: Applies::Send,
        },
        Setting {
            name: "destination",
            kind: Kind::Integer {
                minimum: 0,
                maximum: 65_535,
            },
            presence: Presence::Required,
            meaning: "The outstation's link address, which the master's frames go to.",
            applies: Applies::Send,
        },
        transport::configured::timeout(
            Applies::Both,
            None,
            "How long a peer that stops mid-frame is waited on; unbounded when \
             left out.",
        ),
    ],
};

/// The schemes a Location's address is entered with to choose this technology.
pub const SCHEMES: &[&str] = &["dnp3"];
