//! `glc-audit` — the offline integrity auditor (ADR-0014 §13.4).
//!
//! Re-verifies every stored commitment in a database using the same
//! recompute-and-compare logic the signing guards implement, and reports.
//!
//! # Run it against a snapshot, not the live database
//!
//! That is the point. The signing guards already protect the live path,
//! record by record, at signing time. What they cannot tell you is whether
//! the backup you would restore from is worth restoring — and answering that
//! is what makes an hourly snapshot a backup rather than a file.
//!
//! It opens the database **read-only** and writes nothing, so running it
//! against the live file is safe too; it just answers a less useful question.
//!
//! # Exit codes
//!
//! - `0` — checked, and everything agreed
//! - `1` — findings; the report names each one
//! - `2` — could not run (bad arguments, unreadable database)
//!
//! Distinct so a cron job can page on `1` and alert differently on `2`. An
//! audit that could not run is not a passing audit, and collapsing the two
//! would make a broken cron entry look like a clean bill of health.

use std::path::PathBuf;

use glc_relayer::glc::db::Db;
use glc_relayer::ops::audit;

const USAGE: &str = "glc-audit — offline integrity auditor

  glc-audit --db PATH [--quiet]

Re-verifies every frozen claim commitment and payout intent against the
fields they were computed from, plus SQLite's own PRAGMA integrity_check.
Read-only: it never writes, never halts a record, and is safe to run against
a backup on another host.

Exit 0 = clean, 1 = findings, 2 = could not run.";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.iter().any(|a| a == "-h" || a == "--help") {
        println!("{USAGE}");
        return;
    }
    let Some(db_path) = args
        .iter()
        .position(|a| a == "--db")
        .and_then(|i| args.get(i + 1))
    else {
        eprintln!("{USAGE}");
        std::process::exit(2);
    };
    let quiet = args.iter().any(|a| a == "--quiet");

    let db = match Db::open(&PathBuf::from(db_path)) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("could not open {db_path}: {e}");
            std::process::exit(2);
        }
    };

    let report = match audit::audit(&db) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("the audit could not complete: {e}");
            std::process::exit(2);
        }
    };

    if !quiet || !report.is_clean() {
        println!("{}", report.summary());
    }
    if report.is_clean() {
        // Say what was checked even on success. "Clean" over zero records is
        // a very different statement from "clean" over ten thousand, and an
        // operator reading a cron mail deserves to be able to tell them
        // apart.
        if !quiet {
            println!("\nclean");
        }
        return;
    }

    println!();
    for f in &report.findings {
        println!("FINDING: {f}");
    }
    println!(
        "\n{} finding(s). These are reported, never repaired: recovery is an\n\
         operator decision made with `glc-admin` so it lands in the audit trail\n\
         (docs/runbooks.md §1).",
        report.findings.len()
    );
    std::process::exit(1);
}
