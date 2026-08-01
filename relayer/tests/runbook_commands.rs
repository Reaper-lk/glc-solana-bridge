//! Every `glc-admin` command the runbooks name must actually exist.
//!
//! # Why this is a test and not a review checklist
//!
//! `docs/runbooks.md` is read during incidents, by people under pressure,
//! who will type what it says. A renamed or removed subcommand turns a
//! recovery step into "unknown command" at the worst possible moment — and
//! nothing about renaming a subcommand would otherwise fail.
//!
//! Phases 7i-0 and 7i-1 exist because three documented procedures had no
//! executable form. This test is what stops that recurring: the
//! documentation and the binary are checked against each other on every CI
//! run, not on every reviewer's attention span.
//!
//! It deliberately checks only what it can check mechanically — that the
//! commands and environment variables named in prose exist. Whether the
//! *procedure* is correct is what rehearsal is for (ADR-0014 §8.7), and that
//! is still outstanding.

use std::collections::BTreeSet;

fn runbooks() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/runbooks.md");
    std::fs::read_to_string(path).expect("docs/runbooks.md is missing")
}

fn glc_admin_source() -> String {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/bin/glc-admin.rs");
    std::fs::read_to_string(path).expect("glc-admin source is missing")
}

/// Every `glc-admin <subcommand>` mentioned anywhere in the runbooks.
fn commands_named_in_runbooks(text: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (i, _) in text.match_indices("glc-admin ") {
        let rest = &text[i + "glc-admin ".len()..];
        let word: String = rest
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || *c == '-')
            .collect();
        // Skip prose like "glc-admin is a one-shot tool" and the flag-only
        // mentions ("glc-admin approve-*").
        if word.len() > 2 && !word.ends_with('-') {
            out.insert(word);
        }
    }
    out
}

/// The subcommands the binary actually dispatches on.
fn commands_the_binary_accepts(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for line in src.lines() {
        let t = line.trim();
        // Matches the dispatch arms: `"status" => status(&args),`
        if let Some(rest) = t.strip_prefix('"') {
            if let Some(name) = rest.split('"').next() {
                if t.contains("=>")
                    && !name.is_empty()
                    && name.chars().all(|c| c.is_ascii_lowercase() || c == '-')
                {
                    out.insert(name.to_string());
                }
            }
        }
    }
    out
}

#[test]
fn every_command_the_runbooks_name_exists_in_the_binary() {
    let named = commands_named_in_runbooks(&runbooks());
    let accepted = commands_the_binary_accepts(&glc_admin_source());

    assert!(
        !named.is_empty(),
        "parsed no commands out of the runbooks — the extractor is broken, \
         which would make this test silently vacuous"
    );

    let missing: Vec<&String> = named.difference(&accepted).collect();
    assert!(
        missing.is_empty(),
        "docs/runbooks.md tells an operator to run commands glc-admin does not accept: {missing:?}\n\
         accepted: {accepted:?}"
    );
}

#[test]
fn the_runbooks_cover_every_command_the_binary_offers() {
    // The other direction: a command nobody documents is a command nobody
    // will find during an incident. Not fatal, but it means either the
    // runbook or the command is incomplete.
    let named = commands_named_in_runbooks(&runbooks());
    let accepted = commands_the_binary_accepts(&glc_admin_source());

    let undocumented: Vec<&String> = accepted
        .difference(&named)
        .filter(|c| !matches!(c.as_str(), "help" | "-h" | "--help"))
        .collect();
    assert!(
        undocumented.is_empty(),
        "glc-admin offers commands the runbooks never mention: {undocumented:?}"
    );
}

#[test]
fn every_environment_variable_the_runbooks_name_is_actually_read() {
    // A runbook that tells an operator to set GLC_FOO when the code reads
    // GLC_BAR produces a change that appears to work and does nothing.
    let text = runbooks();
    let mut named = BTreeSet::new();
    for (i, _) in text.match_indices("GLC_") {
        let word: String = text[i..]
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        if word.len() > 4 {
            named.insert(word);
        }
    }
    assert!(!named.is_empty(), "parsed no env vars — extractor broken");

    // Every source file that reads configuration, so a variable read by any
    // binary counts as real.
    let mut sources = String::new();
    for rel in [
        "/src/main.rs",
        "/src/bin/glc-admin.rs",
        "/src/bin/signer-server.rs",
        "/src/glc/config.rs",
        "/src/solana/config.rs",
    ] {
        let path = format!("{}{rel}", env!("CARGO_MANIFEST_DIR"));
        sources.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
    }

    let unread: Vec<&String> = named.iter().filter(|v| !sources.contains(&**v)).collect();
    assert!(
        unread.is_empty(),
        "docs/runbooks.md names environment variables nothing reads: {unread:?}"
    );
}

#[test]
fn every_metric_the_runbooks_name_is_actually_exposed() {
    let text = runbooks();
    let mut named = BTreeSet::new();
    for (i, _) in text.match_indices("glc_") {
        let word: String = text[i..]
            .chars()
            .take_while(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        if word.len() > 4 {
            named.insert(word);
        }
    }
    assert!(
        !named.is_empty(),
        "parsed no metric names — extractor broken"
    );

    let mut sources = String::new();
    for rel in ["/src/ops/health.rs", "/src/ops/collector.rs"] {
        let path = format!("{}{rel}", env!("CARGO_MANIFEST_DIR"));
        sources.push_str(&std::fs::read_to_string(&path).unwrap_or_default());
    }

    let missing: Vec<&String> = named.iter().filter(|m| !sources.contains(&**m)).collect();
    assert!(
        missing.is_empty(),
        "docs/runbooks.md names metrics the bridge does not expose: {missing:?}"
    );
}

#[test]
fn every_invariant_the_runbooks_name_is_actually_reported() {
    // The runbooks tell operators to look for `BREACH <name>` in /health.
    // A renamed invariant makes that instruction silently useless.
    let text = runbooks();
    let health =
        std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/ops/health.rs")).unwrap();

    for name in [
        "solvency",
        "vault_reconciliation",
        "no_integrity_halts",
        "validator_epoch_fresh",
        "indexer_not_halted",
    ] {
        assert!(
            text.contains(name),
            "the runbooks never mention the {name} invariant"
        );
        assert!(
            health.contains(&format!("name: \"{name}\"")),
            "the runbooks name an invariant health.rs does not report: {name}"
        );
    }
}

#[test]
fn the_runbooks_state_the_unrehearsed_and_open_items() {
    // These are the honest limits of the document. Losing them would make it
    // read as more complete than it is — which is the specific failure this
    // whole phase exists to prevent.
    let text = runbooks();
    for claim in [
        "custody.md` #7",      // the single-key pause model
        "not met",             // testnet rehearsal outstanding
        "no procedure exists", // proof-of-reserves
    ] {
        assert!(
            text.contains(claim),
            "docs/runbooks.md no longer records: {claim:?}"
        );
    }
}
