//! The deployment guide must list every variable the binaries actually read.
//!
//! # Why this is a test
//!
//! Phases 7e–7i added twelve environment variables that
//! `docs/federation-deployment.md` never mentioned. Two of them —
//! `GLC_SIGNER_GOVERNANCE_APPROVALS_PATH` and
//! `GLC_SIGNER_SWEEP_APPROVALS_PATH` — are **optional and fail closed**, so
//! an operator deploying from that document got a federation that started
//! cleanly, served deposits and payouts correctly, and could not rotate its
//! keys or escape a compromised vault. Nothing complained until the day it
//! mattered.
//!
//! Nothing about adding a `env_required("GLC_NEW_THING")` would otherwise
//! fail. This closes that, the same way `runbook_commands.rs` closes it for
//! operator commands.
//!
//! # What it does not check
//!
//! That the *descriptions* are correct — only that the set of names agrees.
//! A wrong description still needs a reader.

use std::collections::BTreeSet;
use std::path::PathBuf;

fn read(rel: &str) -> String {
    let path = format!("{}/{rel}", env!("CARGO_MANIFEST_DIR"));
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

fn deployment_doc() -> String {
    read("../docs/federation-deployment.md")
}

/// Every `GLC_*` name appearing in a source file, however it is read.
fn vars_in(src: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (i, _) in src.match_indices("GLC_") {
        let name: String = src[i..]
            .chars()
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
            .collect();
        // Skip prefixes that are not whole names (e.g. the `GLC_` in prose).
        if name.len() > 4 {
            out.insert(name);
        }
    }
    out
}

/// The configuration surface of the three shipped binaries.
fn vars_the_binaries_read() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for f in [
        "src/main.rs",
        "src/bin/signer-server.rs",
        "src/bin/glc-admin.rs",
    ] {
        let src = read(f);
        // Only names inside an actual read call, so a variable merely
        // mentioned in a comment does not count as configuration.
        // `env_required`, `env_required_u32`, `env_required_u64`, ... — the
        // prefix, not an enumerated list, so a new numeric variant cannot
        // quietly fall out of the extractor and make this test vacuous.
        for marker in [
            "env_required",
            "env_optional(",
            "env::var(",
            "env::var_os(",
            "keypair_at(",
        ] {
            for (i, _) in src.match_indices(marker) {
                let rest = &src[i + marker.len()..];
                let quoted: String = rest
                    .trim_start_matches(|c: char| c.is_ascii_alphanumeric() || c == '_')
                    .trim_start_matches('(')
                    .trim_start()
                    .trim_start_matches('"')
                    .chars()
                    .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || *c == '_')
                    .collect();
                if quoted.starts_with("GLC_") && quoted.len() > 4 {
                    out.insert(quoted);
                }
            }
        }
    }
    out
}

#[test]
fn every_variable_the_binaries_read_is_documented() {
    let read_by_code = vars_the_binaries_read();
    assert!(
        read_by_code.len() > 30,
        "extracted only {} variables — the extractor is broken, which would make this \
         test silently vacuous",
        read_by_code.len()
    );

    let doc = deployment_doc();
    let undocumented: Vec<&String> = read_by_code
        .iter()
        .filter(|v| !doc.contains(v.as_str()))
        .collect();
    assert!(
        undocumented.is_empty(),
        "docs/federation-deployment.md does not mention variables the binaries require: \
         {undocumented:?}\n\
         An operator deploying from that document would get a broken or silently degraded \
         federation."
    );
}

#[test]
fn the_fail_closed_optional_variables_are_called_out_as_such() {
    // These two are the dangerous shape: optional, and their absence
    // disables an entire incident-response capability without any error.
    // Documenting the NAME is not enough; the consequence has to be stated.
    let doc = deployment_doc();
    for (var, must_mention) in [
        ("GLC_SIGNER_GOVERNANCE_APPROVALS_PATH", "refused"),
        ("GLC_SIGNER_SWEEP_APPROVALS_PATH", "refused"),
        ("GLC_OPS_LISTEN_ADDR", "not exposed"),
    ] {
        assert!(doc.contains(var), "{var} is not documented at all");
        // Any mention may carry the consequence — operators read the table
        // and the prose, and requiring it at the first occurrence would be
        // an arbitrary constraint on how the guide is organised.
        let stated = doc
            .match_indices(var)
            .any(|(i, _)| doc[i..(i + 400).min(doc.len())].contains(must_mention));
        assert!(
            stated,
            "the deployment guide names {var} but does not say what happens when it is \
             unset (expected to mention {must_mention:?})"
        );
    }
}

#[test]
fn the_documented_variables_are_all_still_read() {
    // The other direction: a variable that stopped being read but is still
    // documented sends an operator to set something with no effect.
    //
    // The guide deliberately records one RETIRED name
    // (`GLC_SOLANA_VALIDATOR_KEYPAIR_PATHS`, from the Phase 5 bootstrap
    // topology) precisely to tell operators it is gone, so that one is
    // allowed — but only because the surrounding text says so.
    let doc = deployment_doc();
    let documented = vars_in(&doc);
    let read_by_code = vars_the_binaries_read();

    let retired = "GLC_SOLANA_VALIDATOR_KEYPAIR_PATHS";
    assert!(
        doc.contains(&format!("`{retired}` no longer exists")),
        "the retired variable must be documented AS retired, not merely listed"
    );

    let stale: Vec<&String> = documented
        .iter()
        .filter(|v| v.as_str() != retired && !read_by_code.contains(*v))
        .collect();
    assert!(
        stale.is_empty(),
        "docs/federation-deployment.md documents variables nothing reads: {stale:?}"
    );
}

#[test]
fn the_own_node_requirement_is_stated_where_operators_will_look() {
    // ADR-0017 E2. Both processes run on one host and both need Goldcoin
    // access, so pointing them at one node is the natural mistake — and it
    // silently defeats the independent validation that makes a signer's
    // refusal mean anything.
    let doc = deployment_doc();
    assert!(
        doc.contains("GLC_SIGNER_GLC_RPC_URL"),
        "the signer's own-node variable must be documented"
    );
    let stated = doc.match_indices("GLC_SIGNER_GLC_RPC_URL").any(|(i, _)| {
        let w = &doc[i..(i + 600).min(doc.len())];
        w.contains("own") && w.contains("never the relayer")
    });
    assert!(
        stated,
        "the guide must say the signer's Goldcoin node is its OWN, not the relayer's"
    );
}

// ---------------------------------------------------------------------------
// The launch checklist cites tests as its evidence
// ---------------------------------------------------------------------------

/// Every `*.rs` the launch checklist names as verification must exist.
///
/// The checklist's whole claim is "an item is only ticked if something fails
/// when it stops being true". A cited test that has been renamed or deleted
/// turns a tick into an assertion nobody is checking — which is exactly the
/// failure mode Phases 7i-0 through 7i found three times in documentation.
#[test]
fn every_test_the_launch_checklist_cites_exists() {
    let checklist = read("../docs/launch-checklist.md");
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"));

    let mut cited = BTreeSet::new();
    for (i, _) in checklist.match_indices(".rs`") {
        // Walk back to the opening backtick.
        let start = checklist[..i].rfind('`').map(|b| b + 1);
        if let Some(start) = start {
            let name = &checklist[start..i];
            if !name.is_empty()
                && name
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                cited.insert(format!("{name}.rs"));
            }
        }
    }
    assert!(
        cited.len() > 10,
        "extracted only {} cited tests — the extractor is broken and this test proves nothing",
        cited.len()
    );

    let missing: Vec<&String> = cited
        .iter()
        .filter(|name| {
            !root.join("tests").join(name).exists()
                && !root
                    .join("../programs/glc-bridge/tests")
                    .join(name)
                    .exists()
        })
        .collect();
    assert!(
        missing.is_empty(),
        "docs/launch-checklist.md cites tests that do not exist: {missing:?}\n\
         Those checklist items are unbacked claims."
    );
}

/// The checklist must keep saying the bridge is not ready while open items
/// remain, and must keep naming the rehearsal caveat.
#[test]
fn the_checklist_states_its_own_limits() {
    let c = read("../docs/launch-checklist.md");
    for claim in [
        "not launch-ready",
        // The rehearsals self-skip without their binaries, so a green CI run
        // is not evidence they passed. Losing this sentence would make CI
        // look like it covers them.
        "does not mean the rehearsals passed",
        "custody.md",
        "not started",
    ] {
        assert!(
            c.contains(claim),
            "docs/launch-checklist.md no longer records: {claim:?}"
        );
    }
}
