//! Shared secret-shaped name detection.
//!
//! Single source of truth used by both the sandbox env sanitizer
//! (`sandbox::linux::runner`) and the audit redactor (`audit`) so the two
//! cannot drift. Before this module existed the audit redactor recognised
//! bare suffixes (`KEY`, `TOKEN`, …) while the sandbox sanitizer only
//! recognised underscore-anchored ones (`_KEY`, …), so a variable such as
//! `AUTHTOKEN` was redacted from audit logs yet still leaked into the
//! sandboxed child process environment.

pub(crate) fn is_secret_name(name: &str) -> bool {
    let up = name.to_ascii_uppercase();
    const SUFFIXES: &[&str] = &[
        "_API_KEY",
        "_KEY",
        "_TOKEN",
        "_SECRET",
        "_PASSWORD",
        "_PASSWD",
        "KEY",
        "TOKEN",
        "SECRET",
        "PASSWORD",
        "PASSWD",
    ];
    const PREFIXES: &[&str] = &[
        "ANTHROPIC_",
        "OPENAI_",
        "AWS_",
        "GCP_",
        "AZURE_",
        "GITHUB_",
        "GITLAB_",
        "STRIPE_",
    ];
    if PREFIXES.iter().any(|p| up.starts_with(p)) || SUFFIXES.iter().any(|s| up.ends_with(s)) {
        return true;
    }
    matches!(
        up.as_str(),
        "GITHUB_TOKEN" | "GH_TOKEN" | "NPM_TOKEN" | "DATABASE_URL" | "REDIS_URL"
    )
}
