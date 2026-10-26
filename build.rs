use std::process::Command;

fn main() {
    println!("cargo:rerun-if-changed=.git/HEAD");

    let commit = git_commit().or_else(|| {
        std::env::var("GITHUB_SHA")
            .ok()
            .map(|sha| sha.chars().take(12).collect())
    });
    let commit = commit.unwrap_or_else(|| {
        println!("cargo:warning=Git commit ID unavailable; About will show unknown");
        "unknown".to_string()
    });
    println!("cargo:rustc-env=KEEPASS_TUI_COMMIT={commit}");
    println!(
        "cargo:rustc-env=KEEPASS_TUI_TARGET={}",
        std::env::var("TARGET").unwrap_or_else(|_| "unknown".to_string())
    );
}

fn git_commit() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short=12", "HEAD"])
        .output()
        .ok()?;
    output
        .status
        .success()
        .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|commit| !commit.is_empty())
}
