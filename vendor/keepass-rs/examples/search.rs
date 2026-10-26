//! Search example.
//!
//! Demonstrates searching entries in a database.
//!
//! Run: cargo run --example search

use keepass_rs::{
    Database, DatabaseVersion, Entry, Group, NodeId, ProtectedString, SearchHelper,
    SearchParameters,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut db = Database::new(DatabaseVersion::KDBX31);

    let root = Group::new(NodeId::new_uuid());
    let root_id = root.id;
    db.groups.insert(root.id, root);
    db.root_group_id = Some(root_id);

    // Add several entries
    let entries_data = vec![
        ("GitHub", "user@example.com", "https://github.com"),
        ("GitLab", "user@example.com", "https://gitlab.com"),
        ("Gmail", "me@gmail.com", "https://mail.google.com"),
        ("AWS Console", "admin@company.com", "https://aws.amazon.com"),
        ("Netflix", "user@example.com", "https://netflix.com"),
    ];

    for (title, user, url) in entries_data {
        let mut entry = Entry::new(NodeId::new_uuid());
        entry.title = title.to_string();
        entry.username = ProtectedString::new_protected(user);
        entry.url = url.to_string();
        db.add_entry(entry, &root_id);
    }

    // Collect references for search
    let entry_refs: Vec<&Entry> = db.entries.values().collect();

    // Search by query
    let params = SearchParameters::new("git");
    let results = SearchHelper::search_entries(&entry_refs, &params);
    println!("Search 'git': {} results", results.len());
    for result in &results {
        if let Some(entry) = db.entries.get(&result.entry_id) {
            println!("  - {} (score: {:.2})", entry.title, result.score);
        }
    }

    // Search by URL
    let params = SearchParameters::new("google");
    let results = SearchHelper::search_entries(&entry_refs, &params);
    println!("\nSearch 'google': {} results", results.len());
    for result in &results {
        if let Some(entry) = db.entries.get(&result.entry_id) {
            println!("  - {} ({})", entry.title, entry.url);
        }
    }

    Ok(())
}
