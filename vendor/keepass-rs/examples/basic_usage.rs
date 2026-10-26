//! KeePass database round-trip example.
//!
//! Creates a new KDBX 3.1 database, adds entries, saves to a file,
//! then reads it back and verifies the content.
//!
//! Run: cargo run --example basic_usage

use std::io::Cursor;

use keepass_rs::{
    open_database, save_database, CompositeKey, Database, DatabaseVersion, Entry, Group, NodeId,
    ProtectedString,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 1. Create a new database
    let mut db = Database::new(DatabaseVersion::KDBX31);

    // Create root group
    let root = Group::new(NodeId::new_uuid());
    let root_id = root.id;
    db.groups.insert(root.id, root);
    db.root_group_id = Some(root_id);

    // Create "Email" subgroup
    let mut email_group = Group::new(NodeId::new_uuid());
    email_group.title = "Email".to_string();
    let email_group_id = email_group.id;
    db.groups.insert(email_group.id, email_group);
    db.groups
        .get_mut(&root_id)
        .unwrap()
        .add_child_group(email_group_id);

    // Add an entry in root
    let mut entry = Entry::new(NodeId::new_uuid());
    entry.title = "GitHub".to_string();
    entry.username = ProtectedString::new_protected("user@example.com");
    entry.password = ProtectedString::new_protected("s3cret_p4ssw0rd");
    entry.url = "https://github.com".to_string();
    db.add_entry(entry, &root_id);

    // Add an entry in Email group
    let mut email_entry = Entry::new(NodeId::new_uuid());
    email_entry.title = "Gmail".to_string();
    email_entry.username = ProtectedString::new_protected("me@gmail.com");
    email_entry.password = ProtectedString::new_protected("gm4il_p4ss");
    db.add_entry(email_entry, &email_group_id);

    println!(
        "Created database: {} entries, {} groups",
        db.entry_count(),
        db.group_count()
    );

    // 2. Save to buffer
    let key = CompositeKey::new().with_password(b"demo_password");
    let mut buffer = Vec::new();
    save_database(&mut buffer, &db, &key)?;
    println!("Saved: {} bytes", buffer.len());

    // 3. Read back
    let cursor = Cursor::new(buffer);
    let loaded = open_database(cursor, &key)?;
    println!(
        "Loaded: {} entries, {} groups",
        loaded.entry_count(),
        loaded.group_count()
    );

    // 4. Display loaded content
    if let Some(root) = loaded.root_group() {
        println!("Root group: {}", root.title);
        for child_id in &root.child_group_ids {
            if let Some(g) = loaded.groups.get(child_id) {
                println!("  Group: {}", g.title);
            }
        }
    }

    for (id, entry) in &loaded.entries {
        println!(
            "  Entry {}: {}",
            id.as_uuid().map(|u| u.to_string()).unwrap_or_default(),
            entry.title
        );
    }

    println!("\nSave → Load round-trip complete!");
    Ok(())
}
