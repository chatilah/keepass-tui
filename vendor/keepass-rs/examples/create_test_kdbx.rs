//! Helper: create a test KDBX file for kdbx2json demo
use keepass_rs::{
    save_database, CompositeKey, Database, DatabaseVersion, Entry, Group, NodeId, ProtectedString,
};

fn main() {
    let mut db = Database::new(DatabaseVersion::KDBX31);

    // Root group
    let root = Group::new(NodeId::new_uuid());
    let root_id = root.id;
    db.groups.insert(root.id, root);
    db.root_group_id = Some(root_id);

    // Subgroups
    let mut email_group = Group::new(NodeId::new_uuid());
    email_group.title = "Email".to_string();
    let email_id = email_group.id;
    db.groups.insert(email_group.id, email_group);
    db.groups
        .get_mut(&root_id)
        .unwrap()
        .child_group_ids
        .push(email_id);

    let mut work_group = Group::new(NodeId::new_uuid());
    work_group.title = "Work".to_string();
    let work_id = work_group.id;
    db.groups.insert(work_group.id, work_group);
    db.groups
        .get_mut(&root_id)
        .unwrap()
        .child_group_ids
        .push(work_id);

    // Entries in root
    let mut e1 = Entry::new(NodeId::new_uuid());
    e1.title = "GitHub".to_string();
    e1.username = ProtectedString::new_protected("user@example.com");
    e1.password = ProtectedString::new_protected("gh_s3cret_p@ss!");
    e1.url = "https://github.com".to_string();
    let e1_id = e1.id;
    db.entries.insert(e1.id, e1);
    db.groups
        .get_mut(&root_id)
        .unwrap()
        .child_entry_ids
        .push(e1_id);

    // Entries in Email
    let mut e2 = Entry::new(NodeId::new_uuid());
    e2.title = "Gmail".to_string();
    e2.username = ProtectedString::new_protected("me@gmail.com");
    e2.password = ProtectedString::new_protected("gm4il_p4ssw0rd");
    e2.url = "https://mail.google.com".to_string();
    let e2_id = e2.id;
    db.entries.insert(e2.id, e2);
    db.groups
        .get_mut(&email_id)
        .unwrap()
        .child_entry_ids
        .push(e2_id);

    let mut e3 = Entry::new(NodeId::new_uuid());
    e3.title = "Outlook".to_string();
    e3.username = ProtectedString::new_protected("me@outlook.com");
    e3.password = ProtectedString::new_protected("0utl00k_s3cr3t");
    e3.url = "https://outlook.live.com".to_string();
    let e3_id = e3.id;
    db.entries.insert(e3.id, e3);
    db.groups
        .get_mut(&email_id)
        .unwrap()
        .child_entry_ids
        .push(e3_id);

    // Entries in Work
    let mut e4 = Entry::new(NodeId::new_uuid());
    e4.title = "AWS Console".to_string();
    e4.username = ProtectedString::new_protected("admin@company.com");
    e4.password = ProtectedString::new_protected("Aws!2025#Secure");
    e4.url = "https://aws.amazon.com/console".to_string();
    let e4_id = e4.id;
    db.entries.insert(e4.id, e4);
    db.groups
        .get_mut(&work_id)
        .unwrap()
        .child_entry_ids
        .push(e4_id);

    // Custom field
    let mut e5 = Entry::new(NodeId::new_uuid());
    e5.title = "VPN".to_string();
    e5.username = ProtectedString::new_protected("vpn_user");
    e5.password = ProtectedString::new_protected("vpn_p@ss");
    e5.url = "vpn.company.com".to_string();
    e5.custom_fields.push(keepass_rs::EntryField {
        name: "Server".to_string(),
        value: ProtectedString::new_protected("vpn1.company.com"),
        is_protected: false,
    });
    e5.custom_fields.push(keepass_rs::EntryField {
        name: "OTP Secret".to_string(),
        value: ProtectedString::new_protected("JBSWY3DPEHPK3PXP"),
        is_protected: true,
    });
    e5.tags = vec!["work".to_string(), "vpn".to_string(), "network".to_string()];
    let e5_id = e5.id;
    db.entries.insert(e5.id, e5);
    db.groups
        .get_mut(&work_id)
        .unwrap()
        .child_entry_ids
        .push(e5_id);

    // Save
    let key = CompositeKey::new().with_password(b"test123");
    let mut buffer = Vec::new();
    save_database(&mut buffer, &db, &key).unwrap();
    std::fs::write("/tmp/test.kdbx", &buffer).unwrap();
    println!(
        "Created /tmp/test.kdbx ({} bytes, {} entries, {} groups)",
        buffer.len(),
        db.entries.len(),
        db.groups.len()
    );

    // Print entry IDs for --entry test
    println!("\nEntry IDs:");
    for (id, e) in &db.entries {
        println!("  {:?} → {}", id, e.title);
    }
}
