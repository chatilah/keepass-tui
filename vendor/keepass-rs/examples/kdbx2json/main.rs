//! CLI tool to read KDB/KDBX files and output JSON.
//!
//! Usage:
//!   cargo run --example kdbx2json -- <file.kdbx> <password> [--key-file <path>] [--pretty]
//!
//! Example:
//!   cargo run --example kdbx2json -- test.kdbx "mypassword" --pretty
//!   cargo run --example kdbx2json -- test.kdbx "mypassword" --key-file keyfile.keyx

use std::env;
use std::fs;
use std::io;
use std::process;

use serde_json::{json, Value};

use keepass_rs::{
    crypto::{CompressionAlgorithm, EncryptionAlgorithm},
    open_database, CompositeKey, Database, DatabaseVersion, DateInstant, Entry, Group, NodeId,
};

// ─── CLI Argument Parsing ─────────────────────────────────────────────

struct CliArgs {
    file_path: String,
    password: String,
    key_file: Option<String>,
    pretty: bool,
    show_passwords: bool,
    groups_only: bool,
    entry_id: Option<String>,
}

fn parse_args() -> Result<CliArgs, String> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.len() < 2 {
        return Err(format!(
            "Usage: {} <file.kdbx> <password> [--key-file <path>] [--pretty] [--show-passwords] [--groups-only] [--entry <id>]",
            env::args().next().unwrap_or("kdbx2json".into())
        ));
    }

    let file_path = args[0].clone();
    let password = args[1].clone();
    let mut key_file = None;
    let mut pretty = false;
    let mut show_passwords = false;
    let mut groups_only = false;
    let mut entry_id = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--key-file" => {
                i += 1;
                key_file = Some(args.get(i).ok_or("--key-file requires a path")?.clone());
            }
            "--pretty" => pretty = true,
            "--show-passwords" => show_passwords = true,
            "--groups-only" => groups_only = true,
            "--entry" => {
                i += 1;
                entry_id = Some(args.get(i).ok_or("--entry requires an ID")?.clone());
            }
            other => return Err(format!("Unknown argument: {}", other)),
        }
        i += 1;
    }

    Ok(CliArgs {
        file_path,
        password,
        key_file,
        pretty,
        show_passwords,
        groups_only,
        entry_id,
    })
}

// ─── Serialization Helpers ────────────────────────────────────────────

fn node_id_to_value(id: &NodeId) -> Value {
    match id {
        NodeId::Uuid(u) => json!(u.to_string()),
        NodeId::Int(i) => json!(i),
    }
}

fn date_to_value(d: &DateInstant) -> Value {
    match d {
        DateInstant::EpochMillis(ms) => match chrono::DateTime::from_timestamp_millis(*ms) {
            Some(dt) => json!(dt.format("%Y-%m-%dT%H:%M:%S%.3fZ").to_string()),
            None => json!(ms),
        },
        DateInstant::Compressed(bytes) => json!(format!("compressed:{:02x?}", bytes)),
        DateInstant::Never => json!(null),
    }
}

fn encryption_to_value(e: &EncryptionAlgorithm) -> &'static str {
    match e {
        EncryptionAlgorithm::AesRijndael => "AES-256-CBC",
        EncryptionAlgorithm::Twofish => "Twofish-256-CBC",
        EncryptionAlgorithm::ChaCha20 => "ChaCha20",
    }
}

fn compression_to_value(c: &CompressionAlgorithm) -> &'static str {
    match c {
        CompressionAlgorithm::None => "None",
        CompressionAlgorithm::Gzip => "Gzip",
    }
}

fn version_to_value(v: &DatabaseVersion) -> &'static str {
    match v {
        DatabaseVersion::KDB => "KDB (1.x)",
        DatabaseVersion::KDBX31 => "KDBX 3.1",
        DatabaseVersion::KDBX4 => "KDBX 4.0",
    }
}

fn entry_to_json(entry: &Entry, show_passwords: bool) -> Value {
    let mut custom_fields = serde_json::Map::new();
    for f in &entry.custom_fields {
        let val = if f.is_protected && !show_passwords {
            "••••••••".to_string()
        } else {
            f.value.as_str().to_string()
        };
        custom_fields.insert(f.name.clone(), json!(val));
    }

    let mut binaries_arr = Vec::new();
    for (name, data) in &entry.binaries {
        binaries_arr.push(json!({
            "name": name,
            "size": data.len(),
        }));
    }

    json!({
        "id": node_id_to_value(&entry.id),
        "title": entry.title,
        "username": entry.username.as_str(),
        "password": if show_passwords { entry.password.as_str() } else { "••••••••" },
        "url": entry.url,
        "notes": if show_passwords { entry.notes.as_str() } else { "••••••••" },
        "icon_id": match &entry.icon { keepass_rs::IconImage::Standard(s) => s.icon_id, _ => 0 },
        "custom_icon_uuid": entry.custom_icon_uuid.map(|u| u.to_string()),
        "background_color": entry.background_color,
        "foreground_color": entry.foreground_color,
        "tags": entry.tags,
        "custom_fields": custom_fields,
        "attachments": binaries_arr,
        "autotype_enabled": entry.autotype_enabled,
        "expires": entry.expires,
        "usage_count": entry.usage_count,
        "creation_time": date_to_value(&entry.creation_time),
        "last_modification_time": date_to_value(&entry.last_modification_time),
        "last_access_time": date_to_value(&entry.last_access_time),
        "expiry_time": date_to_value(&entry.expiry_time),
        "history_count": entry.history.len(),
    })
}

fn group_to_json(group: &Group, db: &Database, show_passwords: bool, show_entries: bool) -> Value {
    let children: Vec<Value> = group
        .child_group_ids
        .iter()
        .filter_map(|gid| {
            db.groups
                .get(gid)
                .map(|g| group_to_json(g, db, show_passwords, show_entries))
        })
        .collect();

    let entries: Vec<Value> = if show_entries {
        group
            .child_entry_ids
            .iter()
            .filter_map(|eid| {
                db.entries
                    .get(eid)
                    .map(|e| entry_to_json(e, show_passwords))
            })
            .collect()
    } else {
        vec![]
    };

    json!({
        "id": node_id_to_value(&group.id),
        "name": group.title,
        "icon_id": match &group.icon { keepass_rs::IconImage::Standard(s) => s.icon_id, _ => 0 },
        "custom_icon_uuid": group.custom_icon_uuid.map(|u| u.to_string()),
        "notes": group.notes,
        "is_expanded": group.is_expanded,
        "entry_count": group.child_entry_ids.len(),
        "subgroup_count": group.child_group_ids.len(),
        "expires": group.expires,
        "usage_count": group.usage_count,
        "enable_searching": group.enable_searching,
        "creation_time": date_to_value(&group.creation_time),
        "last_modification_time": date_to_value(&group.last_modification_time),
        "groups": children,
        "entries": entries,
    })
}

fn database_to_json(db: &Database, show_passwords: bool, groups_only: bool) -> Value {
    let root = match db.root_group() {
        Some(r) => group_to_json(r, db, show_passwords, !groups_only),
        None => json!(null),
    };

    json!({
        "version": version_to_value(&db.version),
        "name": db.name,
        "description": db.description,
        "default_username": db.default_username,
        "encryption": encryption_to_value(&db.encryption_algorithm),
        "compression": compression_to_value(&db.compression),
        "entry_count": db.entry_count(),
        "group_count": db.group_count(),
        "recycle_bin_uuid": db.recycle_bin_uuid.map(|u| u.to_string()),
        "root": root,
    })
}

// ─── Main ─────────────────────────────────────────────────────────────

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    };

    // Read file
    let file_bytes = match fs::read(&args.file_path) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Error reading '{}': {}", args.file_path, e);
            process::exit(1);
        }
    };

    // Build composite key
    let mut key = CompositeKey::new().with_password(args.password.as_bytes());
    if let Some(ref kf_path) = args.key_file {
        match fs::read(kf_path) {
            Ok(kf_data) => key = key.with_key_file(&kf_data),
            Err(e) => {
                eprintln!("Error reading key file '{}': {}", kf_path, e);
                process::exit(1);
            }
        }
    }

    // Open database
    let db = match open_database(io::Cursor::new(file_bytes), &key) {
        Ok(db) => db,
        Err(e) => {
            eprintln!("Error opening database: {}", e);
            process::exit(1);
        }
    };

    // Output JSON
    let json_output = if let Some(ref eid) = args.entry_id {
        // Output single entry
        let target_id = match uuid::Uuid::parse_str(eid) {
            Ok(u) => NodeId::from_uuid(u),
            Err(_) => {
                eprintln!("Invalid entry UUID: {}", eid);
                process::exit(1);
            }
        };
        match db.entries.get(&target_id) {
            Some(entry) => entry_to_json(entry, args.show_passwords),
            None => {
                eprintln!("Entry not found: {}", eid);
                process::exit(1);
            }
        }
    } else {
        database_to_json(&db, args.show_passwords, args.groups_only)
    };

    let output = if args.pretty {
        serde_json::to_string_pretty(&json_output).unwrap_or_default()
    } else {
        serde_json::to_string(&json_output).unwrap_or_default()
    };

    println!("{}", output);
}
