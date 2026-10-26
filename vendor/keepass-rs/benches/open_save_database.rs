//! End-to-end open/save roundtrip across formats.
//!
//! Run: cargo bench --bench open_save_database

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use keepass_rs::{
    open_database, save_database, CompositeKey, Database, DatabaseVersion, Entry, Group, NodeId,
    ProtectedString,
};
use std::io::Cursor;

fn build_db(version: DatabaseVersion, n: usize) -> Database {
    let mut db = Database::new(version);
    let root_id = NodeId::new_uuid();
    let mut root = Group::new(root_id);
    root.title = "Root".to_string();
    for i in 0..n {
        let eid = NodeId::new_uuid();
        let mut e = Entry::new(eid);
        e.title = format!("entry-{i}");
        e.username = ProtectedString::new_plain(&format!("u{i}"));
        e.password = ProtectedString::new_protected("pw");
        root.add_child_entry(eid);
        db.entries.insert(eid, e);
    }
    db.groups.insert(root_id, root);
    db.root_group_id = Some(root_id);
    db
}

fn bench_save(c: &mut Criterion) {
    let key = CompositeKey::new().with_password(b"bench-password");
    let mut group = c.benchmark_group("save_database");
    for n in [10usize, 100, 1_000] {
        for (label, ver) in [
            ("kdbx31", DatabaseVersion::KDBX31),
            ("kdbx4", DatabaseVersion::KDBX4),
        ] {
            let db = build_db(ver, n);
            group.bench_with_input(BenchmarkId::new(format!("{label}/{n}"), n), &n, |b, _| {
                b.iter(|| {
                    let mut buf = Vec::new();
                    save_database(&mut buf, black_box(&db), black_box(&key)).unwrap();
                    black_box(buf);
                })
            });
        }
    }
    group.finish();
}

fn bench_open(c: &mut Criterion) {
    let key = CompositeKey::new().with_password(b"bench-password");
    let mut group = c.benchmark_group("open_database");
    for n in [10usize, 100, 1_000] {
        for (label, ver) in [
            ("kdbx31", DatabaseVersion::KDBX31),
            ("kdbx4", DatabaseVersion::KDBX4),
        ] {
            let db = build_db(ver, n);
            let mut buf = Vec::new();
            save_database(&mut buf, &db, &key).unwrap();
            group.bench_with_input(BenchmarkId::new(format!("{label}/{n}"), n), &n, |b, _| {
                b.iter(|| {
                    let cur = Cursor::new(black_box(&buf));
                    let db = open_database(cur, black_box(&key)).unwrap();
                    black_box(db.entry_count());
                })
            });
        }
    }
    group.finish();
}

criterion_group!(benches, bench_save, bench_open);
criterion_main!(benches);
