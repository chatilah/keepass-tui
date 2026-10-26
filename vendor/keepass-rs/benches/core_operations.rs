//! Core in-memory operations: search, group traversal, merge.
//!
//! Run: cargo bench --bench core_operations

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use keepass_rs::{
    Database, DatabaseVersion, Entry, Group, NodeId, ProtectedString, SearchHelper,
    SearchParameters,
};

/// Build a database with `n` entries spread across `groups` flat subgroups.
fn build_db(n: usize, groups: usize) -> Database {
    let mut db = Database::new(DatabaseVersion::KDBX4);
    let root_id = NodeId::new_uuid();
    let mut root = Group::new(root_id);
    root.title = "Root".to_string();

    let per_group = n / groups.max(1);
    let mut total = 0usize;
    for g in 0..groups {
        let gid = NodeId::new_uuid();
        let mut group = Group::new(gid);
        group.title = format!("Group-{g}");
        for _ in 0..per_group {
            if total >= n {
                break;
            }
            let eid = NodeId::new_uuid();
            let mut e = Entry::new(eid);
            e.title = format!("entry-{total}");
            e.username = ProtectedString::new_plain(&format!("user{total}@x.com"));
            e.url = format!("https://x{total}.com");
            e.password = ProtectedString::new_protected("pw");
            group.add_child_entry(eid);
            db.entries.insert(eid, e);
            total += 1;
        }
        root.add_child_group(gid);
        db.groups.insert(gid, group);
    }
    db.groups.insert(root_id, root);
    db.root_group_id = Some(root_id);
    db
}

fn bench_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("search");
    for n in [100usize, 1_000, 10_000] {
        let db = build_db(n, 10);
        let entries: Vec<&Entry> = db.entries.values().collect();
        // Match every 10th entry title.
        let params = SearchParameters::new("entry-5");
        group.bench_with_input(BenchmarkId::new("plain", n), &n, |b, _| {
            b.iter(|| {
                let r = SearchHelper::search_entries(black_box(&entries), black_box(&params));
                black_box(r);
            })
        });
        let regex = SearchParameters::regex("entry-[0-9]5$");
        group.bench_with_input(BenchmarkId::new("regex", n), &n, |b, _| {
            b.iter(|| {
                let r = SearchHelper::search_entries(black_box(&entries), black_box(&regex));
                black_box(r);
            })
        });
    }
    group.finish();
}

fn bench_get_all_entries_recursive(c: &mut Criterion) {
    let mut group = c.benchmark_group("traversal");
    for n in [100usize, 1_000, 10_000] {
        let db = build_db(n, 10);
        let root_id = db.root_group_id.unwrap();
        group.bench_with_input(BenchmarkId::new("all_entries", n), &n, |b, _| {
            b.iter(|| {
                let v = db.get_all_entries_in_group(black_box(&root_id));
                black_box(v.len());
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_search, bench_get_all_entries_recursive);
criterion_main!(benches);
