# keepass-rs

[![CI](https://github.com/meission/keepass-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/meission/keepass-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20%2B%20MulanPSL--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.77%2B-orange.svg)](Cargo.toml)
[![Tests](https://img.shields.io/badge/tests-220%20passing-brightgreen.svg)]()

Platform-independent KeePass database library written in Rust.
Goal Supports KDB (v1), KDBX 3.1, and KDBX 4.0 file formats.
Designed for [KeePassDX](https://github.com/Kunzisoft/KeePassDX) compatibility with Flutter business layer integration.

**[中文文档](README_zh.md)**

---

## ✨ Features

### File Formats

| Format | Read | Write | Notes |
|--------|------|-------|-------|
| **KDB v1** | ✅ | ✅ | KeePass 1.x format |
| **KDBX 3.1** | ✅ | ✅ | KeePass 2.x pre-4.0 |
| **KDBX 4.0** | ✅ | ✅ | KeePass 2.47+, binary attachment pool |

### Encryption

| Algorithm | Mode | Usage |
|-----------|------|-------|
| **AES-256** | CBC | Database encryption (default) |
| **ChaCha20** | Stream | KDBX 4.0 inner stream |
| **Twofish** | CBC | Alternative database encryption |
| **Salsa20** | Stream | KDBX 3.1 inner stream |

### Key Derivation

| KDF | Parameters | Usage |
|-----|------------|-------|
| **AES-KDF** | Rounds (default 6000) | KDBX 3.1 |
| **Argon2d** | Memory, iterations, parallelism | KDBX 4.0 default |
| **Argon2id** | Memory, iterations, parallelism | KDBX 4.0 alternative |

### Core Capabilities

- 🔐 **Full encryption** — AES-256, ChaCha20, Twofish, Salsa20
- 🗝️ **Key derivation** — AES-KDF, Argon2d, Argon2id
- 🔍 **Regex search** — Title, username, URL, notes, tags
- 🔀 **Three-way merge** — Conflict detection and resolution
- 🛠️ **Integrity repair** — Automatic database repair
- 🔑 **OTP support** — TOTP / HOTP with SHA-1/256/512
- ✍️ **Digital signatures** — ECDSA (P-256) / RSA verification
- 📊 **Change tracking** — Diff and audit log
- 🧪 **Fuzz testing** — Robustness against malformed inputs
- 📱 **Multi-platform** — Android JNI, HarmonyOS NAPI, Flutter FRB

---

## 🚀 Quick Start

Add to `Cargo.toml`:

```toml
[dependencies]
keepass-rs = "0.1"
```

### Open an Existing Database

```rust
use keepass_rs::{open_database, CompositeKey};
use std::fs::File;

let file = File::open("database.kdbx")?;
let key = CompositeKey::new().with_password(b"mypassword");
let db = open_database(file, &key)?;

println!("Database: {}", db.name);
println!("Entries: {}", db.entries.len());
```

### Search Entries

```rust
use keepass_rs::{SearchHelper, SearchParameters};

let params = SearchParameters::new("github");
let entries: Vec<&Entry> = db.entries.values().collect();
let results = SearchHelper::search_entries(&entries, &params);

for r in &results {
    println!("Found: {} - {}", r.entry.title, r.entry.url);
}
```

### Modify and Save

```rust
use keepass_rs::{save_database, NodeId};
use keepass_rs::model::entry::Entry;
use keepass_rs::model::core::security::ProtectedString;

let entry_id = NodeId::new_uuid();
let mut entry = Entry::new(entry_id);
entry.title = "New Entry".to_string();
entry.username = ProtectedString::new_plain("user@example.com");
entry.password = ProtectedString::new_protected("s3cret!");

if let Some(root) = &mut db.root_group {
    root.add_child_entry(entry_id);
}
db.entries.insert(entry_id, entry);

let mut out = File::create("output.kdbx")?;
save_database(&mut out, &db, &key)?;
```

### Create a New Database

```rust
use keepass_rs::model::db::database::{Database, DatabaseVersion};
use keepass_rs::model::db::composite_key::CompositeKey;
use keepass_rs::model::group::Group;
use keepass_rs::model::core::node::NodeId;
use keepass_rs::save_database;

let mut db = Database::new(DatabaseVersion::KDBX4);
db.name = "My Database".to_string();

let root_id = NodeId::new_uuid();
let root = Group::new(root_id);
db.root_group = Some(root);

let key = CompositeKey::new().with_password(b"masterpassword");

let mut out = File::create("new.kdbx")?;
save_database(&mut out, &db, &key)?;
```

### TOTP Calculation

```rust
use keepass_rs::model::entry::otp::{OtpParameters, TokenCalculator, OtpType, OtpHashAlgorithm};

let params = OtpParameters {
    otp_type: OtpType::Totp,
    algorithm: OtpHashAlgorithm::Sha1,
    digits: 6,
    period: 30,
    counter: 0,
    secret: base32::decode(base32::Alphabet::RFC4648, "JBSWY3DPEHPK3PXP").unwrap(),
};

let code = TokenCalculator::compute(&params)?;
println!("TOTP: {}", code);
```

---

## 📱 Platform Integration

### Android (JNI)

```kotlin
// From Kotlin
val db = KeePassLib.openDatabase(file, "password")
val entries = db.searchEntries("github")
```

See [examples/keepass-jni](examples/keepass-jni/) for the full JNI bridge.

### HarmonyOS NEXT (NAPI)

```typescript
// From ArkTS
const db = keepass.openDatabase(filePath, 'password')
const entries = db.searchEntries('github')
```

See [examples/keepass-ohos](examples/keepass-ohos/) for the NAPI bridge.

### Flutter

```dart
// Via flutter_rust_bridge
final db = await api.openDatabase(path: filePath, password: 'password');
final entries = await api.searchEntries(query: 'github');
```

See [examples/flutter_rust_bridge](examples/flutter_rust_bridge/) for Flutter integration.

---

## 📦 Module Overview

| Module | Description |
|--------|-------------|
| `crypto` | Encryption primitives (AES, ChaCha20, Twofish, Salsa20, Argon2) |
| `model` | Data models (Database, Entry, Group, Node, Icon, OTP) |
| `model::core` | Core types (NodeId, DateInstant, ProtectedString) |
| `model::db` | Database, CompositeKey, ChangeTracker |
| `model::entry` | Entry, AutoType, FieldReferences, OTP |
| `model::group` | Group hierarchy |
| `model::meta` | Icons, Tags, CustomData, Templates |
| `kdbx` | KDBX file I/O, KDF, merge, repair, search, XML, stream |
| `kdbx::file` | KDB / KDBX 3.1 / KDBX 4.0 readers & writers |
| `kdbx::kdf` | AES-KDF, Argon2 key derivation |
| `kdbx::xml` | XML serialization / deserialization |
| `kdbx::stream` | HashedBlock (3.1), HMAC Block (4.0) streams |
| `kdbx::merge` | Three-way database merge |
| `kdbx::repair` | Integrity verification and repair |
| `kdbx::search` | Regex-based entry search |
| `kdbx::signature` | ECDSA / RSA digital signature verification |

---

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Application Layer                     │
│          Android (JNI) │ HarmonyOS (NAPI) │ Flutter      │
├─────────────────────────────────────────────────────────┤
│                      keepass-rs                          │
│  ┌──────────┐  ┌──────────┐  ┌────────────────────────┐ │
│  │  crypto   │  │  model   │  │         kdbx           │ │
│  │ AES       │  │ Database │  │ file/  kdf/  xml/      │ │
│  │ ChaCha20  │  │ Entry    │  │ merge  repair  search  │ │
│  │ Twofish   │  │ Group    │  │ stream  fuzz           │ │
│  │ Argon2    │  │ Node     │  │ signature  variant_dict│ │
│  └──────────┘  └──────────┘  └────────────────────────┘ │
├─────────────────────────────────────────────────────────┤
│                   Rust Crypto Primitives                  │
│            aes · chacha20 · twofish · argon2 · sha2      │
└─────────────────────────────────────────────────────────┘
```

---

## 🧪 Testing

```bash
# Run all tests (220 tests)
cargo test

# Run with clippy (0 warnings)
cargo clippy -- -D warnings

# Run e2e roundtrip tests
cargo test --test e2e_roundtrip

# Format check
cargo fmt --check
```

### Test Coverage

| Module | Tests | Key Coverage |
|--------|-------|--------------|
| `crypto` | 25 | AES, ChaCha20, Twofish, Salsa20, Argon2, Hash, HMAC |
| `model` | 95 | Database, Entry, Group, OTP, Binary, Codec, UUID |
| `kdbx::xml` | 5 | XML roundtrip, protected fields, special chars, nested groups |
| `kdbx::merge` | 12 | Three-way merge, conflict detection |
| `kdbx::repair` | 8 | Integrity verification, auto-repair |
| `kdbx::search` | 6 | Regex search, tag filter |
| `kdbx::stream` | 10 | HashedBlock, HMAC Block read/write |
| `e2e` | 7 | KDB/KDBX31/KDBX4 full roundtrip with real data |

---

## 📚 Documentation

| Document | Description |
|----------|-------------|
| [KeePassDX Compatibility](docs/keepass-dx-compatibility.md) | API compatibility with KeePassDX 4.x |
| [KeePassXC Compatibility](docs/keepassxc-compatibility.md) | API compatibility with KeePassXC |
| [Project Integrity Assessment](docs/project-integrity-assessment.md) | Code quality and optimization report |

---

## 🔧 Examples

| Example | Description |
|---------|-------------|
| `basic_usage` | Open, read, modify, save a database |
| `search` | Regex search across entries |
| `create_test_kdbx` | Create a test KDBX file for the kdbx2json demo |
| `keepass-jni` | Android JNI bridge (Kotlin interop) |
| `keepass-ohos` | HarmonyOS NAPI bridge (ArkTS interop) |
| `kdbx2json` | Convert KDBX to JSON (CLI tool) |
| `flutter_rust_bridge` | Flutter integration via flutter_rust_bridge (Dart interop) |

---

## 📋 Requirements

- **Rust** 1.77+ (MSRV)
- **Platforms**: Linux, macOS, Windows, Android, HarmonyOS NEXT
- **Dependencies**: `aes`, `chacha20`, `twofish`, `argon2`, `sha2`, `hmac`, `quick-xml`, `uuid`, `base64`, `flate2`, `cipher`, `p256`, `rsa`

---

## 📄 License

Licensed under either of:

- **MIT License** ([LICENSE](LICENSE))
- **木兰公共许可证 第2版 (MulanPSL-2.0)** ([LICENSE](LICENSE))

at your option.

---

## 🙏 Acknowledgments

- [KeePass](https://keepass.info/) — Original password manager
- [KeePassDX](https://github.com/Kunzisoft/KeePassDX) — Android KeePass client (compatibility reference)
- [ohos-rs](https://github.com/ohos-rs) — HarmonyOS Rust bindings
- [napi-rs](https://github.com/napi-rs/napi-rs) — Node.js NAPI bindings for Rust
