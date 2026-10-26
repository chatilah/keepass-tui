# keepass-rs

[![CI](https://github.com/meission/keepass-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/meission/keepass-rs/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20%2B%20MulanPSL--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/MSRV-1.77%2B-orange.svg)](Cargo.toml)
[![Tests](https://img.shields.io/badge/tests-220%20passing-brightgreen.svg)]()

平台无关的 KeePass 数据库 Rust 库。
目标支持 KDB (v1)、KDBX 3.1 和 KDBX 4.0 文件格式。
兼容 [KeePassDX](https://github.com/Kunzisoft/KeePassDX)，适用于 Flutter 业务层集成。

**[English](README.md)**

---

## ✨ 特性

### 文件格式

| 格式 | 读取 | 写入 | 说明 |
|------|------|------|------|
| **KDB v1** | ✅ | ✅ | KeePass 1.x 格式 |
| **KDBX 3.1** | ✅ | ✅ | KeePass 2.x (4.0 之前) |
| **KDBX 4.0** | ✅ | ✅ | KeePass 2.47+，二进制附件池 |

### 加密算法

| 算法 | 模式 | 用途 |
|------|------|------|
| **AES-256** | CBC | 数据库加密（默认） |
| **ChaCha20** | 流 | KDBX 4.0 内部流加密 |
| **Twofish** | CBC | 可选数据库加密 |
| **Salsa20** | 流 | KDBX 3.1 内部流加密 |

### 密钥派生

| KDF | 参数 | 用途 |
|-----|------|------|
| **AES-KDF** | 轮次（默认 6000） | KDBX 3.1 |
| **Argon2d** | 内存、迭代次数、并行度 | KDBX 4.0 默认 |
| **Argon2id** | 内存、迭代次数、并行度 | KDBX 4.0 可选 |

### 核心能力

- 🔐 **完整加密** — AES-256、ChaCha20、Twofish、Salsa20
- 🗝️ **密钥派生** — AES-KDF、Argon2d、Argon2id
- 🔍 **正则搜索** — 标题、用户名、URL、备注、标签
- 🔀 **三路合并** — 冲突检测与解决
- 🛠️ **完整性修复** — 自动数据库修复
- 🔑 **OTP 支持** — TOTP / HOTP，支持 SHA-1/256/512
- ✍️ **数字签名** — ECDSA (P-256) / RSA 签名验证
- 📊 **变更追踪** — 差异对比与审计日志
- 🧪 **模糊测试** — 针对畸形输入的鲁棒性测试
- 📱 **多平台** — Android JNI、HarmonyOS NAPI、Flutter FRB

---

## 🚀 快速开始

添加到 `Cargo.toml`：

```toml
[dependencies]
keepass-rs = "0.1"
```

### 打开已有数据库

```rust
use keepass_rs::{open_database, CompositeKey};
use std::fs::File;

let file = File::open("database.kdbx")?;
let key = CompositeKey::new().with_password(b"mypassword");
let db = open_database(file, &key)?;

println!("数据库名: {}", db.name);
println!("条目数: {}", db.entries.len());
```

### 搜索条目

```rust
use keepass_rs::{SearchHelper, SearchParameters};

let params = SearchParameters::new("github");
let entries: Vec<&Entry> = db.entries.values().collect();
let results = SearchHelper::search_entries(&entries, &params);

for r in &results {
    println!("找到: {} - {}", r.entry.title, r.entry.url);
}
```

### 修改并保存

```rust
use keepass_rs::{save_database, NodeId};
use keepass_rs::model::entry::Entry;
use keepass_rs::model::core::security::ProtectedString;

let entry_id = NodeId::new_uuid();
let mut entry = Entry::new(entry_id);
entry.title = "新条目".to_string();
entry.username = ProtectedString::new_plain("user@example.com");
entry.password = ProtectedString::new_protected("s3cret!");

if let Some(root) = &mut db.root_group {
    root.add_child_entry(entry_id);
}
db.entries.insert(entry_id, entry);

let mut out = File::create("output.kdbx")?;
save_database(&mut out, &db, &key)?;
```

### 创建新数据库

```rust
use keepass_rs::model::db::database::{Database, DatabaseVersion};
use keepass_rs::model::db::composite_key::CompositeKey;
use keepass_rs::model::group::Group;
use keepass_rs::model::core::node::NodeId;
use keepass_rs::save_database;

let mut db = Database::new(DatabaseVersion::KDBX4);
db.name = "我的数据库".to_string();

let root_id = NodeId::new_uuid();
let root = Group::new(root_id);
db.root_group = Some(root);

let key = CompositeKey::new().with_password(b"masterpassword");

let mut out = File::create("new.kdbx")?;
save_database(&mut out, &db, &key)?;
```

### TOTP 计算

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

## 📱 平台集成

### Android (JNI)

```kotlin
// Kotlin 调用
val db = KeePassLib.openDatabase(file, "password")
val entries = db.searchEntries("github")
```

完整 JNI 桥接见 [examples/keepass-jni](examples/keepass-jni/)。

### HarmonyOS NEXT (NAPI)

```typescript
// ArkTS 调用
const db = keepass.openDatabase(filePath, 'password')
const entries = db.searchEntries('github')
```

完整 NAPI 桥接见 [examples/keepass-ohos](examples/keepass-ohos/)。

### Flutter

```dart
// 通过 flutter_rust_bridge
final db = await api.openDatabase(path: filePath, password: 'password');
final entries = await api.searchEntries(query: 'github');
```

Flutter 集成见 [examples/flutter_rust_bridge](examples/flutter_rust_bridge/)。

---

## 📦 模块总览

| 模块 | 说明 |
|------|------|
| `crypto` | 加密原语（AES、ChaCha20、Twofish、Salsa20、Argon2） |
| `model` | 数据模型（Database、Entry、Group、Node、Icon、OTP） |
| `model::core` | 基础类型（NodeId、DateInstant、ProtectedString） |
| `model::db` | Database、CompositeKey、ChangeTracker |
| `model::entry` | Entry、AutoType、FieldReferences、OTP |
| `model::group` | Group 层级结构 |
| `model::meta` | Icon、Tag、CustomData、Template |
| `kdbx` | KDBX 文件 I/O、KDF、合并、修复、搜索、XML、流 |
| `kdbx::file` | KDB / KDBX 3.1 / KDBX 4.0 读写器 |
| `kdbx::kdf` | AES-KDF、Argon2 密钥派生 |
| `kdbx::xml` | XML 序列化 / 反序列化 |
| `kdbx::stream` | HashedBlock (3.1)、HMAC Block (4.0) 流 |
| `kdbx::merge` | 三路数据库合并 |
| `kdbx::repair` | 完整性验证与修复 |
| `kdbx::search` | 正则表达式条目搜索 |
| `kdbx::signature` | ECDSA / RSA 数字签名验证 |

---

## 🏗️ 架构

```
┌─────────────────────────────────────────────────────────┐
│                       应用层                              │
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
│                    Rust 加密原语                           │
│            aes · chacha20 · twofish · argon2 · sha2      │
└─────────────────────────────────────────────────────────┘
```

---

## 🧪 测试

```bash
# 运行全部测试（220 个测试）
cargo test

# 运行 clippy（0 警告）
cargo clippy -- -D warnings

# 运行端到端往返测试
cargo test --test e2e_roundtrip

# 格式检查
cargo fmt --check
```

### 测试覆盖

| 模块 | 测试数 | 关键覆盖 |
|------|--------|----------|
| `crypto` | 25 | AES、ChaCha20、Twofish、Salsa20、Argon2、Hash、HMAC |
| `model` | 95 | Database、Entry、Group、OTP、Binary、Codec、UUID |
| `kdbx::xml` | 5 | XML 往返、加密字段、特殊字符、嵌套分组 |
| `kdbx::merge` | 12 | 三路合并、冲突检测 |
| `kdbx::repair` | 8 | 完整性验证、自动修复 |
| `kdbx::search` | 6 | 正则搜索、标签过滤 |
| `kdbx::stream` | 10 | HashedBlock、HMAC Block 读写 |
| `e2e` | 7 | KDB/KDBX31/KDBX4 完整往返 |

---

## 📚 文档

| 文档 | 说明 |
|------|------|
| [KeePassDX 兼容性报告](docs/keepass-dx-compatibility.md) | 与 KeePassDX 4.x 的 API 兼容性分析 |
| [KeePassXC 兼容性报告](docs/keepassxc-compatibility.md) | 与 KeePassXC 的 API 兼容性分析 |
| [项目完整性评估](docs/project-integrity-assessment.md) | 代码质量与优化报告 |

---

## 🔧 示例

| 示例 | 说明 |
|------|------|
| `basic_usage` | 打开、读取、修改、保存数据库 |
| `search` | 正则搜索条目 |
| `create_test_kdbx` | 为 kdbx2json 演示创建测试 KDBX 文件 |
| `keepass-jni` | Android JNI 桥接（Kotlin 互操作） |
| `keepass-ohos` | HarmonyOS NAPI 桥接（ArkTS 互操作） |
| `kdbx2json` | KDBX 转 JSON（CLI 工具） |
| `flutter_rust_bridge` | Flutter 集成（Dart 互操作） |

---

## 📋 环境要求

- **Rust** 1.77+（MSRV）
- **平台**：Linux、macOS、Windows、Android、HarmonyOS NEXT
- **依赖**：`aes`、`chacha20`、`twofish`、`argon2`、`sha2`、`hmac`、`quick-xml`、`uuid`、`base64`、`flate2`、`cipher`、`p256`、`rsa`

---

## 📄 许可证

双重许可，可任选其一：

- **MIT 许可证**（[LICENSE](LICENSE)）
- **木兰公共许可证 第2版 (MulanPSL-2.0)**（[LICENSE](LICENSE)）

---

## 🙏 致谢

- [KeePass](https://keepass.info/) — 原始密码管理器
- [KeePassDX](https://github.com/Kunzisoft/KeePassDX) — Android KeePass 客户端（兼容性参考）
- [ohos-rs](https://github.com/ohos-rs) — HarmonyOS Rust 绑定
- [napi-rs](https://github.com/napi-rs/napi-rs) — Node.js NAPI Rust 绑定
