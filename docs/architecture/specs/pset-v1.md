# PinsetStore File Format

Table of contents

TODO: specifiy size of peer_id_len to be [u8; 32] for v1 since only AES-256-GCM is usable 

## 1. Introduction

This document specifies the on-disk file format for the `PinsetStore`, a secure, local store of peer identity pins used by the P2P password manager.

A PinsetStore file:

* Contains a header with metadata (AEAD algorithm, key source, store identifier, nonce, an optional key,management parameters), followed by
* A single AEAD-sealed body containing one or more pins records.

The format is designed to be:

* Compact and binary, suitable for long-term storage.
* Extensible, via TLV-encoded optional header fields.
* Strict, with clearly defined invariants to avoid ambiguous on insecure interpretations.

The canonical magic for this format is

```text
"PSET" (0x50, 0x53, 0x45, 0x54)
```

## 2. Terminology

* PSET file: A single PinsetStore file on disk.
* Header: Unencrypted prefix containing metadata and TLV-encoded options.
* Body: AEAD-sealed payload containing pin records.
* AEAD: Authenticated encryption with associated data (e.g. AES-GCM).
* KEK: Key Encryption Key (e.g. OS keystore key or KDF-derived key).
* DEK/FEK: Data/File Encryption Key used ot encrypt the body.
* TLV: Type-Length-Value encoding.

Normative keywords **MUST**, **SHOULD**, and **MAY** are to be interpreted as in [["RFC2119"](https://www.rfc-editor.org/rfc/rfc2119)].

## 3. Versioning and Magic

### 3.1. Magic

Every PSET file **MUST** begin with the 4-byte magic:

```text
"PSET" (0x50 0x53 0x45 0x54)
```

If the magic does not match, one **MUST** reject the file with a BadMagic-style error.

### 3.2. Version

* `version` is a single u8 field immediately following the magic.
* This RFC defines `version = 1` ("PSET v1").
* Implementations **MUST** reject version 0.
* Implementations **MUST** reject unknown versions (i.e. any version implementations do not explicitly support).

Future file format revisions may define additional versions and semantics.

### 4. High-Level Layout

A PSET file is laid out as:

```text

+-------------------------+
| Header (unencrypted)    |
+-------------------------+
| Body (AEAD-sealed blob) |
+-------------------------+
```

// TODO make a more detailed lay out and one with sizes like in RFC 768

### 5.1. Header Layout (Fixed Prefix + TLVs)

The header consists of a fixed-size prefix followed by a TLV section:

```text
offset  size  field
------  ----  --------
0       4     MAGIC = "PSET"
4       1     version (u8)
5       1     aead_alg (u8)
6       1     key_source (u8)
7       8     seq (u64, big-endian)
15      16    store_id (16 bytes)
31      12    nonce (12 bytes)
43      ...   TLV section (0 or more TLVs, then TLV_END)
```

### 5.2. Body Layout (Inside AEAD)

The body is a single AEAD ciphertext, which, when successfully decrypted yields:

```text
offset  size  field
------  ----  --------
0       4     record_count (u32, big-endian)
4       ...   records[record_count]
```

Each record is encoded in a fixed sequence described in §8.

The entire body, from `record_count` through the end of the last record, is AEAD-protected using parameters derived from the header (key source, KDF, KEK, wrap). The exact key management policy is out of the scope for this document, §7 provides informational guidance.

## 6. Header Fields

### 6.1. AEAD Algorithm (aead_alg)

* Type: u8
* Mapping:

```text
1 = AES-GCM
```

* Implementations **MUST** reject any unknown `aead_alg` value.

AES-GCM uses a 96-bit (12-byte) nonce. For `AeadAlgorithm::AesGcm`, the nonce field **MUST** be exactly 12 bytes.

### 6.2. Key Source (key_source)

* Type: u8
* Mapping:

```text
1 = OsKeyStore    (KeySource::OsKeyStore)
2 = PassphraseKdf (KeySource::PassphraseKdf)
```

* Implementations **MUST** reject unknown `key_sources` values.

The key source determines how the KEK/DEK are obtained:

* OsKeyStore: the KEK is obtained form an OS-specific keystore API, optionally guided by `kek_locator`.
* PassphraseKdf: the KEK is derived from the user passphrase using a KDF described in the kdf TLV.

### 6.3. Sequence Number (seq)

* Type: u64, big-endian.
* Semantics:
  * Monotonic sequence number incremented on each store write.
  * Intended for use in nonce derivation and/or anti-rollback checks.

Implementations **SHOULD** treat `seq` as monotonically increasing per PSET file and **MAY** validate monotonically increasing `seq` across loads, depending on how they track prior state.

### 6.4. Store Identifier (store_id)

* Type: 16-byte opaque value.
* Semantics:
  * Uniquely identifies a PinsetStore.
  * May be used as a salt or domain separation constant in key derivation or other cryptographic operations.

This RFC does not constrain the generation method beyond requiring uniqueness per logical store.

### 6.5. Nonce (nonce)

* Type: 12-byte array (96 bits).
* For `aead_alg` = `AES-GCM`, this **MUST** be 12 bytes.

The PSET format does not mandate how the nonce is constructed, only that:

* Implementations **MUST NOT** reuse a (key, nonce) pair for AES-GCM.
* Implementations **SHOULD** ensure nonces are either:
  * Generated randomly with negligible collision probability, or
  * Derived from `seq` and/or other unique data in a collision-resistant way.

The `validate` method in the reference implementation enforces nonce length consistency with `aead_alg`.

## 7. Header TLV Section

After the fixed header fields, a sequence of TLVs encodes optional header parameters. The TLV section is terminated by a single `TLV_END` byte.

### 7.1. TLV Encoding

Each TLV (except `TLV_END`) is encoded as:

```text
+--------+--------------+-----------+
| 1 byte | 2 bytes (BE) | len bytes |
+--------+--------------+-----------+
|  type  | length (u16) |   value   |
+--------+--------------+-----------+
```

* type: TLV tag (u8).
* length: big-endian u16 length of value.
* value: raw bytes.

Length must fit into u16; values longer than 65535 **MUST** be rejected.

The TLV section ends when a single byte with value `TLV_END` is encountered, with no length or value following it.

### 7.2. TLV tags

Current tags:

```text
0x01  = KDF         (TLV_KDF)
0x02  = KEK_LOCATOR (TLV_KEK_LOCATOR)
0x03  = WRAP        (TLV_WRAP)
0x07F = END         (TLV_END, no length/value)
```

#### 7.2.1. TLV_KDF (0x01)

* Value: UTF-8 string.
* Semantics:
  * Encodes KDF configuration when `key_source = PassphraseKdf`.
  * String format is implementation-defined (e.g. "argon2id:v=19,m=...,t=...,p=...").

If `TLV_KDF` is present:

* Value **MUST** be valid UTF-8.
* Implementations **MUST** reject invalid UTF-8 in this field.

#### 7.2.2. TLV_KEK_LOCATOR (0x02)

* Value: serialized OS-native string bytes.
* Semantics:
  * Provides an opaque locator for retrieving a KEK from the OS keystore.
  * Encoding/decoding of `OsStr` is platform-specific.

Readers **MUST** treat this value as opaque bytes and must not assume UTF-8 encoding.

#### 7.2.3. TLV_WRAP (0x03)

* Value: arbitrary bytes.
* Semantics:
  * Contains a wrapped key (e.g. DEK/FEK wrapped under a KEK).
  * The interpretation is up to the key-management layer.

Readers **MUST** not interpret the `wrap` payload at the file-format layer; it is
an opaque ciphertext blob.

#### 7.2.4. TLV_END (0x07F)

* Single byte (no following length of value).
* Marks the end of the TLV section.

### 7.3. Unknown TLV tags

In PSET v1:

* Unknown TLV tags **MUST** cause the file to be rejected

Future versions may relax this and allow forward-compatible ignoring of unknowns tags.

## 8. Body and Record Encoding

The body is AEAD-encrypted and authenticated. After successful decryption, parsing
proceeds as described in this section.

### 8.1. Body prefix

```text
offset  size  field
------  ----  ------------------------------
0       4     record_count (u32, big_endian)
4       ...   records[record_count]
```

* `record_count` is the number of records encoded.
* Implementations **SHOULD** reject absurdly large `record_count` values (e.g. those that would exceed memory limits), but the exact threshold is implementation-defined.

### 8.2. PinsetRecord Layout

Each `PinsetRecord` is encoded in the following order:

```text
offset  size         field
------  ----         ----------
0       2            peer_id_len (u32, big-endian)
2       peer_id_len  peer_id     (**MUST** be 32 bytes)
...     1            key_type    (u8)
...     2            key_len     (u16, big-endian)
...     key_len      key_data
...     8            added_at    (i64, big-endian; Unix timestamp)
...     1            has_expires (u8; 0 or 1)
...     [8]          expires_at  (i64; big-endian; if has_expires == 1)
...     1            flags       (u8)
```

#### 8.2.1. peer_id_len and peer_id

// TODO: change

* `peer_id_len` is a u16 length; in v1 it **MUST** equal 32.
* Implementation **MUST** reject any record where `peer_id_len` != 32.
* `peer_id` is then exactly 32 bytes.

#### 8.2.2. key_type

* Type: u8
* Mapping:

```text
1 = Ed25519
2 = Spki 
3 = PqHybrid
```

* Implementation **MUST** reject unknown `key_type` values.

`PqHybrid` is reserved for hybrid post-quantum schemes.

#### 8.2.3. key_len and key_data

* `key_len`: u16, big-endian.
* `key_data:key_len` bytes, zeroized

If `key_len` does not match the subsequent number of bytes, or if `key_len` is unreasonably large, implementation **SHOULD** reject the file.

#### 8.2.4. added_at

* Type: signed 64-bit Unix timestamp (i64, seconds since Unix epoch), big-endian.

If the timestamp cannot be represented as a valid `DateTime` (e.g. out-of-range), implementation **MUST** reject the record.

#### 8.2.5. has_expires and expires_at

* `has_expires` is a u8 flag:
  * 0 -> no expiry; `expires_at` field is omitted.
  * 1 -> `expires_at` is present and must be read.
* If `has_expires == 1`, an `expires_at` timestamp follows:
  * Type: i64 Unix timestamp, big-endian.

Invalid timestamps **MUST** cause the record (and file) to be rejected.

#### 8.2.6. flags

`flags` is a u8 bitfield represented as a `PinsetFlags`.

Current bit assignments:

```text
bit 0   (0b0000_0001): ACTIVE
bit 1   (0b0000_0010): RETIRED
bit 2   (0b0000_0100): TOFU
bit 3-7 (0b1111_1000): RESERVED (**MUST** be 0 in v1)
```

* `ACTIVE` and `RETIRED` are mutually exclusive; both set at once is considered invalid logically.
* If ant reserved bit is set, `PinsetFlags::from_bits` returns `None`, and the file **MUST** be rejected with an "invalid flags bits" error.

## 9. Validation Rules

### 9.1 Header Validation

A valid PSET v1 header **MUST** satisfy:

1. `MAGIC == b"PSET"`.
2. `version == 1`.
3. `aead_alg` is recognized (currently `1 = AES-GCM`).
4. `key_source` is recognized (1 or 2).
5. `nonce` length equals `aead_alg` `nonce` length (i.e 12 bytes for AES-GCM).
6. TLV section:

* TLVs are correctly structured.
* Lengths fit into u16.
* `TLV_KDF` values are valid UTF-8.
* `TLV_END` appears exactly once, terminating the TLV section.
* No unknown TLV tags appear

Any violation **MUST** cause decoding to fail.

### 9.2. Record Validation

Each record **MUST** satisfy:

1. `peer_id_len` is 32.
2. `key_type` is recognized.
3. `key_len` matches the number of following bytes.
4. `added_at` and (if present) `expires_at` are valid timestamps.
5. `flags` contains only defined bits (`ACTIVE`, `RETIRED`, `TOFU`); reserved bits are zero.

Higher-level logic **MUST** enforce logical invariants such as

* Not both **ACTIVE** and **RETIRED**.
* `expires_at` not earlier than `added_at`, if both are present.

## 10. Security Considerations

* AEAD Nonce Uniqueness: Implementations **MUST NOT** reuse the same (key, nonce) pair for AES-GCM. This RFC defines the nonce field and its length but leaves the derivation scheme to the implementation.
* Key Zeroization: `key_data` and `wrap` are represented as Zeroizing buffers in the reference implementation and **SHOULD** be wiped from memory when no longer needed.

// TODO: maybe change?

* Strict Parsing: Unknown algorithms, key types, TLV tags, or invalid flags **MUST** cause decoding to fail, rather than be ignored, to avoid silent downgrade or misinterpretation.

## 11. Compatibility and Extensibility

Future versions may:

* Introduce new `aead_alg` values.
* Introduce new `key_types`.
* Relax TLV handling to allow unknown tags to be ignored.
* Define semantics for currently reserved `flags` bits.

Any such expansions **MUST NOT** violate the invariants specified for v1 files.