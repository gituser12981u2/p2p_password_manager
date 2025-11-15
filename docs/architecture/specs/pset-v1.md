# PinsetStore File Format

Table of contents

## 1. Introduction

This document specifies the on-disk file format for the `PinsetStore`, a secure, local store of peer identitiy pins used by the P2P password manager.

A PinsetStore file:

* Contains a header with metadata ( AEAD algorithm, key source, store identifier, nonce, an optional key,management parameters), followed by
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

### 5.1 Header Layout (Fixed Prefix + TLVs)

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

### 5.2 Body Layout (Inside AEAD)

The body is a single AEAD ciphertext, which, when successfully decrypted yields:

```text
offset  size  field
------  ----  --------
0       4     record_count (u32, big-endian)
4       ...   records[record_count]
```

Each record is encoded in a fixed sequence described in §8.

The entire body, from record_count through the end of the last record, is AEAD-protected using parameters derived from the header (key source, KDF, KEK, wrap). The exact key management policy is out of the scope for this document, §7 provides informational guidance.

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

The TLV section ends when a single byte with value TLV_END is encountered, with no length or value following it.

### 7.2. TLV tags

Current tags:
