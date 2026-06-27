# QVKey v1 Binary Format Spec

:::warning DISCLAIMER
This codebase is AI-generated and has not undergone security audits.
:::

QuantumVault serializes hybrid cryptographic keys into unified single-file formats ending in `.qvk`.

## Binary Structure

A `.qvk` file layout consists of:

| Offset (Bytes) | Size (Bytes) | Field Name | Description |
|---|---|---|---|
| `0` | `3` | **Magic Bytes** | ASCII "QVK" |
| `3` | `1` | **Version** | Version code (current: `0x01`) |
| `4` | `1` | **Key Type** | Type of key (e.g. `0x01` Public, `0x02` Secret) |
| `5` | `8` | **Timestamp** | 64-bit Little-Endian creation time (Unix epoch) |
| `13` | `2` | **Metadata Size** | 16-bit Little-Endian length of the JSON metadata block |
| `15` | `N` | **JSON Metadata** | UTF-8 encoded custom JSON metadata (comments, labels, etc.) |
| `15 + N` | `4` | **Payload Size** | 32-bit Little-Endian length of the cryptographic payload |
| `19 + N` | `P` | **Payload** | Raw key bytes (KEM secret/public keys, DSA secret/public keys, etc.) |
| `19 + N + P` | `32` | **Checksum** | BLAKE3 checksum computed over all preceding bytes |
