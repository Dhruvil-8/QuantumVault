# C API Reference

:::warning DISCLAIMER
This codebase is AI-generated and has not undergone security audits.
:::

The FFI interface is defined in [quantumvault.h](../quantumvault-ffi/quantumvault.h).

## Handle Allocation

```c
struct QVIdentityHandle *qv_identity_generate(void);
void qv_identity_free(struct QVIdentityHandle *handle);

struct QVPublicKeyHandle *qv_public_key_from_bytes(const uint8_t *buf, uintptr_t buf_len);
void qv_public_key_free(struct QVPublicKeyHandle *handle);
```

---

## Key Export

```c
enum QVStatus qv_identity_export_public(
    const struct QVIdentityHandle *handle,
    uint8_t *buf,
    uintptr_t buf_len,
    uintptr_t *out_len
);

enum QVStatus qv_identity_export_secret(
    const struct QVIdentityHandle *handle,
    uint8_t *buf,
    uintptr_t buf_len,
    uintptr_t *out_len
);
```

---

## Encryption/Decryption

```c
enum QVStatus qv_encrypt(
    const uint8_t *data,
    uintptr_t data_len,
    const struct QVPublicKeyHandle *recipient,
    const struct QVIdentityHandle *sender,
    uint8_t *buf,
    uintptr_t buf_len,
    uintptr_t *out_len
);

enum QVStatus qv_decrypt(
    const uint8_t *envelope,
    uintptr_t envelope_len,
    const struct QVIdentityHandle *recipient,
    const struct QVPublicKeyHandle *sender_pub,
    uint8_t *buf,
    uintptr_t *buf_len
);
```
