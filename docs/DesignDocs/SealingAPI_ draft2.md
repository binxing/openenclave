# Open Enclave Sealing API (Draft 2)

This document describes API functions provided by the Open Enclave SDK for
sealing/unsealing data against an enclave's identity.

## Motivation

Sealing is an important capability of TEEs, which allows an enclave to encrypt
and/or integrity-protect data at rest, using keys (aka., sealing keys) derived
from the enclave's own identity. TEEs may have distinct formulas for key
derivation and may support different key lengths. And that leads to the desire
for a TEE-agnostic sealing API.

### Objectives

1. *Comprehensive* - All TEE specific features/options should be accessible to developers when needed.
2. *Crypto-agile* - Different implementations may choose different crypto algorithms.
   - Allow multiple implementations to coexist in an enclave - This is needed for migration from one implementation to another.
3. *User friendly* - Most developers just have the simple need of persisting data securely, without the desire of digging into crypto or TEE specific details.
   - *TEE-agnostic* - Allow TEE-agnostic code by providing reasonable defaults for TEE specific features/options.
   - *Easy to use* - Not be cumbersome for the majority of use cases.
   - *Authenticated Encryption* - Most developers are not cryptographic experts and may have difficulty in choosing what aspects (i.e. confidentiality and/or integrity) of data to protect.
4. *Interoperable with existing SDKs* - It's desirable that a blob sealed by an enclave built with the Open Enclave SDK could be unsealed by another enclave built with a different SDK (e.g., the Intel SGX SDK), or vice versa.

### Non-Objectives

- Cross-device sealing is not supported.
  - Sealing/unsealing must be done on the same device.
- Cross-TEE sealing is not supported.
  - Sealing/unsealing must be done in the same type of TEE.

## Rationale

```C
oe_result_t oe_seal(
    const oe_seal_key_info_t* key_info,
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t **blob,
    size_t *blob_size);

oe_result_t oe_unseal(
    uint8_t* blob,
    size_t blob_size,
    uint8_t** plaintext,
    size_t* plaintext_size);

oe_result_t oe_initialize_seal_key_info(
    oe_seal_key_info_t* key_info,
    oe_seal_policy_t seal_policy,
    const uint8_t* entropy,
    size_t entropy_size);
```

The the sealing APIs are listed above. Most of the function parameters are self-explanatory. This section explains some of the architectural decisions behind them.

More details can be found in [Specification](#specification) later in this document on the parameters and behaviors of those APIs.

### Seal Key Derivation

`oe_seal` uses `*key_info` (of type `oe_seal_key_info_t`) to dictate the derivation of seal keys. `oe_seal_key_info_t` is a TEE specific structure.

On SGX, `oe_seal_key_info_t` is the same as the `sgx_key_request_t` strcuture, which is the input to the `EGETKEY` instruction for key derivation.

```C
typedef sgx_key_request_t oe_seal_key_info_t;
```

On OP-TEE, *TSK* (*Trusted Application Storage Key*) serves as the *KEK* (*Key Encryption Key*) for encrypting *FEK*s (*File Encryption Key*s) in *ECB* mode. Hence, `oe_seal_key_info_t` could be simply the ciphertext of a seal key. Please note that all OP-TEE keys are 256-bit AES keys. **Open:** Is my understanding correct?

```C
typedef _optee_seal_key_info_t {
    uint8_t encrypted_seal_key[32];
} oe_seal_key_info_t;
```

### TEE Agnostic

Most developers just have the simple need of persisting data securely and desire an API to initialize `oe_seal_key_info_t` with TEE defaults, so that they don't have to touch any TEE specifics. Moreover, even TEE specific enclave code can benefit from such an API as it's easier to modify selective fields than setting up the whole `oe_seal_key_info_t` structure from scratch.

`oe_initialize_seal_key_info()` is the API for initializing an `oe_seal_key_info_t` structure with TEE specific defaults.

`seal_policy` has the same definition as the existing `oe_get_seal_key_by_policy()` API.

- SGX supports both `OE_SEAL_POLICY_UNIQUE` and `OE_SEAL_POLICY_PRODUCT`.
- A TEE should return `OE_UNSUPPORTED` if an unsupported policy is being requested.
  - **Open:** In OP-TEE, it seems the only thing that matters is the TA's UUID. So only `UNIQUE` or `PRODUCT` can be supported, depending on whether the UUID identifies a single TA or a group of TAs.

`entropy`/`entropy_size` supplies a buffer of arbitrary size to be mixed into the seal key.

- If `entropy` is `NULL` and
  - If `entropy_size` is `OE_SEAL_NO_ENTROPY` (`0`), no additional entropy will be added to `*key_info`.
  - If `entropy_size` is `OE_SEAL_MAX_ENTROPY` (`-1`), a TEE specific number of random bytes will be added to `*key_info`.
  - Otherwise, the specified number of random bytes will be added. Please note that this is necessary only if the device's RNG is biased.
- If `entropy` is not `NULL` and
  - If `entropy_size` is at or below a TEE specific size, the byte array pointed to by `entropy` will be added to `*key_info` directly.
  - If `entropy_size` is above a TEE specific size, the byte array will be hashed before being added to `*key_info`.

The reason for `entropy` and `entropy_size` is to allow multiple seal keys.

- On SGX, `entropy` serves as `KEYID` for `EGETKEY`.
- On OP-TEE, `entropy` serves as the encrypted seal key. This will work for any block cipher secure against ciphertext only attack, such as AES.

### Crypto-agility

`oe_seal()` doesn't offer choices of cipher/mode or accept cipher related parameters. Reasons include

1. The implementation understands the TEE specifics so can do a better job than average developers.
   - Cipher - Each TEE has its preferred cipher. E.g., SGX (or x86_64 processors in general) favors AES because of AES-NI.
   - Integrity Protection - Each TEE has its preferred hash or authenticated encryption algorithms. E.g., SGX favors SHA-256 and GCM because of SHA-NI and the `PCLMULQDQ` instruction.
   - Key Length - Each TEE has its preferred key length due to its hardware or software architectures. E.g., SGX employs 128-bit fuse keys so favors 128-bit keys, while OP-TEE uses 256-bit keys only.
2. There's no need to support multiple crypto algorithms for most uses.
   - Both the sealer and the unsealer must come from the same vendor (usually manifested as signed by the same private key) so there's no reason they cannot agree on a single algorithm offline. With that said, only one crypto algorithm would be needed, hence there'd be no choice of algorithms.
   - An enclave developer can choose the algorithm at build time, by linking the desired sealing library, or by providing his/her own implementation of `oe_seal()` and `oe_unseal()`.
   - Multiple sealing libraries can still be linked into a single enclave to support migrating sealed blobs from one implementation to another. More details are presented in this section.
3. Simple APIs lead to simple implementations.
   - Given the simply API definitions, it'll be easy for developers to put in their own implementions when a desired algorithm is missing.

To allow switching between implementations, each should be packaged in its own library, preferrably suffixed with the algorithm name. E.g., `liboeseal_gcm_aes.a`, `liboeseal_sm4_hmac_sha256.a`, etc.

To allow multiple implementations to coexist in the same enclave image, weak symbols must be used.

- Each function should have a strong, library specific symbol name. E.g., `oe_seal_gcm_aes()` and `oe_unseal_gcm_aes()`.
  - Library specific names allows the functions to be referenced explicitly, especially when multiple implementations coexist in the same enclave.
- Each function should be aliased to a weak, generic symbol name. E.g., `oe_seal()` and `oe_unseal()`.
  - Generic symbols allow switching between implementations seamlessly at link time.

**Open:** Weak symbols are supported by ELF only. What object file format is used on Windows build?

The code snippets below demonstrate how to implement `oe_seal()`/`oe_unseal()` using 2 different algorithms.

In `seal_algo1.c`, we define the strong symbol `oe_seal_algo1()` and its weak alias `oe_seal()`.

```C
oe_result_t oe_seal_algo1(
    const oe_seal_key_info_t* key_info,
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t **blob,
    size_t *blob_size)
{
    // Implemented using algo1 ...
}

oe_result_t oe_seal(
    const oe_seal_key_info_t* key_info,
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t **blob,
    size_t *blob_size) __attribute__((weak, alias("oe_seal_algo1")));
```

Similarly, we define the strong symbol `oe_seal_algo2()` and its weak alias `oe_seal()` in `seal_algo2.c`.

```C
oe_result_t oe_seal_algo2(
    const oe_seal_key_info_t* key_info,
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t **blob,
    size_t *blob_size)
{
    // Implemented using algo2 ...
}

oe_result_t oe_seal(
    const oe_seal_key_info_t* key_info,
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t **blob,
    size_t *blob_size) __attribute__((weak, alias("oe_seal_algo2")));
```

Then,

- By `oe_seal()`, the source code is implementation neutral and will work with any library supplied at the linker command line.
- By `oe_seal_algo1()` and/or `oe_seal_algo2()`, the source code is explicit about the implementation so could work with multiple implementations in the same enclave.

### Unsealing In-place

There are FAQs around unsealing in-place:

1. Why in-place?
   - It's convenient, because `blob` usually resides in writable memory and is discarded after unsealing. A common workflow:
     1. `blob` is passed in via an ECall.
     2. The ECall bridge allocates `blob` memory.
     3. ECall unseals `blob` to extract the secret.
     4. The ECAll bridge frees `blob`.
2. What if plain text is larger than ciphertext?
   - Encryption alone never compresses data. Compression and encryption are two different things, even though some communication protocols (e.g., TLS) do support both.
3. What if `blob` points to read-only memory?
   - Copy `blob` into secure writable memory before unsealing.

## Changes to Existing APIs

Deprecate `oe_get_seal_key_by_policy()`.

- Always returns the same key - not meeting needs of most applications.
- `key_info` is not typed.
- Replaced with `oe_get_seal_key_info()` + `oe_get_seal_key()`.

Modifiy `oe_get_seal_key()`.

- Change `key_info` to be of type `oe_seal_key_info_t*`.
- Remove `key_info_size`.

Modify `oe_free_seal_key()`.

- Remove `key_info`.

Modify `oe_free_key()`.

- Remove `key_info` and `key_info_size`.

## Specification
