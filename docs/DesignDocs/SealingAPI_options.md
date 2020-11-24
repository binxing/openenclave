# Sealing API Definitions

## Option 1 - Sealing Plugins (Sealers)

An excerpt from Mr. Simon Leet's [comment](https://github.com/openenclave/openenclave/pull/3652#discussion_r512388257):

> Instead of trying to tweak this design towards acceptability, I'll propose an entirely different strawman design that I want folks to think about that we can then compare and debate:
>
> * OE SDK no longer provides `oe_get_seal_key` to an end user.
> * OE SDK implements a plug-in model for sealing functionality, much in the same way that it has for attestation.
>
>   * A TEE provider (like SGX) is responsible for implementing a plug-in that knows how seal/unseal on that TEE platform and _defines a plug-in-specific cryptosuite and data blob format._
>
>     * This shifts the crypto-agility problem out of the SDK; a developer can adopt alternative implementations of sealing plugins or plugins using different (newer) cryptosuites without relying on the SDK to determine that on their behalf.
>   * OE SDK provides `oe_seal` and `oe_unseal` APIs that are wrappers over TEE plug-in implementation.
>
>     * Many of the ideas from attestation plug-ins may carry over here, such as UUID targeting, plug-in registration, etc. Some will get simplified (e.g. UUID is always embedded in sealed blob because there is no cross-TEE sealing)
>     * Some or all of the OE semantics may go away attempting to generalize sealing policies across TEEs, much in the same way that attestation plugins don't attempt to build on top of the old `oe_parse_report` semantics.
>     * For example, consider a trivial use case where the user has no control over sealing parameters at all if they write cross-TEE code; `oe_seal` just calls the appropriate TEE-plugin and it seals with a default policy of its choice (e.g. always with MRENCLAVE for SGX). The TEE-plugin may then expose its custom set of properties through an opaque blob type through the `oe_seal` API that a user that wants to customize functionality on a specific TEE can manipulate themselves (e.g. `sgx_key_request` struct for SGX).
>
> I'm not proposing that we actually run off and go build this strawman (there are some other problems I'm glossing over here like the `oe_get_private_key` API) but it represents a high level concept for an alternative that I think hits some of the stated objectives better:
>
> * Actually TEE-agnostic, bakes less implementation directly into OE SDK (or at least, could be more easily broken out as standalone components moving forwards)
> * Accommodative in that the plug-ins get to expose the full range of options specific to a TEE if desired without it filtering through an OE SDK aggregation layer.
>
>   * The trade-off being less expressive sealing semantics for apps that want to span different TEEs, at least in this strawman version.
> * Easy to use in that there's no management of key info at all, and that's incorporated into the `oe_seal` function.
>
>   * With proper built-in defaults per TEE, it could also avoid some of the registration complexity associated with attestation plugins, again because there's a much stronger binding of TEE the enclave is running in vs. attestation.
> * Interoperable with existing Intel SDK, since Intel controls the plugin entirely, they can choose to provide that functionality as they see fit.

The API for sealing will look like the following:

```C
oe_result_t oe_seal(
    const oe_uuid_t* sealer_id,
    oe_seal_policy_t policy,
    oe_key_derivation_setting_t* settings,
    uint32_t settings_count,
    const void* opt_params,
    size_t opt_params_size,
    uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t** sealed_data,
    size_t* sealed_data_size);
```

Where,

- `sealer` is the UUID identifying the sealing plugin.
  - **Open**: Is there a TEE agnostic sealer that works across all TEEs?
  - **Open**: How to enumerate available sealers and their capabilities, so that the developer can determine the right one that meets his/her requirements?
- `policy` is either `OE_SEAL_POLICY_UNIQUE` or `OE_SEAL_POLICY_PRODUCT`.
- `settings` contain settings for seal key derivation.
  - There are generic settings applicable to all TEEs, such as `entropy`. TEE agnostic code should use generic settings only.
  - There are also TEE specific settings, such as `attribute_mask` on SGX.
- Additionally, `opt_params` pass through sealer specific options.
- All other function arguments are self-explanatory.

Additional APIs necessary to manage sealing plugins: *TBD*

Option 1 focuses on completeness.

- All combinations of TEE/cryptosuite can be implemented as separate sealers.
- Each sealer may support a distinct set of options/parameters that are passed through by the API.
- Multiple sealers can coexist in the same enclave.

## Option 2 - Simple APIs

Each TEE has its distinct set of options for deriving seal keys. All those options are captured in a TEE specific structure - `oe_seal_key_info_t`, which serves as the only function argument that governs seal key derivation.

The API for sealing will look like the following:

```C
oe_result_t oe_seal(
    const oe_seal_key_info_t* key_info,
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t** sealed_data,
    size_t* sealed_data_size);
```

Where,

- `key_info` points to a TEE specific structure that governs seal key derivation.
- All other function arguments are self-explanatory.

To allow TEE agnostic code, the following API initializes an instance of `oe_seal_key_info_t` using TEE defaults.

```C
oe_result_t oe_initialize_seal_key_info(
    oe_seal_key_info_t* key_info,
    oe_seal_policy_t seal_policy,
    const uint8_t* entropy,
    size_t entropy_size);
```

Where,

- `key_info` is the instance of `oe_seal_key_info_t` to be initialized.
- `seal_policy` is either `OE_SEAL_POLICY_UNIQUE` or `OE_SEAL_POLICY_PRODUCT`. Think of it as a *KDF*, this augument selects the *KDK*.
- `entropy` is a byte array. Per NIST.SP800-108, a *KDF* may take multiple inputs, e.g., *Label* and *Context*. But all those inputs would eventually be concatenated into an octet string. This `entropy` is indeed an octet string that contains everything else that needs to be mixed into the derived key.

Option 2 focuses on simplicity.

- All key derivation parameters are kept in a single structure that could be initialized with TEE defaults. This makes TEE agnostic code very easy to write.
  - `oe_initialize_seal_key_info()` along with `oe_get_seal_key()` provides an easy way to derive enclave key in a TEE agnostic manner for usages other than sealing.
- No crypto related options offered - The implementation always uses strongest crypto supported by the underlying TEE.
- Different cryptosuites can be supported by providing different implementations in static libraries. Thanks to the simple API, implementations are very easy to add.
  - Should an ISV not be able to find an implementation that meets its needs, it could put in its own very easily.
- Multiple implementations can coexist in the same enclave using weak symbols. Please note that weak symbols are supported by ELF only.

### Coexistence of multiple sealing implementations

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
