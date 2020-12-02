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
    const uint8_t* plaintext,
    size_t plaintext_size,
    uint8_t** sealed_data,
    size_t* sealed_data_size);
```

Where,

- `sealer` is the UUID identifying the sealing plugin.
  - **Open**: Is there a TEE agnostic sealer that works across all TEEs?
  - **Open**: How to enumerate available sealers and their capabilities, so that the developer can determine the right one that meets his/her requirements?
    - `oe_enumerate_sealers()`? How to abstract/describe a sealer's capabilities?
    - Without an enuermation API, the sealer must be selected at build time. Then why parameterize it?
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

### Sample Code

In the most common cases, both `settings` and `opt_params` are set to `NULL` to take sealer defaults.

```C
oe_result_t seal_my_data(
    const uint8_t* my_data,
    size_t my_data_size,
    uint8_t** blob,
    size_t* blob_size)
{
    return oe_seal(
        OE_SEAL_DEFAULT_SEALER,
        OE_SEAL_POLICY_PRODUCT,
        NULL,
        0,
        NULL,
        0,
        my_data,
        my_data_size,
        blob,
        blob_size);
}
```

Let's assume `oe_key_derivation_setting_t` is defined as a tuple like below.

```C
typedef _key_derivation_setting
{
    int type;
    int size;
    const void* data;
} oe_key_derivation_setting_t;

// Settings supported by all TEEs
#define OE_KEY_DERIVATION_ENTROPY               1
// More TEE neutral setting types...

// Settings supported by SGX
#define OE_SGX_KEY_DERIVATION_ATTRIBUTE_MASK    0x10001
// More SGX specific setting types...
```

In the rarer cases where key derivation needs to be tuned, the `settings` array is used.

```C
oe_result_t seal_my_data(
    const uint8_t* my_data,
    size_t my_data_size,
    uint8_t** blob,
    size_t* blob_size)
{
    static const char label[] = "Sealing Key";
    static const uint64_t attr_mask = OE_SEALKEY_DEFAULT_FLAGSMASK | OE_SGX_FLAGS_PROVISION_KEY;

    oe_key_derivation_setting_t settings[2];
    settings[0].type = OE_KEY_DERIVATION_ENTROPY;
    settings[0].size = sizeof(label);
    settings[0].data = label;
    settings[1].type = OE_SGX_KEY_DERIVATION_ATTRIBUTE_MASK;
    settings[1].size = sizeof(attr_mask);
    settings[1].data = &attr_mask;
    // More settings go here...

    return oe_seal(
        OE_SEAL_DEFAULT_SEALER,
        OE_SEAL_POLICY_PRODUCT,
        settings,
        sizeof(settings)/sizeof(*settings),
        NULL,
        0,
        my_data,
        my_data_size,
        blob,
        blob_size);
}
```

In the even rarer cases where additional sealer specific options need to be passed, the free-formed `opt_params` is set up in a sealer specific manner.

```C
// A sealer specific header is included for definitions of optional parameters
#include <openenclave/sealers/seal_ABC.h>

oe_result_t seal_my_data(
    const uint8_t* my_data,
    size_t my_data_size,
    uint8_t** blob,
    size_t* blob_size)
{
    sealer_ABC_option_t options[] = {
        // sealer specific options go here...
    };

    return oe_seal(
        OE_SEAL_SEALER_ABC,
        OE_SEAL_POLICY_PRODUCT,
        NULL,
        0,
        options,
        sizeof(options),
        my_data,
        my_data_size,
        blob,
        blob_size);
}
```

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

### Sample Code

In the most common cases,

```C
oe_result_t seal_my_data(
    const uint8_t* my_data,
    size_t my_data_size,
    uint8_t** blob,
    size_t* blob_size)
{
    oe_result_t result;
    oe_seal_key_info_t key_info;

    result = oe_initialize_seal_key_info(
        &key_info,
        OE_SEAL_POLICY_PRODUCT,
        NULL,
        0);

    if (result == OE_OK)
        result = oe_seal(
            &key_info,
            my_data,
            my_data_size,
            blob,
            blob_size);

    return result;
}
```

In the rarer cases where key derivation needs to be tuned,

```C
oe_result_t seal_my_data(
    const uint8_t* my_data,
    size_t my_data_size,
    uint8_t** blob,
    size_t* blob_size)
{
    static const char label[] = "Sealing Key";
    oe_result_t result;

    result = oe_initialize_seal_key_info(
        &key_info,
        OE_SEAL_POLICY_PRODUCT,
        label,
        sizeof(label));

    if (result == OE_OK)
    {
        key_info.attribute_mask.flags = OE_SEALKEY_DEFAULT_FLAGSMASK | OE_SGX_FLAGS_PROVISION_KEY;
        // More assignments to key_info.* go here...

        // Given oe_seal is a weak symbol, this resolves to the 1st definition on the linker's command line
        result = oe_seal(
            &key_info,
            my_data,
            my_data_size,
            blob,
            blob_size);
    }
    return result;
}
```

In the cases where multiple implementations are referenced in the same enclave, use the strong/explicit symbol names.

```C
oe_result_t reseal_my_data(
    uint8_t* blob1,     // input blob sealed using algo1
    size_t blob1_size,
    uint8_t** blob2,    // output blob to be sealed using algo2
    size_t* blob2_size)
{
    oe_result_t result;
    oe_seal_key_info_t key_info;
    uint8_t* my_data;
    size_t my_data_size;

    // Unseal blob1 using algo1
    result = oe_unseal_algo1(blob1, blob1_size, &my_data, &my_data_size);
    if (result != OE_OK)
        return result;

    result = oe_initialize_seal_key_info(&key_info, OE_SEAL_POLICY_PRODUCT, NULL, 0);
    if (result != OE_OK)
        return result;

    // Reseal using algo2
    return oe_seal_algo2(&key_info, my_data, my_data_size, blob2, blob2_size);
}
```

## Comparison of 2 Options

### Runtime vs. Buildtime Binding

In Option 1 `oe_seal()` binds to a sealing provider via UUID at runtime, while in Option 2 it binds to an implementation at link time.

Option 1 has the following advantages:

1. An enclave can determine which sealer to use at runtime.
2. Multiple plugins/sealers can coexist easily.

(1) however isn't a requirement. After all, sealing and unsealing have to be done by the same enclave or enclaves of the same product. There's no reason the sealing and the unsealing enclaves cannot agree on the same sealer.

(2) can be achieved in Option 2 as well (using weak symbols), though a bit tricky.

On the flip side, UUID implies additional interface (APIs) for managing plugins, such as registering plugins and specifying the default. Option 2 however doesn't bear those management overhead (at least no additional registration APIs needed).

### oe_key_derivation_setting_t vs. oe_seal_key_info_t

Option 1 introduces `oe_key_derivation_setting_t` to carry sealing parameters, which is likely to be TLV tuples. Option 2 on the other hand adopts a TEE specific `oe_seal_key_info_t` structure to capture all options supported by the underlying TEE.

`oe_seal_key_info_t` is NOT defined by OE but by the underlying TEE - e.g., on SGX `oe_seal_key_info_t` is in fact a `typedef` of `sgx_key_request_t`. In practice, each TEE provides dedicated ISA (on SGX) or API (on OP-TEE) for key derivation. The input to that ISA or API is well defined and could serve as the definition of `oe_seal_key_info_t`. Changes to `oe_seal_key_info_t` should be a rare event. Moreover, TEE ISA/API changes are usually backward compatible - i.e., only new fields will be added while existing fields will be kept, hence exposing it wouldn't cause compatibility problems normally.

In contrast, `oe_key_derivation_setting_t` is an abstraction to present TEE features in a logical way. But

- It's hard to work out a "reasonable" set of features across supported TEEs to be exposed as setting type. Or if the full set of features are provided for each TEE, it'd be cumbersome (more cumbersome than direct assignments to structure fields) to set up.
- Once a new TEE is added to OE's support list, the set of settings needs to be reviewed and probably revised, which is an on-going burden to architecture.
- Documentation overhead - OE has to document the supported settings, while enclave developers have to study them. For developers who are dealing with TEE specific features, they are usually familiar with the TEE details so would probably prefer to work with the TEE ISA/API defined structures directly. The additional abstraction layer presents an overhead to both SDK and enclave developers.
- An advantage of Option 1 is `oe_seal()` may sanitize input before passing them through to the selected plugin, while in Option 2 the implementation has to validate function parameters by itself.

### Optional Parameters

Option 1 supports an additional `opt_params` as an opaque structure to cover all other settings/parameters that cannot be covered by `settings`. Option 2 doesn't support `opt_params`.

`opt_params` can carry plugin specific settings, such as key length, tag length, IV, etc. Generally speakings, all settings to a sealing implementation can fall into 2 categories - key derivation settings and crypto settings. The 1st category is TEE specific and captured in `oe_seal_key_info_t` in Option 2, while the 2nd category is NOT offered intentionally and the implementation is supposed to use the strongest setting supported by the underlying TEE.

### 1-step vs. 2-step Sealing

In Option 1 sealing is a 1-step process while it's a 2-step process in Option 2.

Option 1 adopts 1-step sealing because

- Some believe that seal keys shall never be revealed to developers, hence the existing `oe_get_seal_key()` API shall be depricated/removed. `key_info` is an intermediate structure serving as input to `oe_get_seal_key()`, so has no reason to be exposed anymore once `oe_get_seal_key()` has been removed.
- `oe_seal()` accepts `settings` and `opt_params` that cover all possible options/parameters, so there's no need for developers to touch `key_info`.

Option 2 employs 2-step sealing because

- Some (including the author) believe that seal keys could have more usages than just sealing. Hence `oe_get_seal_key()` shall be kept. Given that, `key_info` could be set up in the same way (by `oe_initialize_seal_key_info()`) and shared by both `oe_get_seal_key()` and `oe_seal()`.
- `oe_initialize_seal_key_info()` takes TEE neutral parameters only. Any TEE specific settings must be done via direct assignments to `key_info` fields. With that said, sealing could be a 3-step process, with the TEE specific code inserted in between `oe_initialize_seal_key_info()` and `oe_seal()`.