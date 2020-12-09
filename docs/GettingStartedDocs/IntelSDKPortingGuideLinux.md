# Intel SGX SDK for Linux to Open Enclave SDK Porting Guide

The [Intel SGX SDK for Linux](https://01.org/intel-software-guard-extensions)
and the Open Enclave SDK share many design principles but differ in
implementations. It requires source code changes to build enclaves with the
Open Enclave SDK that were developed initially with the Intel SGX SDK for
Linux.

Please note that this doc focuses on **Linux**, and applies to the *Intel SGX
SDK for Linux* only unless noted otherwise.

## Create Project Build Files

The Open Enclave SDK supports a number of build systems, among which `cmake` is
a convenient one. This section shows how to build an enclave using `cmake`. For
those not familiar with `cmake`, a tutorial is available at
https://cmake.org/cmake/help/latest/guide/tutorial/index.html.

Firstly, a `CMakeLists.txt` file needs to be created in the enclave's source
directory. Open Enclave requires `cmake 3.11` or later so the first statement
should be:

```cmake
cmake_minimum_required(VERSION 3.11)
```

Then an enclave is just a C/C++ project.

```cmake
project("MyEnclaveProject" LANGUAGE C CXX)
```

Next, import the `OpenEnclave` package.

```cmake
find_package(OpenEnclave CONFIG REQUIRED)
```

To import the `OpenEnclave` package by name, it is necessary to add the Open
Enclave SDK's install location to environment variables used by `cmake`, by
either
 - Appending `<install_path>` to `$CMAKE_PREFIX_PATH`, or
 - Appending `<install_path>/bin` to `$PATH`.

A convenient way is to `source` the
`<install_path>/shared/openenclave/openenclaverc` file. For example, assuming
the default install path `/opt/openenclave`:

```bash
source /opt/openenclave/shared/openenclave/openenclaverc
```

Now generate the ECall/OCall bridge/proxy routines for the enclave. The Open
Enclave SDK supports the use of EDL definitions like the Intel SGX SDK for
Linux, with some differences discussed
[later](#migrate-enclave-settings) in this document.

```cmake
add_custom_command(
  OUTPUT MyEnclave_t.h MyEnclave_t.c MyEnclave_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/MyEnclave.edl
  COMMAND openenclave::oeedger8r --trusted ${CMAKE_SOURCE_DIR}/MyEnclave.edl
          --search-path ${OE_INCLUDEDIR})
```

Please note above generates **trusted** ECall/OCall bridges/proxies for the
enclave only; while the snippet below generates the **untrusted** ECall/OCall
proxies/bridges for the host application (that loads/runs the enclave).

```cmake
add_custom_command(
  OUTPUT MyEnclave_u.h MyEnclave_u.c MyEnclave_args.h
  DEPENDS ${CMAKE_SOURCE_DIR}/MyEnclave.edl
  COMMAND openenclave::oeedger8r --untrusted ${CMAKE_SOURCE_DIR}/MyEnclave.edl
          --search-path ${OE_INCLUDEDIR})
```

Finally, build the enclave as an executable. Please don't forget to include
`MyEnclave_t.c` (generated above) in the source list.

```cmake
add_executable(MyEnclave MyEnclave.cpp
               ${CMAKE_CURRENT_BINARY_DIR}/MyEnclave_t.c)

# Current API version
target_compile_definitions(MyEnclave PUBLIC OE_API_VERSION=2)

# Needed by the generated MyEnclave_t.c
target_include_directories(MyEnclave PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(MyEnclave openenclave::oeenclave openenclave::oelibc)
```

Similarly, `MyEnclave_u.c` shall be included in the host application's source
list like below:

```cmake
add_executable(MyEnclaveHost MyEnclaveHost.cpp
               ${CMAKE_CURRENT_BINARY_DIR}/MyEnclave_u.c)

# Needed by the generated MyEnclave_u.c
target_include_directories(MyEnclaveHost PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(MyEnclaveHost openenclave::oehost)
```

Enclaves must be signed before they can be loaded. How to sign an enclave
depends on how the private signing key is managed in your project. For
demonstration purposes, the following snippet generates a random RSA key pair
to sign the enclave. An enclave configuration file (`MyEnclave.conf` below) may
also be provided. Details of enclave configuration/settings are described
[later](#migrate-enclave-settings) in this document.

```cmake
# Generate key
add_custom_command(
  OUTPUT private.pem public.pem
  COMMAND openssl genrsa -out private.pem -3 3072
  COMMAND openssl rsa -in private.pem -pubout -out public.pem)

# Sign enclave
add_custom_command(
  OUTPUT MyEnclave.signed
  DEPENDS MyEnclave MyEnclave.conf private.pem
  COMMAND openenclave::oesign sign -e $<TARGET_FILE:MyEnclave>
          -c ${CMAKE_SOURCE_DIR}/MyEnclave.conf -k private.pem)
```

Readers are encouraged to look for complete examples under
`<install_path>/share/openenclave/samples` directory

## Migrate Enclave Settings

**Enclave Settings**, also known as **Enclave Metadata**, refers to information
consumed by enclave loaders to instantiate enclaves, such as heap size, stack
size, number of trusted hardware threads (i.e., number of TCS's), etc.

Enclave settings are specified as human-readable text in *configuration files*.
Both the Intel SGX SDK for Linux and the Open Enclave SDK provide tools to
compile configuration files into their binary form and embed them into the
final enclave image. However, they differ in both format and feature set.

### Configuration File Formats

The Intel SGX SDK for Linux adopted an XML format for encoding enclave settings
in text form, which is usually named as *Enclave*.config.xml. The signing tool
(i.e., `sgx_sign`) converts it into binary form and stores it in a dedicated
section (i.e., `.sgxmeta`) of the enclave's ELF image before it calculates the
enclave's measurement (i.e., `SIGSTRUCT::MRENCLAVE`). At runtime, the ELF
section `.sgxmeta` is consumed by the enclave loader to instantiate the exact
enclave that matches the measurement calculated by the signing tool.

Below comes from the sample code - SampleEnclave, of the Intel SGX SDK for
Linux.

```xml
<EnclaveConfiguration>
  <ProdID>0</ProdID>
  <ISVSVN>0</ISVSVN>
  <StackMaxSize>0x40000</StackMaxSize>
  <HeapMaxSize>0x100000</HeapMaxSize>
  <TCSNum>10</TCSNum>
  <TCSPolicy>1</TCSPolicy>
  <!-- Recommend changing 'DisableDebug' to 1 to make the enclave undebuggable for enclave release -->
  <DisableDebug>0</DisableDebug>
  <MiscSelect>0</MiscSelect>
  <MiscMask>0xFFFFFFFF</MiscMask>
</EnclaveConfiguration>
```

Rather than XML, the Open Enclave SDK uses plaintext files instead. A
configuration file, usually named *enclave*.conf, is supplied to the signing
tool (i.e., `oesign`) command line to govern the instantiation of the enclave.
The compiled metadata is then stored in a dedicated ELF section named
`.oeinfo`. Additionally, Open Enclave SDK provides `OE_SET_ENCLAVE_SGX`, a C
macro for embedding default enclave settings in C source files. *enclave*.conf
is in fact optional and is necessary only if some of those defaults provided to
`OE_SET_ENCLAVE_SGX` macro need overridden. Under the hood,
`OE_SET_ENCLAVE_SGX` is expanded to instantiation of an
`oe_sgx_enclave_properties_t` structure in `.oeinfo` section. Detailed
information can be found in
the Open Enclave SDK instructions to
[Build and Sign an Enclave](buildandsign.md)

Below is the same configuration as above but in the Open Enclave SDK's
*enclave*.conf format.

```
# <ProdID>0</ProdID>
ProductID=0

# <ISVSVN>0</ISVSVN>
SecurityVersion=0

# <StackMaxSize>0x40000</StackMaxSize>
NumStackPages=64

# <HeapMaxSize>0x100000</HeapMaxSize>
NumHeapPages=256

# <TCSNum>10</TCSNum>
NumTCS=10

# <DisableDebug>0</DisableDebug>
Debug=1

# There are no equivalent Open Enclave enclave settings for the following
# <TCSPolicy>1</TCSPolicy>
# <MiscSelect>0</MiscSelect>
# <MiscMask>0xFFFFFFFF</MiscMask>
```

### Supported Enclave Settings by Intel SGX SDK for Linux and Open Enclave SDK

At the time of this writing, the Intel SGX SDK for Linux supports a superset of
the Open Enclave SDK's features, hence not every element of Intel's
*Enclave*.conf.xml has an equivalent in the Open Enclave SDK's *enclave*.conf
file. The table below summarizes the equivalence and difference.

|.xml Element (Intel)|.conf Key (Open Enclave)|Type|Definition|Notes|
|---|---|---|---|---|
|`<ProdID>`|`ProductID`|`uint16_t`|`SIGSTRUCT::ISVPRODID` - 2-byte product ID chosen by ISV
|`<ISVSVN>`|`SecurityVersion`|`uint16_t`|`SIGSTRUCT::ISVSVN` - 2-byte security version number to prevent rollback attacks against sealing keys
|`<ReleaseType>`||`bool`|`1` indicates a release build|Intel SDK copies this bit to MSB of `SIGSTRUCT::HEADER`. The Open Enclave SDK does *NOT* support configuring this bit but hard-codes it to `0`.This bit is *NOT* documented in [SDM](https://software.intel.com/content/www/us/en/develop/articles/intel-sdm.html). User enclaves shall avoid using this bit.
|`<IntelSigned>`||`bool`|If `1`, set `SIGSTRUCT::VENDOR` to `0x8086` (or `0` otherwise)|The Open Enclave SDK does *NOT* support configuring this field currently but hard-codes it to `0`. Per SDM, this field is informational.
|`<ProvisionKey>`||`bool`|`1` to grant access to *Provision Key*. This corresponds to bit 4 of `SIGSTRUCT::ATTRIBUTES`|`Debug` is the only attribute configurable via the Open Enclave SDK's .conf file. All other attributes can only be configured by enclosing an `oe_sgx_enclave_properties_t` structure manually in the `.oeinfo` section in a source file.|`<LaunchKey>`||`bool`|`1` to grant access to *Launch Key*. This corresponds to bit 5 of `SIGSTRUCT::ATTRIBUTES`|Similar to `<ProvisionKey>` above, manual instantiation of `oe_sgx_enclave_properties_t` is required.
|`<DisableDebug>`|`Debug`|`bool`|Indicate whether debugging is allowed|The Intel SGX SDK for Linux and the Open Enclave SDKs use different polarity - i.e., `<DisableDebug>1</DisableDebug>` is equivalent to `Debug=0`.
|`<HW>`||`uint32_t`|Hardware verions. This occupies the space of `SIGSTRUCT::SWDEFINED`|Currently it's used only by Intel's LE (Launch Enclave). The Open Enclave SDK does *NOT* support configuring this field currently but hard-codes it to `0`. User enclaves shall avoid using it.
|`<TCSNum>`|`NumTCS`|`uint32_t`|Number of TCS's (trusted threads)|This is the number of TCS's, and is also the initial number of TCS's on SGX v2. The Open Enclave SDK supports only SGX v1 at the moment.
|`<TCSMaxNum>`||`uint32_t`|Maximal number of TCS's|TCS's can be added at runtime on SGX v2. The Open Enclave SDK supports only SGX v1 at the moment.
|`<TCSMinPool>`||`uint32_t`|Minimal number of TCS's to keep|TCS's can be removed at runtime on SGX v2. The Open Enclave SDK supports only SGX v1 at the moment.
|`<TCSPolicy>`||`bool`|`0` to bind TCS to untrusted thread, `1` to unbind them|The Open Enclave SDK never binds TCS's to untrusted threads.
|`<StackMaxSize>`|`NumStackPages`|`uint64_t`|Maximal stack size in bytes (Intel) or in pages (Open Enclave)|This is the stack size on SGX v1, or maximal stack size on SGX v2. The Open Enclave SDK supports only SGX v1 at the moment.
|`<StackMinSize>`||`uint64_t`|Minimal stack size in bytes|Stack pages can be removed at runtime on SGX v2. The Open Enclave SDK supports only SGX v1 at the moment.
|`<HeapMaxSize>`||`uint64_t`|Maximal heap size in bytes|For SGX v2 only. The Open Enclave SDK supports only SGX v1 at the moment.
|`<HeapMinSize>`||`uint64_t`|Minimal heap size in bytes|For SGX v2 only. The Open Enclave SDK supports only SGX v1 at the moment.
|`<HeapInitSize>`|`NumHeapPages`|`uint64_t`|Initial heap size in bytes (Intel) or pages (Open Enclave)|The Open Enclave SDK supports only SGX v1 at the moment.
|`<ReservedMemMaxSize>`||`uint64_t`||This, along with the `ReservedMem*` elements below, allows appending extra virtual memory to an enclave. The Open Enclave SDK doesn't support this feature.
|`<ReservedMemMinSize>`||`uint64_t`
|`<ReservedMemInitSize>`||`uint64_t`
|`<ReservedMemExecutable>`||`uint64_t`
|`<MiscSelect>`||`uint32_t`|`SIGSTRUCT::MISCSELECT` - selects extended information to be reported on AEX|The Open Enclave SDK does *NOT* support configuring this field currently but hard-codes it to `0` (i.e. no MISC features are enabled).
|`<MiscMask>`||`uint32_t`|`SIGSTRUCT::MISCMASK` - selects `MISCSELECT` bits to enforce|The Open Enclave SDK does *NOT* support configuring this field currently but hard-codes it to `0xffffffff` (i.e. all bits are enforced).
|`<EnableKSS>`||`bool`|`1` to enable *Key Separation and Sharing*|The Open Enclave SDK supports only SGX v1 at the moment.
|`<ISVFAMILYID_H>`||`uint64_t`|This, along with `<ISVFAMILYID_L>` below, forms 16-byte `SIGSTRUCT::ISVFAMILYID`|The Open Enclave SDK supports only SGX v1 at the moment.
|`<ISVFAMILYID_L>`||`uint64_t`|See above|
|`<ISVEXTPRODID_H>`||`uint64_t`|This, along with `<ISVEXTPRODID_L>` below, forms 16-byte `SIGSTRUCT::ISVEXTPRODID`|The Open Enclave SDK supports only SGX v1 at the moment.
|`<ISVEXTPRODID_L>`||`uint64_t`|See above|

As mentioned in the *Notes* column above, certain missing features, such as
those controlling SGX enclave attribute bits (e.g., `<LaunchKey>`,
`<ProvisionKey>`), could still be enabled by setting
`oe_sgx_enclave_properties_t::config.attributes` manually, even though they
aren't supported explicitly by the `OE_SET_ENCLAVE_SGX` macro or *.conf file.
Instead, a developer can directly define the `oe_enclave_properties_sgx` global
in the `.oeinfo` section without using the `OE_SET_ENCLAVE_SGX` macro. For
example, to set the `PROVISION_KEY`, a developer can define the following in
the enclave code:

```C
OE_INFO_SECTION_BEGIN
volatile const oe_sgx_enclave_properties_t oe_enclave_properties_sgx = {
    .header = {.size = sizeof(oe_sgx_enclave_properties_t),
               .enclave_type = OE_ENCLAVE_TYPE_SGX,
               .size_settings = {.num_heap_pages = 512,
                                 .num_stack_pages = 512,
                                 .num_tcs = 4}},
    .config = {.product_id = 1234,
               .security_version = 5678,
               .attributes = OE_SGX_FLAGS_PROVISION_KEY |
                             OE_MAKE_ATTRIBUTES(0)},
    .end_marker = 0xecececececececec};
OE_INFO_SECTION_END
```

If compatibilities with both SDKs are desired, avoid using features specific to
either SDK.

As a final note, neither the Intel SGX SDK for Linux nor the Open Enclave SDK
provides configuration settings for enabling/disabling XState features (e.g.,
AVX, AVX-512, etc.) explicitly. Open Enclave's SGX enclave loader uses the
enabled XState features on the local platform to initialize
`SECS::ATTRIBUTES::XFRM`, and hard-codes
`SIGSTRUCT::ATTRIBUTEMASK::XFRM` to `0`. That is, XState features are *NOT*
enforced and must *NOT* be relied upon for security.

## Migrate ECall/OCall Definitions (EDL Files)

Both the Intel SGX SDK for Linux and the Open Enclave SDK support the same
grammar for defining trusted/untrusted functions (a.k.a. ECalls/OCalls) in EDL
files.  However, built-in OCalls are defined in different headers. Intel's
built-in OCalls are defined in `sgx_tstdc.edl` while the Open Enclave SDK's are
defined in `platform.edl`.

Most EDL files include (by `include` statements) common C headers for both host
and enclave sides. The most commonly included header is the one defining SGX
architectural structures, which is `arch.h` in the Intel SGX SDK for Linux or
`openenclave/bits/sgx/sgxtypes.h` in the Open Enclave SDK. Please also note
that some structures may be named differently, e.g., the EINITTOKEN
architectural structure is defined as `token_t` in the Intel SGX SDK for Linux
but `einittoken_t` in the Open Enclave SDK.

The code snippet below shows a way to include/import C headers and EDL
definitions conditionally, in order to be compatible with both SDKs.

```
enclave {
#ifdef OEEDGER8R
    include "openenclave/bits/sgx/sgxtypes.h";
    from "openenclave/edl/sgx/platform.edl" import *;
#else
    include "arch.h";
    from "sgx_tstdc.edl" import *;
#endif
    /* ECall/OCall definitions go here */
}
```

For example, if using `oeedger8r`:

```bash
oeedger8r --trusted ${CMAKE_SOURCE_DIR}/MyEnclave.edl --search-path ${OE_INCLUDEDIR} -DOEEDGER8R
```

`sgx_edger8r` also supports macro preprocessing in EDL files, but does not
accept macro definitions as arguments. To use `sgx_edger8r`:

```bash
sgx_edger8r --trusted ${CMAKE_SOURCE_DIR}/MyEnclave.edl --search-path ${OE_INCLUDEDIR}
```

The last thing worth noting is that the Open Enclave SDK doesn't support nested
ECalls (i.e., an ECall in the context of an OCall) like the Intel SGX SDK for
Linux does. Existing enclaves making use of nested ECalls need to be reworked
to be compatible with the Open Enclave SDK.

## Port C/C++ Source Code

Given similarities in the architectures of both SDKs, there should not be any
significant code flow/logic changes required. However, source code
incompatibilities still exist in:
- Header files - They are structured and/or named differently. Fortunately,
  Open Enclave provides 2 comprehensive headers, namely `openenclave/enclave.h`
  and `openenclave/host.h`, to be included by trusted and untrusted code,
  respectively. A single `#include` should suffice in most cases.
- APIs - Most Open Enclave APIs are prefixed by `oe_` while Intel's APIs are by
  `sgx_`. Moreover, some APIs may take parameters in different orders.
- Structure definitions - Structure members may be named differently. Some
  structures are organized differently too. For example, the Intel SGX SDK for
  Linux defines EINITTOKEN as `token_t` with all MAC'ed fields captured in a
  child structure `launch_body_t`; while in the Open Enclave SDK it is defined
  as a flat `einittoken_t` structure.
- Crypto lib - Intel SGX SDK for Linux supports 2 crypto libs - IPP and
  OpenSSL, and provides a wrapper layer to unify crypto APIs. The Open Enclave
  SDK only supports enclave applications calling
  [MbedTLS](/docs/MbedtlsSupport.md) directly and not through an SDK wrapper.

## Threading

When the untrusted application ECALLS into an enclave, the untrusted Run-Time
System (uRTS) binds the calling host thread to an enclave thread. Host and
enclave threads might be bound for the entire lifetime of the thread. In this
mode, which corresponds to `<TCSPolicy>` 0, the thread-local data is
initialized when the enclave thread starts execution for the first time.

### POSIX Threads (pthreads)

The SGX SDK supports a subset of the POSIX Threads API. The main purpose of the
supported pthreads API is to enable the OpenMP runtime, which, in turn, enables
the oneAPI Deep Neural Network Library (oneDNN).

The SGX SDK supports creating, exiting and joining threads, mutex, conditional
variable and readers-writer lock synchronization operations, as well as storing
and retrieving data from a thread's local storage area.

The Open Enclave SDK also supports a subset of the POSIX Tread API. However, it
is limited to thread synchronization and thread local storage. pthread_create,
pthread_join, and pthread_detach are wrappers around oe_pthread_create,
oe_pthread_join, and oe_pthread_detach, respectively. These functions currently
throw an assertion. We need to work with the OE team on an architecture to
support threading inside enclaves.

## Switchless

The Intel SGX SDK and the Open Enclave SDK support switchless for both ECALL
and OCALL functions. In addition, sgx_edger8r and oeedger8r support the same
keyword to identify switchless functions: transition_using_threads.

TBD: Data structure to configure/initialize and tune (callbacks) switchless.

## Protected Code Loader (PCL)

TBD.

## Protected File System (PFS)

The Open Enclave SDK does not support encrypted files. The OE did port this
feature to a branch, it was then deprecated because they want a full file
system (not an encrypted file). We need to work with the OE on a new
architecture. 


## Trusted Crypto Library (tcrypto)

The Intel SGX SDK includes a wrapper library, sgx_tcrypto, that exposes a
high-level cryptographic API. Other libraries of the SGX SDK, such as the
Sealing Library, as well as Intel's Architecture Enclaves use this API.
The main goal of the sgx_tcrypto library is to provide a common cryptographic
API independent of the underlying cryptographic library, which could be
the Intel IPP Cryptographic Library or OpenSSL.

The sgx_tcrypto library is also available to build enclaves with the OE SDK.
However, there are some minor differences. The sgx_tcrypto is provided outside
the OE SDK. The SGX SDK allows building a single version of sgx_tcrypto, which
internally links with either IPP Crypto or OpenSSL. For the OE SDK, there are
two sgx_tcrypto versions: sgx_tcrypto_ipp and sgx_tcrypto_openssl. The former
links with IPP Crypto, whereas the latter requires the enclave developer to add
the OE SDK OpenSSL library to the list of linker command line.


## Remote Attestation

The Intel® SGX SDK supports APIs for generation and verification various types of quotes.
* For quote generation:
    * There are 3 sets of APIs, and they are available only on the host (untrusted) side.
        * The [DCAP Quoting Library (QL) API](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteGeneration/quote_wrapper/ql/inc/sgx_dcap_ql_wrapper.h) supports generation of ECDSA quotes.
        * The legacy [quote API](https://github.com/intel/linux-sgx/blob/master/common/inc/sgx_uae_epid.h) supports generation of EPID quotes (linkable and unlinkable).
        * The [quote-ex API](https://github.com/intel/linux-sgx/blob/master/common/inc/sgx_uae_quote_ex.h) supports generation of both ECDSA and EPID quotes.
        * These 3 sets of API expose similar features:
            * Get Quoting Enclave (QE) SGX target info structure.
                * DCAP API function: `sgx_qe_get_target_info()`
                * quote API function: `sgx_init_quote()`
                * quote-ex API function: `sgx_init_quote_ex()`
            * Get quote size.
                * DCAP API function: `sgx_qe_get_quote_size()`
                * quote API function: `sgx_calc_quote_size()`
                * quote-ex API function: `sgx_get_quote_size_ex()`
            * Convert enclave SGX report (targeted to the QE) to quote, and place it in the caller supplied buffer.
                * DCAP API function: `sgx_qe_get_quote()`
                * quote API function: `sgx_get_quote()`
                * quote-ex API function: `sgx_get_quote_ex()`
    * With any of the above APIs, the quote generation flow is similar, with multiple steps listed below. These APIs only support host-side operation in steps 1 and 5. Implmenetation of other steps are the responsiblity of the application software.
        * Step 1: the host gets local QE target info.
        * Step 2: the host passes the QE target info to the enclave.
        * Step 3: the enclave generates an SGX report targeted to the local QE.
        * Step 4: the enclave sends the SGX report to the host.
        * Step 5: the host gets quote size, allocates buffer for the quote, and converts the enclave SGX report to a quote placed the allocated buffer.

* For quote verification:
    * The Intel® SGX SDK only supports verification of ECDSA quotes, with both host and enclave side APIs:
        * Host-side API: [DCAP Quote Verification Library (QVL) / Quote Verification Enclave (QVE)](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/dcap_quoteverify/inc/sgx_dcap_quoteverify.h)
            * API function: `sgx_qv_verify_quote()`
                * The QVL API enables quote verification to be performed either by the host-side library itself, or by the QVE.
                * Note: Quote verification with QVE is valuable when the caller is an enclave that can verify QVE identity and security properties.
            * API function: `sgx_qv_get_qve_identity()`
        * Enclave-side API: [DCAP Trusted Verification Library (TVL)](https://github.com/intel/SGXDataCenterAttestationPrimitives/blob/master/QuoteVerification/dcap_tvl/sgx_dcap_tvl.h)
            * API function: `sgx_tvl_verify_qve_report_and_identity()`
                * The TVL API verifies the QVE identity and the QVE report returned from the QVL API.
    * Host-side ECDSA quote verificaiton flow is straightforward:
        * The host application calls the QVL API `sgx_qv_verify_quote()` to verify the quote using the host-side QVL library directly.
    * Enclave-side ECDSA quote verification flow is more complex:
        * Step 1: the enclave gets its self target info.
        * Step 2: the enclave ocalls to the host, to invoke the QVL API `sgx_qv_verify_quote()` to verify quote with QVE. The verification result protected by a QVE report is returned.
        * Step 3: the enclave calls TVL API `sgx_tvl_verify_qve_report_and_identity()` to verify the QVE identity and security properties, as well as the quote verification result in the QVE report.

Note: The Intel® SGX SDK includes a [RemoteAttestation](https://github.com/intel/linux-sgx/blob/master/SampleCode/RemoteAttestation) sample project that demonstrates remote attestation in the context of the Key Exchange (KE) library, which will be covered in the Key Exchange Library section.

As compared to the Intel® SGX SDK, the OE SDK supports a higher level API that is is more friendly to application software developers.
* The document [Attestation_API_Proposal.md](https://github.com/openenclave/openenclave/blob/master/docs/DesignDocs/Attestation_API_Proposal.md) explains the overall API proposal.
    * The [Implementation of SGX Plugins](https://github.com/openenclave/openenclave/blob/master/docs/DesignDocs/Attestation_API_Proposal.md#implementation-of-sgx-plugins) section of this document describes supported formats for SGX evidence attestation and verification.
        * Generation of evidence in ECDSA and EPID formats.
        * Verification of evidence in ECDSA format.
* [Attester API](https://github.com/openenclave/openenclave/blob/master/include/openenclave/attestation/attester.h) for evidence generation:
    * The API is available only on the enclave side.
    * API function `oe_attester_select_format()`: select a supported format ID.
    * API function `oe_get_evidence()`: generate evidence of the input format, and return it in a dynamically allocated buffer.
* [Verifier API](https://github.com/openenclave/openenclave/blob/master/include/openenclave/attestation/verifier.h) for evidence verivication:
    * The API is available on both the enclave and host sides.
    * API function `oe_verifier_get_formats()`: get a list of supported formats.
    * API function `oe_verifier_get_format_settings()`: get optional parameters (if any) for the input format.
    * API function `oe_verify_evidence()`: verify input evidence.

Note: The OE SDK API functions `oe_get_report()` and `oe_verify_report()` are legacy and will be deprecated.

To port existing ISV SGX software projects from the Intel® SGX SDK to the OE SDK:
* The ISV software projects that use the Intel® SGX SDK quote generation API need to be updated to use the OE SDK attester API.
    * The existing 5-step flow based on the Intel® SGX SDK is reduced to a call to the OE SDK API `oe_get_evidence()` in the attester enclave.
    * For support of multiple evidence formats, a call to `oe_attester_select_format()` can be performed to select a format that is supported by the attester enclave.
    * Dependencies:
        * Application enclave code includes header `openenclave/attestation/attester.h`.
        * Application enclave EDL file imports `openenclave/edl/attestation.edl`.
        * Target platform has SGX package `libsgx-dcap-ql` or `libsgx-quote-ex`, and their dependencies, installed.
* The ISV software projects that use the Intel® SGX SDK quote verification API need to be updated to use the OE SDK verifier API.
    * For host-side verifidation:
        * The existing call to the Intel® SGX SDK QVL API `sgx_qv_verify_quote()` is replaced with a call to the OE SDK API `oe_verify_evidence()`.
        * If the verifier application supports multiple evidence formats, it can call `oe_verifier_get_formats()` and pass the output list of format IDs to attesters.
        * Dependencies:
            * Application host code includes header `openenclave/attestation/verifier.h`.
            * Target platform has SGX package `libsgx-dcap-quote-verify` and its dependencies installed.
    * For enclave-side verifidation:
        * The existing 3-step flow based on the Intel® SGX SDK QVL / TVL API is reduced to a call to the OE SDK API `oe_verify_evidence()`.
        * If the verifier enclave supports multiple evidence formats, it can call `oe_verifier_get_formats()` and pass the output list of format IDs to attesters.
        * Dependencies:
            * Application enclave code includes header `openenclave/attestation/verifier.h`.
            * Application enclave EDL file imports `openenclave/edl/attestation.edl`.
            * Target platform has SGX package `libsgx-dcap-quote-verify` and its dependencies installed.       

## Local attestation and Secure Session Establishment

The Intel® SGX SDK includes a library for local attestation and Diffie-Hellman (DH) session establishment between two enclaves on the same platform. The use of this DH Library is demonstrated in the [LocalAttestation](https://github.com/intel/linux-sgx/tree/master/SampleCode/LocalAttestation) sample project as part of the Intel® SGX SDK.
* The DH library API is declared in header [sgx_dh.h](https://github.com/intel/linux-sgx/blob/master/common/inc/sgx_dh.h).
* The API functions are documented in Diffie-Hellman (DH) Session Establishment Functions section of the [Intel® SGX SDK Developer Reference](https://download.01.org/intel-sgx/linux-2.6/docs/Intel_SGX_Developer_Reference_Linux_2.6_Open_Source.pdf) document.
* The [sample project]() is documented in the Local (Intra-Platform) Attestation section of the [Intel® SGX SDK Developer Guide](https://download.01.org/intel-sgx/linux-2.6/docs/Intel_SGX_Developer_Guide.pdf)

This library will be ported to the OE SDK as an add-on library. After porting, this library will have a dependency on the ported tcrypto library.

## Key Exchange Library

The Intel® SGX SDK Key Exchange (KE) library implements the client-side of a variation of SIGMA protocol, for a client SGX enclave to generate an ECDSA or EPID quote, send the quote to a remote server (sometimes called relying party or RP) for attestation, and generate encryption and MAC keys shared with the RP. Note: the remote server side of the implementation is out of the scope of the Intel® SGX SDK.

The KE library has APIs on both the enclave and host sides:
* The enclave side is called Trusted Key Exchange (TKE) API, declared in header [sgx_tkey_exchange.h](https://github.com/intel/linux-sgx/blob/master/common/inc/sgx_tkey_exchange.h)
* The host side is called Untrusted Key Exchange (UKE) API, declared in header [sgx_ukey_exchange.h](https://github.com/intel/linux-sgx/blob/master/common/inc/sgx_ukey_exchange.h)

The KE API functions are described in the [Intel® SGX SDK Developer Reference](https://download.01.org/intel-sgx/linux-2.6/docs/Intel_SGX_Developer_Reference_Linux_2.6_Open_Source.pdf) document.

There is an [end-to-end sample project](https://software.intel.com/content/www/us/en/develop/articles/code-sample-intel-software-guard-extensions-remote-attestation-end-to-end-example.html) that demonstrates how this API can be used for remote attestation and secure key exchange. A [flowchart diagram](https://software.intel.com/content/dam/develop/external/us/en/images/guard-extensions-remote-attestation-end-to-end-example-fig3-781729.png) in this project shows the overall flow.

The OE SDK supports standard-based key exchange protcol call Attested TLS, for remote attestation and establishment of trusted channel for exchange of keys or other sensitive data.
* The Attested TLS protocol is explained in this [README document](https://github.com/openenclave/openenclave/blob/master/samples/attested_tls/AttestedTLSREADME.md#what-is-an-attested-tls-channel).
* The API for certificate generation and verification, `oe_get_attestation_certificate_with_evidence()` and `oe_verify_attestation_certificate_with_evidence()` respectively, are declared in headers [attestation/attester.h](https://github.com/openenclave/openenclave/blob/master/include/openenclave/attestation/attester.h) and [attestation/verifier.h](https://github.com/openenclave/openenclave/blob/master/include/openenclave/attestation/verifier.h).
* There is an [Attested TLS sample](https://github.com/openenclave/openenclave/tree/master/samples/attested_tls) that demonstrates how to establish an Attested TLS session between two enclaves, or between an enclave and a host.

The KE library will not be available in the OE SDK. Existing ISV enclave and host software that uses the KE library can be ported to use standard-based Attested TLS protocol supported by the OE SDK.

## Functions and Data Structures Reference

### Enclave Creation and Destruction

### ECalls

### Quoting and Attestation

### Data Sealing

### Thread Synchronization

#### Spin locks
The Intel SGX SDK provides the following definitions for spin locks.
```c
typedef volatile uint32_t sgx_spinlock_t;
#define SGX_SPINLOCK_INITIALIZER 0
uint32_t SGXAPI sgx_spin_lock(sgx_spinlock_t *lock);
uint32_t SGXAPI sgx_spin_unlock(sgx_spinlock_t *lock);
```

The OE SDK provides the following
```c
typedef volatile uint32_t oe_spinlock_t;
#define OE_SPINLOCK_INITIALIZER 0
oe_result_t oe_spin_lock(oe_spinlock_t* spinlock);
oe_result_t oe_spin_unlock(oe_spinlock_t* spinlock);
```

The OE SDK functions, types, and defines can be used instead of the SGX SDK ones. Also, the OE SDK provides some additional versions of the APIs (trylock, init, etc).

#### Mutexes
The SGX APIs for mutexes are:
```c
int SGXAPI sgx_thread_mutex_init(sgx_thread_mutex_t *mutex, const sgx_thread_mutexattr_t *unused);
int SGXAPI sgx_thread_mutex_destroy(sgx_thread_mutex_t *mutex);
int SGXAPI sgx_thread_mutex_lock(sgx_thread_mutex_t *mutex);
int SGXAPI sgx_thread_mutex_trylock(sgx_thread_mutex_t *mutex);
int SGXAPI sgx_thread_mutex_unlock(sgx_thread_mutex_t *mutex);
```

The OE APIs corresponding to these are:
```c
oe_result_t oe_mutex_init(oe_mutex_t* mutex);
oe_result_t oe_mutex_destroy(oe_mutex_t* mutex);
oe_result_t oe_mutex_lock(oe_mutex_t* mutex);
oe_result_t oe_mutex_trylock(oe_mutex_t* mutex);
oe_result_t oe_mutex_unlock(oe_mutex_t* mutex);
```
The differences in the APIs are in the initialization. The current OE SDK implementation does not accept any mutex attributes. In its current implementation they are all initialized as `PTHREAD_MUTEX_RECURSIVE_NP`. Initialization is simplified via the `OE_MUTEX_INITIALIZER` define:

```c
// Default OE MUTEX initializater. All mutexes are recursive.
#define OE_MUTEX_INITIALIZER \
    {                        \
        {                    \
            0                \
        }                    \
    }
```
 
The SGX API declares but ignores the mutex attributes in the initialization routine. The major difference is that the SGX SDK does support and define an initializer for recursive and another for a non-recursive mutex.
```c
#define SGX_THREAD_MUTEX_NONRECURSIVE   0x01
#define SGX_THREAD_MUTEX_RECURSIVE      0x02
#define SGX_THREAD_NONRECURSIVE_MUTEX_INITIALIZER \
            {0, SGX_THREAD_MUTEX_NONRECURSIVE, 0, SGX_THREAD_T_NULL, {SGX_THREAD_T_NULL, SGX_THREAD_T_NULL}}
#define SGX_THREAD_RECURSIVE_MUTEX_INITIALIZER \
            {0, SGX_THREAD_MUTEX_RECURSIVE, 0, SGX_THREAD_T_NULL, {SGX_THREAD_T_NULL, SGX_THREAD_T_NULL}}
#define SGX_THREAD_MUTEX_INITIALIZER \
            SGX_THREAD_NONRECURSIVE_MUTEX_INITIALIZER
```

If your existing SGX enclave relies on the (default) non-recursive mutex behavior and will behave differently if it were a recursive mutex, your existing code may need to be modified.

#### Conditional Variables
The SGX APIs for conditional variables are:
```c
int SGXAPI sgx_thread_cond_init(sgx_thread_cond_t *cond, const sgx_thread_condattr_t *unused);
int SGXAPI sgx_thread_cond_destroy(sgx_thread_cond_t *cond);
int SGXAPI sgx_thread_cond_wait(sgx_thread_cond_t *cond, sgx_thread_mutex_t *mutex);
int SGXAPI sgx_thread_cond_signal(sgx_thread_cond_t *cond);
int SGXAPI sgx_thread_cond_broadcast(sgx_thread_cond_t *cond);
#define SGX_THREAD_COND_INITIALIZER  {0, {SGX_THREAD_T_NULL, SGX_THREAD_T_NULL}}
```
The corresponding OE APIs are:
```c
oe_result_t oe_cond_init(oe_cond_t* cond);
oe_result_t oe_cond_destroy(oe_cond_t* cond);
oe_result_t oe_cond_wait(oe_cond_t* cond, oe_mutex_t* mutex);
oe_result_t oe_cond_signal(oe_cond_t* cond);
oe_result_t oe_cond_broadcast(oe_cond_t* cond);
#define OE_COND_INITIALIZER \
    {                       \
        {                   \
            0               \
        }                   \
    }
```
These APIs provide the same functionality.

#### Reader Writer Locks
Both SDKs support `rwlock`s. The SGX SDK definitions are:
```c
/* Reader/Writer Locks */
int SGXAPI sgx_thread_rwlock_init(sgx_thread_rwlock_t *rwlock, const sgx_thread_rwlockattr_t *unused);
int SGXAPI sgx_thread_rwlock_destroy(sgx_thread_rwlock_t *rwlock);
int SGXAPI sgx_thread_rwlock_rdlock(sgx_thread_rwlock_t *rwlock);
int SGXAPI sgx_thread_rwlock_wrlock(sgx_thread_rwlock_t *rwlock);
int SGXAPI sgx_thread_rwlock_unlock(sgx_thread_rwlock_t *rwlock);
int SGXAPI sgx_thread_rwlock_tryrdlock(sgx_thread_rwlock_t *rwlock);
int SGXAPI sgx_thread_rwlock_trywrlock(sgx_thread_rwlock_t *rwlock);

int SGXAPI sgx_thread_rwlock_rdunlock(sgx_thread_rwlock_t *rwlock);
int SGXAPI sgx_thread_rwlock_wrunlock(sgx_thread_rwlock_t *rwlock);
```

```c
oe_result_t oe_rwlock_init(oe_rwlock_t* rw_lock);
oe_result_t oe_rwlock_destroy(oe_rwlock_t* rw_lock);
oe_result_t oe_rwlock_rdlock(oe_rwlock_t* rw_lock);
oe_result_t oe_rwlock_wrlock(oe_rwlock_t* rw_lock);
oe_result_t oe_rwlock_unlock(oe_rwlock_t* rw_lock);
oe_result_t oe_rwlock_tryrdlock(oe_rwlock_t* rw_lock);
oe_result_t oe_rwlock_trywrlock(oe_rwlock_t* rw_lock);
```

As you can see above, the SGX SDK provides some unlock APIs that specify whether or not you are trying to unlock a read lock or write lock. The OE SDK has a single unlock API that can be used instead (the SGX SDK also provides this same unlock API as well).

#### Utility functions
The SGX SDK provides the following utility functions
```c
sgx_thread_t SGXAPI sgx_thread_self(void);
int sgx_thread_equal(sgx_thread_t a, sgx_thread_t b);
```

These have direct equivalents in the OE SDK:
```c
oe_thread_t oe_thread_self(void);
bool oe_thread_equal(oe_thread_t thread1, oe_thread_t thread2);
```


## Authors

Cedric Xing (cedric.xing@intel.com)
Shanwei Cen (@shnwc)
