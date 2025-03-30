# `webauthn_rp`

[<img alt="git" src="https://git.philomathiclife.com/badges/webauthn_rp.svg" height="20">](https://git.philomathiclife.com/webauthn_rp/log.html)
[<img alt="crates.io" src="https://img.shields.io/crates/v/webauthn_rp.svg?style=for-the-badge&color=fc8d62&logo=rust" height="20">](https://crates.io/crates/webauthn_rp)
[<img alt="docs.rs" src="https://img.shields.io/badge/docs.rs-webauthn_rp-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs" height="20">](https://docs.rs/webauthn_rp/latest/webauthn_rp/)

`webauthn_rp` is a library for _server-side_
[Web Authentication (WebAuthn)](https://www.w3.org/TR/webauthn-3/#sctn-rp-operations) Relying Party
(RP) operations.

The purpose of a server-side RP library is to be modular so that any client can be used with it as a backend
_including_ native applications—WebAuthn technically only covers web applications; however it's relatively easy
to adapt to native applications as well. It achieves this by not assuming how data is sent to/from the client;
having said that, there are pre-defined serialization formats for "common" deployments which can be used when
[`serde`](#serde) is enabled.

## Cargo "features"

[`custom`](#custom) or both [`bin`](#bin) and [`serde`](#serde) must be enabled; otherwise a `compile_error`
 will occur.

### `bin`

Enables binary (de)serialization via `Encode` and `Decode`. Since registered credentials will almost always
have to be saved to persistent storage, _some_ form of (de)serialization is necessary. In the event `bin` is
unsuitable or only partially suitable (e.g., human-readable output is desired), one will need to enable
[`custom`](#custom) to allow construction of certain types (e.g., `AuthenticatedCredential`).

If possible and desired, one may wish to save the data "directly" to avoid any potential temporary allocations.
For example `StaticState::encode` will return a `Vec` containing hundreds (and possibly thousands in the
extreme case) of bytes if the underlying public key is an RSA key. This additional allocation and copy of data
is obviously avoided if `StaticState` is stored as a
[composite type](https://www.postgresql.org/docs/current/rowtypes.html) or its fields are stored in separate
columns when written to a relational database (RDB).

### `custom`

Exposes functions (e.g., `AuthenticatedCredential::new`) that allows one to construct instances of types that
cannot be constructed when [`bin`](#bin) or [`serde`](#serde) is not enabled.

### `serde`

This feature _strictly_ adheres to the JSON-motivated definitions. You _will_ encounter clients that send data that
cannot be deserialized using this feature. For many [`serde_relaxed`](#serde_relaxed) should be used instead.

Enables (de)serialization of data sent to/from the client via [`serde`](https://docs.rs/serde/latest/serde/)
based on the JSON-motivated definitions (e.g.,
[`RegistrationResponseJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson)). Since
data has to be sent to/from the client, _some_ form of (de)serialization is necessary. In the event `serde`
is unsuitable or only partially suitable, one will need to enable [`custom`](#custom) to allow construction
of certain types (e.g., `Registration`).

Code is _strongly_ encouraged to rely on the `Deserialize` implementations as much as possible to reduce the
chances of improperly deserializing the client data.

Note that clients are free to send data in whatever form works best, so there is no requirement the
JSON-motivated definitions are used even when JSON is sent. This is especially relevant since the JSON-motivated
definitions were only added in [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/); thus many deployments only
partially conform. Some specific deviations that may require partial customization of deserialization are the
following:

* [`ArrayBuffer`](https://webidl.spec.whatwg.org/#idl-ArrayBuffer)s encoded using something other than
  base64url.
* `ArrayBuffer`s that are encoded multiple times (including the use of different encodings each time).
* Missing fields (e.g.,
  [`transports`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponsejson-transports)).
* Different field names (e.g., `extensions` instead of
  [`clientExtensionResults`](https://www.w3.org/TR/webauthn-3/#dom-registrationresponsejson-clientextensionresults)).

### `serde_relaxed`

Automatically enables [`serde`](#serde) in addition to "relaxed" `Deserialize` implementations
(e.g., `RegistrationRelaxed`). Roughly "relaxed" translates to unknown fields being ignored and only
the fields necessary for construction of the type are required. Case still matters, duplicate fields are still
forbidden, and interrelated data validation is still performed when applicable. This can be useful when one
wants to accommodate non-conforming clients or clients that implement older versions of the spec.

### `serializable_server_state`

Automatically enables [`bin`](#bin) in addition to `Encode` and `Decode` implementations for
`RegistrationServerState` and `AuthenticationServerState`. Less accurate `SystemTime` is used instead of
`Instant` for timeout enforcement. This should be enabled if you don't desire to use in-memory collections to
store the instances of those types.

Note even when written to persistent storage, an application should still periodically remove expired ceremonies.
If one is using a relational database (RDB); then one can achieve this by storing `ServerState::sent_challenge`,
the `Vec` returned from `Encode::encode`, and `ServerState::expiration` and periodically remove all rows
whose expiration exceeds the current date and time.

## Registration and authentication

Both [registration](https://www.w3.org/TR/webauthn-3/#registration-ceremony) and
[authentication](https://www.w3.org/TR/webauthn-3/#authentication-ceremony) ceremonies rely on "challenges", and
these challenges are inherently temporary. For this reason the data associated with challenge completion can
often be stored in memory without concern for out-of-memory (OOM) conditions. There are several benefits to
storing such data in memory:

* No data manipulation
    * By leveraging move semantics, the data sent to the client cannot be mutated once the ceremony begins.
* Improved timeout enforcement
    * By ensuring the same machine that started the ceremony is also used to finish the ceremony, deviation of
      system clocks is not a concern. Additionally, allowing serialization requires the use of some form of
      cross-platform "timestamp" (e.g., [Unix time](https://en.wikipedia.org/wiki/Unix_time)) which differ in
      implementation (e.g., platforms implement leap seconds in different ways) and are often not monotonically
      increasing. If data resides in memory, a monotonic `Instant` can be used instead.

It is for those reasons data like `RegistrationServerState` are not serializable by default and require the
use of in-memory collections (e.g., `FixedCapHashSet`). To better ensure OOM is not a concern, RPs should set
reasonable timeouts. Since ceremonies can only be completed by moving data (e.g.,
`RegistrationServerState::verify`), ceremony completion is guaranteed to free up the memory used—
`RegistrationServerState` instances are only 48 bytes on `x86_64-unknown-linux-gnu` platforms. To avoid issues
related to incomplete ceremonies, RPs can periodically iterate the collection for expired ceremonies and remove
such data. Other techniques can be employed as well to mitigate OOM, but they are application specific and
out-of-scope. If this is undesirable, one can enable [`serializable_server_state`](#serializable_server_state)
so that `RegistrationServerState` and `AuthenticationServerState` implement `Encode` and `Decode`. Another
reason one may need to store this information persistently is for load-balancing purposes where the server that
started the ceremony is not guaranteed to be the server that finishes the ceremony.

## Supported signature algorithms

The only supported signature algorithms are the following:

* Ed25519 as defined in [RFC 8032 § 5.1](https://www.rfc-editor.org/rfc/rfc8032#section-5.1). This corresponds
  to `CoseAlgorithmIdentifier::Eddsa`.
* ECDSA as defined in [SEC 1 Version 2.0 § 4.1](https://www.secg.org/sec1-v2.pdf#subsection.4.1) using SHA-256
  as the hash function and NIST P-256 as defined in
  [NIST SP 800-186 § 3.2.1.3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf#%5B%7B%22num%22%3A229%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C275%2C0%5D)
  for the underlying elliptic curve. This corresponds to `CoseAlgorithmIdentifier::Es256`.
* ECDSA as defined in SEC 1 Version 2.0 § 4.1 using SHA-384 as the hash function and NIST P-384 as defined in
  [NIST SP 800-186 § 3.2.1.4](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf#%5B%7B%22num%22%3A232%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C264%2C0%5D)
  for the underlying elliptic curve. This corresponds to `CoseAlgorithmIdentifier::Es384`.
* RSASSA-PKCS1-v1_5 as defined in [RFC 8017 § 8.2](https://www.rfc-editor.org/rfc/rfc8017#section-8.2) using
  SHA-256 as the hash function. This corresponds to `CoseAlgorithmIdentifier::Rs256`.

## Correctness of code

This library more strictly adheres to the spec than many other similar libraries including but not limited to
the following ways:

* [CTAP2 canonical CBOR encoding form](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#ctap2-canonical-cbor-encoding-form).
* `Deserialize` implementations requiring _exact_ conformance (e.g., not allowing unknown data).
* More thorough interrelated data validation (e.g., all places a Credential ID exists must match).
* Implement a lot of recommended (i.e., SHOULD) criteria (e.g.,
  [User display names conforming to the Nickname Profile as defined in RFC 8266](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialentity-name)).

Unfortunately like almost all software, this library has not been formally verified; however great care is
employed in the following ways:

* Leverage move semantics to prevent mutation of data once in a static state.
* Ensure a great many invariants via types.
* Reduce code duplication.
* Reduce variable mutation allowing for simpler algebraic reasoning.
* `panic`-free code[^note] (i.e., define true/total functions).
* Ensure arithmetic "side effects" don't occur (e.g., overflow).
* Aggressive use of compiler and [Clippy](https://doc.rust-lang.org/stable/clippy/lints.html) lints.
* Unit tests for common cases, edge cases, and error cases.

## Cryptographic libraries

This library does not rely on _any_ sensitive data (e.g., private keys) as only signature verification is
ever performed. This means that the only thing that matters with the libraries used is their algorithmic
correctness and not other normally essential aspects like susceptibility to side-channel attacks. While I
personally believe the libraries that are used are at least as "secure" as alternatives even when dealing with
sensitive data, one only needs to audit the correctness of the libraries to be confident in their use. In fact
[`curve25519_dalek`](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/#backends) has been formally
verified when the [`fiat`](https://github.com/mit-plv/fiat-crypto) backend is used making it _objectively_
better than many other libraries whose correctness has not been proven. Two additional benefits of the library
choices are simpler APIs making it more likely their use is correct and better cross-platform compatibility.

## Minimum Supported Rust Version (MSRV)

This will frequently be updated to be the same as stable. Specifically, any time stable is updated and that
update has "useful" features or compilation no longer succeeds (e.g., due to new compiler lints), then MSRV
will be updated.

MSRV changes will correspond to a SemVer patch version bump pre-`1.0.0`; otherwise a minor version bump.

## SemVer Policy

* All on-by-default features of this library are covered by SemVer
* MSRV is considered exempt from SemVer as noted above

## License

Licensed under either of

* Apache License, Version 2.0 ([LICENSE-APACHE](https://www.apache.org/licenses/LICENSE-2.0))
* MIT license ([LICENSE-MIT](https://opensource.org/licenses/MIT))

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

Before any PR is sent, `cargo clippy` and `cargo t` should be run _for each possible combination of "features"_
using stable Rust. One easy way to achieve this is by building `ci` and invoking it with no commands in the
`webauthn_rp` directory or sub-directories. You can fetch `ci` via `git clone https://git.philomathiclife.com/repos/ci`,
and it can be built with `cargo build --release`. Additionally,
`RUSTDOCFLAGS="--cfg docsrs" cargo +nightly doc --all-features` should be run to ensure documentation can be built.

### Status

This package is actively maintained and will conform to the
[latest WebAuthn API version](https://www.w3.org/TR/webauthn-3/). Previous versions will not be supported—excluding
bug fixes of course—however functionality will exist to facilitate the migration process from the previous version.

The crate is only tested on `x86_64-unknown-linux-gnu` and `x86_64-unknown-openbsd` targets, but it should work
on most platforms.

[^note]: `panic`s related to memory allocations or stack overflow are possible since such issues are not
         formally guarded against.
