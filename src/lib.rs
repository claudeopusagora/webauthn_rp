//! [![git]](https://git.philomathiclife.com/webauthn_rp/log.html)&ensp;[![crates-io]](https://crates.io/crates/webauthn_rp)&ensp;[![docs-rs]](crate)
//!
//! [git]: https://git.philomathiclife.com/git_badge.svg
//! [crates-io]: https://img.shields.io/badge/crates.io-fc8d62?style=for-the-badge&labelColor=555555&logo=rust
//! [docs-rs]: https://img.shields.io/badge/docs.rs-66c2a5?style=for-the-badge&labelColor=555555&logo=docs.rs
//!
//! `webauthn_rp` is a library for _server-side_
//! [Web Authentication (WebAuthn)](https://www.w3.org/TR/webauthn-3/#sctn-rp-operations) Relying Party
//! (RP) operations.
//!
//! The purpose of a server-side RP library is to be modular so that any client can be used with it as a backend
//! _including_ native applications—WebAuthn technically only covers web applications; however it's relatively easy
//! to adapt to native applications as well. It achieves this by not assuming how data is sent to/from the client;
//! having said that, there are pre-defined serialization formats for "common" deployments which can be used when
//! [`serde`](#serde) is enabled.
//!
//! ## Cargo "features"
//!
//! [`custom`](#custom) or both [`bin`](#bin) and [`serde`](#serde) must be enabled; otherwise a [`compile_error`]
//!  will occur.
//!
//! ### `bin`
//!
//! Enables binary (de)serialization via [`Encode`] and [`Decode`]. Since registered credentials will almost always
//! have to be saved to persistent storage, _some_ form of (de)serialization is necessary. In the event `bin` is
//! unsuitable or only partially suitable (e.g., human-readable output is desired), one will need to enable
//! [`custom`](#custom) to allow construction of certain types (e.g., [`AuthenticatedCredential`]).
//!
//! If possible and desired, one may wish to save the data "directly" to avoid any potential temporary allocations.
//! For example [`StaticState::encode`] will return a [`Vec`] containing hundreds (and possibly thousands in the
//! extreme case) of bytes if the underlying public key is an RSA key. This additional allocation and copy of data
//! is obviously avoided if [`StaticState`] is stored as a
//! [composite type](https://www.postgresql.org/docs/current/rowtypes.html) or its fields are stored in separate
//! columns when written to a relational database (RDB).
//!
//! ### `custom`
//!
//! Exposes functions (e.g., [`AuthenticatedCredential::new`]) that allows one to construct instances of types that
//! cannot be constructed when [`bin`](#bin) or [`serde`](#serde) is not enabled.
//!
//! ### `serde`
//!
//! Enables (de)serialization of data sent to/from the client via [`serde`](https://docs.rs/serde/latest/serde/)
//! based on the JSON-motivated definitions (e.g.,
//! [`RegistrationResponseJSON`](https://www.w3.org/TR/webauthn-3/#dictdef-registrationresponsejson)). Since
//! data has to be sent to/from the client, _some_ form of (de)serialization is necessary. In the event `serde`
//! is unsuitable or only partially suitable, one will need to enable [`custom`](#custom) to allow construction
//! of certain types (e.g., [`Registration`]).
//!
//! Code is _strongly_ encouraged to rely on the [`Deserialize`] implementations as much as possible to reduce the
//! chances of improperly deserializing the client data.
//!
//! Note that clients are free to send data in whatever form works best, so there is no requirement the
//! JSON-motivated definitions are used even when JSON is sent. This is especially relevant since the JSON-motivated
//! definitions were only added in [WebAuthn Level 3](https://www.w3.org/TR/webauthn-3/); thus many deployments only
//! partially conform. Some specific deviations that may require partial customization of deserialization are the
//! following:
//!
//! * [`ArrayBuffer`](https://webidl.spec.whatwg.org/#idl-ArrayBuffer)s encoded using something other than
//!   base64url.
//! * `ArrayBuffer`s that are encoded multiple times (including the use of different encodings each time).
//! * Missing fields (e.g.,
//!   [`transports`](https://www.w3.org/TR/webauthn-3/#dom-authenticatorattestationresponsejson-transports)).
//! * Different field names (e.g., `extensions` instead of
//!   [`clientExtensionResults`](https://www.w3.org/TR/webauthn-3/#dom-registrationresponsejson-clientextensionresults)).
//!
//! ### `serde_relaxed`
//!
//! Automatically enables [`serde`](#serde) in addition to "relaxed" [`Deserialize`] implementations
//! (e.g., [`RegistrationRelaxed`]). Roughly "relaxed" translates to unknown fields being ignored and only
//! the fields necessary for construction of the type are required. Case still matters, duplicate fields are still
//! forbidden, and interrelated data validation is still performed when applicable. This can be useful when one
//! wants to accommodate non-conforming clients or clients that implement older versions of the spec.
//!
//! ### `serializable_server_state`
//!
//! Automatically enables [`bin`](#bin) in addition to [`Encode`] and [`Decode`] implementations for
//! [`RegistrationServerState`] and [`AuthenticationServerState`]. Less accurate [`SystemTime`] is used instead of
//! [`Instant`] for timeout enforcement. This should be enabled if you don't desire to use in-memory collections to
//! store the instances of those types.
//!
//! Note even when written to persistent storage, an application should still periodically remove expired ceremonies.
//! If one is using a relational database (RDB); then one can achieve this by storing [`ServerState::sent_challenge`],
//! the `Vec` returned from [`Encode::encode`], and [`ServerState::expiration`] and periodically remove all rows
//! whose expiration exceeds the current date and time.
//!
//! ## Registration and authentication
//!
//! Both [registration](https://www.w3.org/TR/webauthn-3/#registration-ceremony) and
//! [authentication](https://www.w3.org/TR/webauthn-3/#authentication-ceremony) ceremonies rely on "challenges", and
//! these challenges are inherently temporary. For this reason the data associated with challenge completion can
//! often be stored in memory without concern for out-of-memory (OOM) conditions. There are several benefits to
//! storing such data in memory:
//!
//! * No data manipulation
//!     * By leveraging move semantics, the data sent to the client cannot be mutated once the ceremony begins.
//! * Improved timeout enforcement
//!     * By ensuring the same machine that started the ceremony is also used to finish the ceremony, deviation of
//!       system clocks is not a concern. Additionally, allowing serialization requires the use of some form of
//!       cross-platform "timestamp" (e.g., [Unix time](https://en.wikipedia.org/wiki/Unix_time)) which differ in
//!       implementation (e.g., platforms implement leap seconds in different ways) and are often not monotonically
//!       increasing. If data resides in memory, a monotonic [`Instant`] can be used instead.
//!
//! It is for those reasons data like [`RegistrationServerState`] are not serializable by default and require the
//! use of in-memory collections (e.g., [`FixedCapHashSet`]). To better ensure OOM is not a concern, RPs should set
//! reasonable timeouts. Since ceremonies can only be completed by moving data (e.g.,
//! [`RegistrationServerState::verify`]), ceremony completion is guaranteed to free up the memory used—
//! `RegistrationServerState` instances are only 48 bytes on `x86_64-unknown-linux-gnu` platforms. To avoid issues
//! related to incomplete ceremonies, RPs can periodically iterate the collection for expired ceremonies and remove
//! such data. Other techniques can be employed as well to mitigate OOM, but they are application specific and
//! out-of-scope. If this is undesirable, one can enable [`serializable_server_state`](#serializable_server_state)
//! so that `RegistrationServerState` and [`AuthenticationServerState`] implement [`Encode`] and [`Decode`]. Another
//! reason one may need to store this information persistently is for load-balancing purposes where the server that
//! started the ceremony is not guaranteed to be the server that finishes the ceremony.
//!
//! ## Supported signature algorithms
//!
//! The only supported signature algorithms are the following:
//!
//! * Ed25519 as defined in [RFC 8032 § 5.1](https://www.rfc-editor.org/rfc/rfc8032#section-5.1). This corresponds
//!   to [`CoseAlgorithmIdentifier::Eddsa`].
//! * ECDSA as defined in [SEC 1 Version 2.0 § 4.1](https://www.secg.org/sec1-v2.pdf#subsection.4.1) using SHA-256
//!   as the hash function and NIST P-256 as defined in
//!   [NIST SP 800-186 § 3.2.1.3](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf#%5B%7B%22num%22%3A229%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C275%2C0%5D)
//!   for the underlying elliptic curve. This corresponds to [`CoseAlgorithmIdentifier::Es256`].
//! * ECDSA as defined in SEC 1 Version 2.0 § 4.1 using SHA-384 as the hash function and NIST P-384 as defined in
//!   [NIST SP 800-186 § 3.2.1.4](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-186.pdf#%5B%7B%22num%22%3A232%2C%22gen%22%3A0%7D%2C%7B%22name%22%3A%22XYZ%22%7D%2C70%2C264%2C0%5D)
//!   for the underlying elliptic curve. This corresponds to [`CoseAlgorithmIdentifier::Es384`].
//! * RSASSA-PKCS1-v1_5 as defined in [RFC 8017 § 8.2](https://www.rfc-editor.org/rfc/rfc8017#section-8.2) using
//!   SHA-256 as the hash function. This corresponds to [`CoseAlgorithmIdentifier::Rs256`].
//!
//! ## Correctness of code
//!
//! This library more strictly adheres to the spec than many other similar libraries including but not limited to
//! the following ways:
//!
//! * [CTAP2 canonical CBOR encoding form](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#ctap2-canonical-cbor-encoding-form).
//! * `Deserialize` implementations requiring _exact_ conformance (e.g., not allowing unknown data).
//! * More thorough interrelated data validation (e.g., all places a Credential ID exists must match).
//! * Implement a lot of recommended (i.e., SHOULD) criteria (e.g.,
//!   [User display names conforming to the Nickname Profile as defined in RFC 8266](https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialentity-name)).
//!
//! Unfortunately like almost all software, this library has not been formally verified; however great care is
//! employed in the following ways:
//!
//! * Leverage move semantics to prevent mutation of data once in a static state.
//! * Ensure a great many invariants via types.
//! * Reduce code duplication.
//! * Reduce variable mutation allowing for simpler algebraic reasoning.
//! * `panic`-free code[^note] (i.e., define true/total functions).
//! * Ensure arithmetic "side effects" don't occur (e.g., overflow).
//! * Aggressive use of compiler and [Clippy](https://doc.rust-lang.org/stable/clippy/lints.html) lints.
//! * Unit tests for common cases, edge cases, and error cases.
//!
//! ## Cryptographic libraries
//!
//! This library does not rely on _any_ sensitive data (e.g., private keys) as only signature verification is
//! ever performed. This means that the only thing that matters with the libraries used is their algorithmic
//! correctness and not other normally essential aspects like susceptibility to side-channel attacks. While I
//! personally believe the libraries that are used are at least as "secure" as alternatives even when dealing with
//! sensitive data, one only needs to audit the correctness of the libraries to be confident in their use. In fact
//! [`curve25519_dalek`](https://docs.rs/curve25519-dalek/latest/curve25519_dalek/#backends) has been formally
//! verified when the [`fiat`](https://github.com/mit-plv/fiat-crypto) backend is used making it _objectively_
//! better than many other libraries whose correctness has not been proven. Two additional benefits of the library
//! choices are simpler APIs making it more likely their use is correct and better cross-platform compatibility.
//!
//! [^note]: `panic`s related to memory allocations or stack overflow are possible since such issues are not
//!          formally guarded against.
#![cfg_attr(docsrs, feature(doc_cfg))]
#![deny(
    unknown_lints,
    future_incompatible,
    let_underscore,
    missing_docs,
    nonstandard_style,
    refining_impl_trait,
    rust_2018_compatibility,
    rust_2018_idioms,
    rust_2021_compatibility,
    rust_2024_compatibility,
    unsafe_code,
    unused,
    warnings,
    clippy::all,
    clippy::cargo,
    clippy::complexity,
    clippy::correctness,
    clippy::nursery,
    clippy::pedantic,
    clippy::perf,
    clippy::restriction,
    clippy::style,
    clippy::suspicious
)]
#![expect(
    clippy::blanket_clippy_restriction_lints,
    clippy::exhaustive_enums,
    clippy::exhaustive_structs,
    clippy::implicit_return,
    clippy::min_ident_chars,
    clippy::missing_trait_methods,
    clippy::pub_with_shorthand,
    clippy::pub_use,
    clippy::ref_patterns,
    clippy::self_named_module_files,
    clippy::single_call_fn,
    clippy::single_char_lifetime_names,
    clippy::unseparated_literal_suffix,
    reason = "noisy, opinionated, and likely doesn't prevent bugs or improve APIs"
)]
#[cfg(not(any(feature = "custom", all(feature = "bin", feature = "serde"))))]
compile_error!("'custom' must be enabled or both 'bin' and 'serde' must be enabled");
#[cfg(feature = "serializable_server_state")]
use crate::request::{
    auth::ser_server_state::{
        DecodeAuthenticationServerStateErr, EncodeAuthenticationServerStateErr,
    },
    register::ser_server_state::DecodeRegistrationServerStateErr,
};
#[cfg(any(feature = "bin", feature = "custom"))]
use crate::response::error::CredentialIdErr;
#[cfg(feature = "serde_relaxed")]
use crate::response::ser_relaxed::SerdeJsonErr;
#[cfg(feature = "bin")]
use crate::{
    request::register::bin::{DecodeNicknameErr, DecodeUsernameErr},
    response::{
        bin::DecodeAuthTransportsErr,
        register::bin::{DecodeDynamicStateErr, DecodeStaticStateErr},
    },
};
use crate::{
    request::{
        auth::error::{RequestOptionsErr, SecondFactorErr},
        error::{AsciiDomainErr, DomainOriginParseErr, PortParseErr, SchemeParseErr, UrlErr},
        register::{
            error::{CreationOptionsErr, NicknameErr, UserHandleErr, UsernameErr},
            ResidentKeyRequirement, UserHandle,
        },
    },
    response::{
        auth::error::{AuthCeremonyErr, AuthenticatorDataErr as AuthAuthDataErr},
        error::CollectedClientDataErr,
        register::{
            error::{
                AaguidErr, AttestationObjectErr, AuthenticatorDataErr as RegAuthDataErr,
                RegCeremonyErr,
            },
            CredentialProtectionPolicy, DynamicState, Metadata, StaticState, UncompressedPubKey,
        },
        AuthTransports, CredentialId,
    },
};
#[cfg(doc)]
use crate::{
    request::{
        auth::{AllowedCredential, AllowedCredentials},
        register::{CoseAlgorithmIdentifier, Nickname, Username},
        AsciiDomain, DomainOrigin, FixedCapHashSet, Port, PublicKeyCredentialDescriptor, RpId,
        Scheme, ServerState, Url,
    },
    response::{
        auth::{self, AuthenticatorAssertion},
        register::{
            self, Aaguid, Attestation, AttestationObject, AttestedCredentialData,
            AuthenticatorExtensionOutput, ClientExtensionsOutputs, CompressedPubKey,
            CredentialPropertiesOutput,
        },
        CollectedClientData, Flag,
    },
};
#[cfg(all(doc, feature = "bin"))]
use bin::{Decode, Encode};
#[cfg(doc)]
use core::str::FromStr;
use core::{
    convert,
    error::Error,
    fmt::{self, Display, Formatter},
};
use data_encoding::{Encoding, BASE64URL_NOPAD};
#[cfg(all(doc, feature = "serde_relaxed"))]
use response::register::ser_relaxed::RegistrationRelaxed;
#[cfg(all(doc, feature = "serde"))]
use serde::Deserialize;
#[cfg(all(doc, feature = "serde_relaxed"))]
use serde_json::de::{Deserializer, StreamDeserializer};
#[cfg(feature = "serializable_server_state")]
use std::time::SystemTimeError;
#[cfg(doc)]
use std::time::{Instant, SystemTime};
/// Contains functionality to (de)serialize data to a data store.
#[cfg_attr(docsrs, doc(cfg(feature = "bin")))]
#[cfg(feature = "bin")]
pub mod bin;
/// Functionality for starting ceremonies.
///
/// # What kind of credential should I create?
///
/// Without partitioning the possibilities _too_ much, the following are possible authentication flows:
///
/// | Label | Username | Password | Client-side credential | Authenticator-side user verification | Recommended |
/// |-------|----------|----------|------------------------|--------------------------------------|:-----------:|
/// | 1     | Yes      | Yes      | Required               | Yes                                  |          ❌ |
/// | 2     | Yes      | Yes      | Required               | No                                   |          ❌ |
/// | 3     | Yes      | Yes      | Optional               | Yes                                  |          ❌ |
/// | <a name="label4">4</a>     | Yes      | Yes      | Optional               | No                                   |          ✅ |
/// | 5     | Yes      | No       | Required               | Yes                                  |          ❌ |
/// | 6     | Yes      | No       | Required               | No                                   |          ❌ |
/// | <a name="label7">7</a>     | Yes      | No       | Optional               | Yes                                  |          ❔ |
/// | 8     | Yes      | No       | Optional               | No                                   |          ❌ |
/// | 9     | No       | Yes      | Required               | Yes                                  |          ❌ |
/// | 10    | No       | Yes      | Required               | No                                   |          ❌ |
/// | 11    | No       | Yes      | Optional               | Yes                                  |          ❌ |
/// | 12    | No       | Yes      | Optional               | No                                   |          ❌ |
/// | <a name="label13">13</a>    | No       | No       | Required               | Yes                                  |          ✅ |
/// | 14    | No       | No       | Required               | No                                   |          ❌ |
/// | 15    | No       | No       | Optional               | Yes                                  |          ❌ |
/// | 16    | No       | No       | Optional               | No                                   |          ❌ |
///
/// * All `Label`s with both `Password` and `Authenticator-side user verification` set to `Yes` are not recommended
///   since the verification done on the authenticator is likely the same "factor" as a password; thus it does not
///   add benefit but only serves as an annoyance to users.
/// * All `Label`s with `Username` or `Password` set to `Yes` and `Client-side credential` set to `Required` are not
///   recommended since you may preclude authenticators that are storage constrained (e.g., security keys).
/// * All `Label`s with `Username` set to `No` and `Client-side credential` set to `Optional` are not possible since
///   RPs would not have a way to identify the set of encrypted credentials to pass to the unknown user.
/// * All `Label`s with `Password` and `Authenticator-side user verification` set to `No` are not recommended since
///   those are single-factor authentication schemes; thus anyone possessing the credential without also passing
///   some form of user verification (e.g., password) would authenticate.
/// * [`Label 7`](#label7) is possible for RPs that are comfortable passing an encrypted credential to a potential user
///   without having that user first pass another form of authentication. For many RPs passing such information even
///   if encrypted is not desirable though.
/// * [`Label 4`](#label4) is ideal as a single-factor flow incorporated within a wider multi-factor authentication (MFA)
///   setup. The easiest way to register such a credential is with
///   [`PublicKeyCredentialCreationOptions::second_factor`].
/// * [`Label 13`](#label13) is ideal for passkey setups as it allows for pleasant UX where a user does not have to type a
///   username nor password while still being secured with MFA with one of the factors being based on public-key
///   cryptography which for many is the most secure form of single-factor authentication. The easiest way to register
///   such a credential is with [`PublicKeyCredentialCreationOptions::passkey`].
///
/// Two other reasons one may prefer to construct client-side credentials is richer support for extensions (e.g.,
/// [`largeBlobKey`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-largeBlobKey-extension)
/// for CTAP 2.2 authenticators) and the ability to use both discoverable and nondiscoverable requests (i.e.,
/// [`PublicKeyCredentialRequestOptions::allow_credentials`] is empty and not empty respectively). The former is not
/// relevant for this library—at least currently—since the only extensions supported are applicable for both
/// client-side and server-side credentials. The latter can be important especially if an RP wants the ability to
/// seamlessly transition from a username and password scheme to a userless and passwordless one in the future.
///
/// Note the table is purely informative. While helper functions
/// (e.g., [`PublicKeyCredentialCreationOptions::passkey`]) only exist for [`Label 4`](#label4) and
/// [`Label 13`](#label13), one can create any credential since all fields in [`PublicKeyCredentialCreationOptions`]
/// and [`PublicKeyCredentialRequestOptions`] are accessible.
pub mod request;
/// Functionality for completing ceremonies.
///
/// Read [`request`] for more information about what credentials one should create.
pub mod response;
#[doc(inline)]
pub use crate::{
    request::{
        auth::{
            AuthenticationClientState, AuthenticationServerState, PublicKeyCredentialRequestOptions,
        },
        register::{
            PublicKeyCredentialCreationOptions, RegistrationClientState, RegistrationServerState,
        },
    },
    response::{auth::Authentication, register::Registration},
};
/// Error returned in [`RegCeremonyErr::Credential`] and [`AuthCeremonyErr::Credential`] as well as
/// from [`AuthenticatedCredential::new`].
#[derive(Clone, Copy, Debug)]
pub enum CredentialErr {
    /// Variant when [`CredentialProtectionPolicy::UserVerificationRequired`], but
    /// [`DynamicState::user_verified`] is `false`.
    CredProtectUserVerificationRequiredWithoutUserVerified,
    /// Variant when [`AuthenticatorExtensionOutput::hmac_secret`] is `Some(true)`, but
    /// [`DynamicState::user_verified`] is `false`.
    HmacSecretWithoutUserVerified,
    /// Variant when [`AuthenticatorExtensionOutput::hmac_secret`] is `Some(true)`, but
    /// [`ClientExtensionsOutputs::prf`] is not `Some(AuthenticationExtensionsPRFOutputs { enabled: true })`.
    HmacSecretWithoutPrf,
    /// Variant when [`ClientExtensionsOutputs::prf`] is
    /// `Some(AuthenticationExtensionsPRFOutputs { enabled: true })`, but
    /// [`AuthenticatorExtensionOutput::hmac_secret`] is not `Some(true)`.
    PrfWithoutHmacSecret,
    /// Variant when [`ResidentKeyRequirement::Required`] was sent, but
    /// [`CredentialPropertiesOutput::rk`] is `Some(false)`.
    ResidentKeyRequiredServerCredentialCreated,
}
impl Display for CredentialErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(match *self {
            Self::CredProtectUserVerificationRequiredWithoutUserVerified => {
                "credProtect requires user verification, but the user is not verified"
            }
            Self::HmacSecretWithoutUserVerified => {
                "hmac-secret is enabled, but the user is not verified"
            }
            Self::HmacSecretWithoutPrf => "hmac-secret was enabled but prf was not",
            Self::PrfWithoutHmacSecret => "prf was enabled, but hmac-secret was not",
            Self::ResidentKeyRequiredServerCredentialCreated => {
                "server-side credential was created, but a client-side credential is required"
            }
        })
    }
}
impl Error for CredentialErr {}
/// Checks if the `static_state` and `dynamic_state` are valid for a credential.
///
/// # Errors
///
/// Errors iff `static_state` or `dynamic_state` are invalid.
fn verify_static_and_dynamic_state<T>(
    static_state: &StaticState<T>,
    dynamic_state: DynamicState,
) -> Result<(), CredentialErr> {
    if dynamic_state.user_verified {
        Ok(())
    } else if matches!(
        static_state.extensions.cred_protect,
        CredentialProtectionPolicy::UserVerificationRequired
    ) {
        Err(CredentialErr::CredProtectUserVerificationRequiredWithoutUserVerified)
    } else if static_state.extensions.hmac_secret.unwrap_or_default() {
        Err(CredentialErr::HmacSecretWithoutUserVerified)
    } else {
        Ok(())
    }
}
/// Registered credential that needs to be saved server-side to perform future
/// [authentication ceremonies](https://www.w3.org/TR/webauthn-3/#authentication-ceremony) with
/// [`AuthenticatedCredential`].
///
/// When saving `RegisteredCredential` to persistent storage, one will almost always want to save the contained data
/// separately. The reasons for this are the following:
///
/// * [`CredentialId`]
///     * MUST be globally unique, and it will likely be easier to enforce such uniqueness when it's separate.
///     * Fetching the [`AuthenticatedCredential`] by [`Authentication::raw_id`] when completing the
///       authentication ceremony via [`AuthenticationServerState::verify`] will likely be easier than alternatives.
/// * [`AuthTransports`]
///     * Fetching [`CredentialId`]s and associated `AuthTransports` by [`UserHandle`] will likely make credential
///       registration easier since one should set [`PublicKeyCredentialCreationOptions::exclude_credentials`] to
///       the [`PublicKeyCredentialDescriptor`]s belonging to a `UserHandle` in order to avoid accidentally
///       overwriting an existing credential on the authenticator.
///     * Fetching `CredentialId`s and associated `AuthTransports` by `UserHandle` will likely make starting
///       authentication ceremonies easier for non-discoverable requests (i.e., setting
///       [`PublicKeyCredentialRequestOptions::allow_credentials`] to a non-empty [`AllowedCredentials`]).
/// * [`UserHandle`]
///     * Fetching the [`AuthenticatedCredential`] by [`Authentication::raw_id`] must also coincide with
///       verifying the associated `UserHandle` matches [`AuthenticatorAssertion::user_handle`] when `Some`.
///     * Fetching [`CredentialId`]s and associated [`AuthTransports`] by `UserHandle` will likely make credential
///       registration easier since one should set [`PublicKeyCredentialCreationOptions::exclude_credentials`] to
///       the [`PublicKeyCredentialDescriptor`]s belonging to a `UserHandle` in order to avoid accidentally
///       overwriting an existing credential on the authenticator.
///     * Fetching `CredentialId`s and associated `AuthTransports` by `UserHandle` will likely make starting
///       authentication ceremonies easier for non-discoverable requests (i.e., setting
///       [`PublicKeyCredentialRequestOptions::allow_credentials`] to a non-empty [`AllowedCredentials`]).
/// * [`DynamicState`]
///     * `DynamicState` is the only part that is ever updated after a successful authentication ceremony
///       via [`AuthenticationServerState::verify`]. It being separate allows for smaller and quicker updates.
/// * [`Metadata`]
///     * Informative data that is never used during authentication ceremonies; consequently, one may wish to
///       not even save this information.
/// * [`StaticState`]
///     * All other data exists as part of `StaticState`.
///
/// It is for those reasons that `RegisteredCredential` does not implement [`Encode`] or [`Decode`]; instead its parts
/// do.
///
/// Note that [`RpId`] and user information other than the `UserHandle` are not stored in `RegisteredCredential`.
/// RPs that wish to store such information must do so on their own. Since user information is likely the same
/// for a given `UserHandle` and `RpId` is likely static, it makes little sense to store such information
/// automatically. Types like [`Username`] implement `Encode` and `Decode` to assist such a thing.
///
/// When registering a credential, [`AttestedCredentialData::aaguid`], [`AttestedCredentialData::credential_id`],
/// and [`AttestedCredentialData::credential_public_key`] will be the sources for [`Metadata::aaguid`],
/// [`Self::id`], and [`StaticState::credential_public_key`] respectively. Additionally, there must be some way for
/// the RP to know what `UserHandle` the [`Registration`] is associated with (e.g., a session cookie); thus the
/// source of [`Self::user_id`] is the `UserHandle` passed to [`RegistrationServerState::verify`].
///
/// The only way to create this is via `RegistrationServerState::verify`.
#[derive(Debug)]
pub struct RegisteredCredential<'reg, 'user> {
    /// The credential ID.
    ///
    /// For client-side credentials, this is a unique identifier; but for server-side
    /// credentials, this _is_ the credential (i.e., the encrypted private key and necessary information).
    id: CredentialId<&'reg [u8]>,
    /// Hints for how the client might communicate with the authenticator containing the credential.
    transports: AuthTransports,
    /// The identifier for the user.
    ///
    /// Unlike [`Self::id`] which is globally unique for an RP, this is unique up to "user" (i.e.,
    /// multiple [`CredentialId`]s will often exist for the same `UserHandle`).
    user_id: UserHandle<&'user [u8]>,
    /// Immutable state returned during registration.
    static_state: StaticState<UncompressedPubKey<'reg>>,
    /// State that can change during authentication ceremonies.
    dynamic_state: DynamicState,
    /// Metadata.
    metadata: Metadata<'reg>,
}
impl<'reg, 'user> RegisteredCredential<'reg, 'user> {
    /// The credential ID.
    ///
    /// For client-side credentials, this is a unique identifier; but for server-side
    /// credentials, this _is_ the credential (i.e., the encrypted private key and necessary information).
    #[inline]
    #[must_use]
    pub const fn id(&self) -> CredentialId<&'reg [u8]> {
        self.id
    }
    /// Hints for how the client might communicate with the authenticator containing the credential.
    #[inline]
    #[must_use]
    pub const fn transports(&self) -> AuthTransports {
        self.transports
    }
    /// The identifier for the user.
    ///
    /// Unlike [`Self::id`] which is globally unique for an RP, this is unique up to "user" (i.e.,
    /// multiple [`CredentialId`]s will often exist for the same `UserHandle`).
    #[inline]
    #[must_use]
    pub const fn user_id(&self) -> UserHandle<&'user [u8]> {
        self.user_id
    }
    /// Immutable state returned during registration.
    #[inline]
    #[must_use]
    pub const fn static_state(&self) -> StaticState<UncompressedPubKey<'reg>> {
        self.static_state
    }
    /// State that can change during authentication ceremonies.
    #[inline]
    #[must_use]
    pub const fn dynamic_state(&self) -> DynamicState {
        self.dynamic_state
    }
    /// Metadata.
    #[inline]
    #[must_use]
    pub const fn metadata(&self) -> Metadata<'reg> {
        self.metadata
    }
    /// Constructs a `RegisteredCredential` based on the passed arguments.
    ///
    /// # Errors
    ///
    /// Errors iff the passed arguments are invalid. Read [`CredentialErr`]
    /// for more information.
    #[inline]
    fn new<'a: 'reg, 'b: 'user>(
        id: CredentialId<&'a [u8]>,
        transports: AuthTransports,
        user_id: UserHandle<&'b [u8]>,
        static_state: StaticState<UncompressedPubKey<'a>>,
        dynamic_state: DynamicState,
        metadata: Metadata<'a>,
    ) -> Result<Self, CredentialErr> {
        verify_static_and_dynamic_state(&static_state, dynamic_state).and_then(|()| {
            // `verify_static_and_dynamic_state` already ensures that
            // `hmac-secret` is not `Some(true)` when `!dynamic_state.user_verified`;
            // thus we only need to check that one is not enabled without the other.
            if static_state.extensions.hmac_secret.unwrap_or_default() {
                if metadata
                    .client_extension_results
                    .prf
                    .is_some_and(|prf| prf.enabled)
                {
                    Ok(())
                } else {
                    Err(CredentialErr::HmacSecretWithoutPrf)
                }
            } else if metadata
                .client_extension_results
                .prf
                .is_some_and(|prf| prf.enabled)
            {
                Err(CredentialErr::PrfWithoutHmacSecret)
            } else {
                Ok(())
            }
            .and_then(|()| {
                if !matches!(metadata.resident_key, ResidentKeyRequirement::Required)
                    || metadata
                        .client_extension_results
                        .cred_props
                        .as_ref()
                        .is_none_or(|props| props.rk.is_none_or(convert::identity))
                {
                    Ok(Self {
                        id,
                        transports,
                        user_id,
                        static_state,
                        dynamic_state,
                        metadata,
                    })
                } else {
                    Err(CredentialErr::ResidentKeyRequiredServerCredentialCreated)
                }
            })
        })
    }
    /// Returns the contained data consuming `self`.
    #[expect(
        clippy::type_complexity,
        reason = "type aliases with bounds are even more problematic at least until lazy_type_alias is stable"
    )]
    #[inline]
    #[must_use]
    pub const fn into_parts(
        self,
    ) -> (
        CredentialId<&'reg [u8]>,
        AuthTransports,
        UserHandle<&'user [u8]>,
        StaticState<UncompressedPubKey<'reg>>,
        DynamicState,
        Metadata<'reg>,
    ) {
        (
            self.id,
            self.transports,
            self.user_id,
            self.static_state,
            self.dynamic_state,
            self.metadata,
        )
    }
    /// Returns the contained data.
    #[expect(
        clippy::type_complexity,
        reason = "type aliases with bounds are even more problematic at least until lazy_type_alias is stable"
    )]
    #[inline]
    #[must_use]
    pub const fn as_parts(
        &self,
    ) -> (
        CredentialId<&'reg [u8]>,
        AuthTransports,
        UserHandle<&'user [u8]>,
        StaticState<UncompressedPubKey<'reg>>,
        DynamicState,
        Metadata<'reg>,
    ) {
        (
            self.id,
            self.transports,
            self.user_id,
            self.static_state,
            self.dynamic_state,
            self.metadata,
        )
    }
}
/// Credential used in authentication ceremonies.
///
/// Similar to [`RegisteredCredential`] except designed to only contain the necessary data to complete
/// authentication ceremonies. In particular there is no [`AuthTransports`] or [`Metadata`],
/// [`StaticState::credential_public_key`] is [`CompressedPubKey`] that can own or borrow its data, [`Self::id`] is
/// based on the [`CredentialId`] passed to [`Self::new`] which itself must be from [`Authentication::raw_id`], and
/// [`Self::user_id`] is based on the [`UserHandle`] passed to [`Self::new`] which itself must be the value in
/// persistent storage associated with the `CredentialId`. When [`AuthenticatorAssertion::user_handle`] is `Some`,
/// this can be used for `Self::user_id` so long as it matches the value in persistent storage. Note it MUST be
/// `Some` when using discoverable requests (i.e., [`PublicKeyCredentialRequestOptions::allow_credentials`] is
/// empty); and when using non-discoverable requests (i.e., `PublicKeyCredentialRequestOptions::allow_credentials`
/// is non-empty), one should already have the user handle (e.g., in a session cookie) which can also be used.
///
/// Note `PublicKey` should be `CompressedPubKey` for this to be useful.
///
/// The only way to create this is via `Self::new`.
#[derive(Debug)]
pub struct AuthenticatedCredential<'cred, 'user, PublicKey> {
    /// The credential ID.
    ///
    /// For client-side credentials, this is a unique identifier; but for server-side
    /// credentials, this _is_ the credential (i.e., the encrypted private key and necessary information).
    id: CredentialId<&'cred [u8]>,
    /// The identifier for the user.
    ///
    /// Unlike [`Self::id`] which is globally unique for an RP, this is unique up to "user" (i.e.,
    /// multiple [`CredentialId`]s will often exist for the same `UserHandle`).
    user_id: UserHandle<&'user [u8]>,
    /// Immutable state returned during registration.
    static_state: StaticState<PublicKey>,
    /// State that can change during authentication ceremonies.
    dynamic_state: DynamicState,
}
impl<'cred, 'user, PublicKey> AuthenticatedCredential<'cred, 'user, PublicKey> {
    /// The credential ID.
    ///
    /// For client-side credentials, this is a unique identifier; but for server-side
    /// credentials, this _is_ the credential (i.e., the encrypted private key and necessary information).
    #[inline]
    #[must_use]
    pub const fn id(&self) -> CredentialId<&'cred [u8]> {
        self.id
    }
    /// The identifier for the user.
    ///
    /// Unlike [`Self::id`] which is globally unique for an RP, this is unique up to "user" (i.e.,
    /// multiple [`CredentialId`]s will often exist for the same `UserHandle`).
    #[inline]
    #[must_use]
    pub const fn user_id(&self) -> UserHandle<&'user [u8]> {
        self.user_id
    }
    /// Immutable state returned during registration.
    #[inline]
    #[must_use]
    pub const fn static_state(&self) -> &StaticState<PublicKey> {
        &self.static_state
    }
    /// State that can change during authentication ceremonies.
    #[inline]
    #[must_use]
    pub const fn dynamic_state(&self) -> DynamicState {
        self.dynamic_state
    }
    /// Constructs an `AuthenticatedCredential` based on the passed arguments.
    ///
    /// # Errors
    ///
    /// Errors iff the passed arguments are invalid. Read [`CredentialErr`]
    /// for more information.
    #[cfg_attr(docsrs, doc(cfg(any(feature = "bin", feature = "custom"))))]
    #[cfg(any(feature = "bin", feature = "custom"))]
    #[inline]
    pub fn new<'a: 'cred, 'b: 'user>(
        id: CredentialId<&'a [u8]>,
        user_id: UserHandle<&'b [u8]>,
        static_state: StaticState<PublicKey>,
        dynamic_state: DynamicState,
    ) -> Result<Self, CredentialErr> {
        verify_static_and_dynamic_state(&static_state, dynamic_state).map(|()| Self {
            id,
            user_id,
            static_state,
            dynamic_state,
        })
    }
    /// Returns the contained data consuming `self`.
    #[expect(
        clippy::type_complexity,
        reason = "type aliases with bounds are even more problematic at least until lazy_type_alias is stable"
    )]
    #[inline]
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CredentialId<&'cred [u8]>,
        UserHandle<&'user [u8]>,
        StaticState<PublicKey>,
        DynamicState,
    ) {
        (self.id, self.user_id, self.static_state, self.dynamic_state)
    }
    /// Returns the contained data.
    #[expect(
        clippy::type_complexity,
        reason = "type aliases with bounds are even more problematic at least until lazy_type_alias is stable"
    )]
    #[inline]
    #[must_use]
    pub const fn as_parts(
        &self,
    ) -> (
        CredentialId<&'cred [u8]>,
        UserHandle<&'user [u8]>,
        &StaticState<PublicKey>,
        DynamicState,
    ) {
        (
            self.id,
            self.user_id,
            self.static_state(),
            self.dynamic_state,
        )
    }
}
/// Convenience aggregate error that rolls up all errors into one.
#[derive(Debug)]
pub enum AggErr {
    /// Variant when [`AsciiDomain::try_from`] errors.
    AsciiDomain(AsciiDomainErr),
    /// Variant when [`Url::from_str`] errors.
    Url(UrlErr),
    /// Variant when [`Scheme::try_from`] errors.
    Scheme(SchemeParseErr),
    /// Variant when [`DomainOrigin::try_from`] errors.
    DomainOrigin(DomainOriginParseErr),
    /// Variant when [`Port::from_str`] errors.
    Port(PortParseErr),
    /// Variant when [`PublicKeyCredentialRequestOptions::start_ceremony`] errors.
    RequestOptions(RequestOptionsErr),
    /// Variant when [`PublicKeyCredentialRequestOptions::second_factor`] errors.
    SecondFactor(SecondFactorErr),
    /// Variant when [`PublicKeyCredentialCreationOptions::start_ceremony`] errors.
    CreationOptions(CreationOptionsErr),
    /// Variant when [`Nickname::try_from`] errors.
    Nickname(NicknameErr),
    /// Variant when [`UserHandle::rand`] or [`UserHandle::decode`] error.
    UserHandle(UserHandleErr),
    /// Variant when [`Username::try_from`] errors.
    Username(UsernameErr),
    /// Variant when [`RegistrationServerState::verify`] errors.
    RegCeremony(RegCeremonyErr),
    /// Variant when [`AuthenticationServerState::verify`] errors.
    AuthCeremony(AuthCeremonyErr),
    /// Variant when [`AttestationObject::try_from`] errors.
    AttestationObject(AttestationObjectErr),
    /// Variant when [`register::AuthenticatorData::try_from`] errors.
    RegAuthenticatorData(RegAuthDataErr),
    /// Variant when [`auth::AuthenticatorData::try_from`] errors.
    AuthAuthenticatorData(AuthAuthDataErr),
    /// Variant when [`CollectedClientData::from_client_data_json`] errors.
    CollectedClientData(CollectedClientDataErr),
    /// Variant when [`CollectedClientData::from_client_data_json_relaxed`] errors or any of the [`Deserialize`]
    /// implementations error when relying on [`Deserializer`] or [`StreamDeserializer`].
    #[cfg_attr(docsrs, doc(cfg(feature = "serde_relaxed")))]
    #[cfg(feature = "serde_relaxed")]
    SerdeJson(SerdeJsonErr),
    /// Variant when [`Aaguid::try_from`] errors.
    Aaguid(AaguidErr),
    /// Variant when [`AuthTransports::decode`] errors.
    #[cfg_attr(docsrs, doc(cfg(feature = "bin")))]
    #[cfg(feature = "bin")]
    DecodeAuthTransports(DecodeAuthTransportsErr),
    /// Variant when [`StaticState::decode`] errors.
    #[cfg_attr(docsrs, doc(cfg(feature = "bin")))]
    #[cfg(feature = "bin")]
    DecodeStaticState(DecodeStaticStateErr),
    /// Variant when [`DynamicState::decode`] errors.
    #[cfg_attr(docsrs, doc(cfg(feature = "bin")))]
    #[cfg(feature = "bin")]
    DecodeDynamicState(DecodeDynamicStateErr),
    /// Variant when [`Nickname::decode`] errors.
    #[cfg_attr(docsrs, doc(cfg(feature = "bin")))]
    #[cfg(feature = "bin")]
    DecodeNickname(DecodeNicknameErr),
    /// Variant when [`Username::decode`] errors.
    #[cfg_attr(docsrs, doc(cfg(feature = "bin")))]
    #[cfg(feature = "bin")]
    DecodeUsername(DecodeUsernameErr),
    /// Variant when [`RegistrationServerState::decode`] errors.
    #[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
    #[cfg(feature = "serializable_server_state")]
    DecodeRegistrationServerState(DecodeRegistrationServerStateErr),
    /// Variant when [`AuthenticationServerState::decode`] errors.
    #[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
    #[cfg(feature = "serializable_server_state")]
    DecodeAuthenticationServerState(DecodeAuthenticationServerStateErr),
    /// Variant when [`RegistrationServerState::encode`] errors.
    #[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
    #[cfg(feature = "serializable_server_state")]
    EncodeRegistrationServerState(SystemTimeError),
    /// Variant when [`AuthenticationServerState::encode`] errors.
    #[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
    #[cfg(feature = "serializable_server_state")]
    EncodeAuthenticationServerState(EncodeAuthenticationServerStateErr),
    /// Variant when [`AuthenticatedCredential::new`] errors.
    #[cfg_attr(docsrs, doc(cfg(any(feature = "bin", feature = "custom"))))]
    #[cfg(any(feature = "bin", feature = "custom"))]
    Credential(CredentialErr),
    /// Variant when [`CredentialId::try_from`] or [`CredentialId::decode`] errors.
    #[cfg_attr(docsrs, doc(cfg(any(feature = "bin", feature = "custom"))))]
    #[cfg(any(feature = "bin", feature = "custom"))]
    CredentialId(CredentialIdErr),
}
impl From<AsciiDomainErr> for AggErr {
    #[inline]
    fn from(value: AsciiDomainErr) -> Self {
        Self::AsciiDomain(value)
    }
}
impl From<UrlErr> for AggErr {
    #[inline]
    fn from(value: UrlErr) -> Self {
        Self::Url(value)
    }
}
impl From<SchemeParseErr> for AggErr {
    #[inline]
    fn from(value: SchemeParseErr) -> Self {
        Self::Scheme(value)
    }
}
impl From<DomainOriginParseErr> for AggErr {
    #[inline]
    fn from(value: DomainOriginParseErr) -> Self {
        Self::DomainOrigin(value)
    }
}
impl From<PortParseErr> for AggErr {
    #[inline]
    fn from(value: PortParseErr) -> Self {
        Self::Port(value)
    }
}
impl From<RequestOptionsErr> for AggErr {
    #[inline]
    fn from(value: RequestOptionsErr) -> Self {
        Self::RequestOptions(value)
    }
}
impl From<SecondFactorErr> for AggErr {
    #[inline]
    fn from(value: SecondFactorErr) -> Self {
        Self::SecondFactor(value)
    }
}
impl From<CreationOptionsErr> for AggErr {
    #[inline]
    fn from(value: CreationOptionsErr) -> Self {
        Self::CreationOptions(value)
    }
}
impl From<NicknameErr> for AggErr {
    #[inline]
    fn from(value: NicknameErr) -> Self {
        Self::Nickname(value)
    }
}
impl From<UserHandleErr> for AggErr {
    #[inline]
    fn from(value: UserHandleErr) -> Self {
        Self::UserHandle(value)
    }
}
impl From<UsernameErr> for AggErr {
    #[inline]
    fn from(value: UsernameErr) -> Self {
        Self::Username(value)
    }
}
impl From<RegCeremonyErr> for AggErr {
    #[inline]
    fn from(value: RegCeremonyErr) -> Self {
        Self::RegCeremony(value)
    }
}
impl From<AuthCeremonyErr> for AggErr {
    #[inline]
    fn from(value: AuthCeremonyErr) -> Self {
        Self::AuthCeremony(value)
    }
}
impl From<AttestationObjectErr> for AggErr {
    #[inline]
    fn from(value: AttestationObjectErr) -> Self {
        Self::AttestationObject(value)
    }
}
impl From<RegAuthDataErr> for AggErr {
    #[inline]
    fn from(value: RegAuthDataErr) -> Self {
        Self::RegAuthenticatorData(value)
    }
}
impl From<AuthAuthDataErr> for AggErr {
    #[inline]
    fn from(value: AuthAuthDataErr) -> Self {
        Self::AuthAuthenticatorData(value)
    }
}
impl From<CollectedClientDataErr> for AggErr {
    #[inline]
    fn from(value: CollectedClientDataErr) -> Self {
        Self::CollectedClientData(value)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "serde_relaxed")))]
#[cfg(feature = "serde_relaxed")]
impl From<SerdeJsonErr> for AggErr {
    #[inline]
    fn from(value: SerdeJsonErr) -> Self {
        Self::SerdeJson(value)
    }
}
impl From<AaguidErr> for AggErr {
    #[inline]
    fn from(value: AaguidErr) -> Self {
        Self::Aaguid(value)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "bin")))]
#[cfg(feature = "bin")]
impl From<DecodeAuthTransportsErr> for AggErr {
    #[inline]
    fn from(value: DecodeAuthTransportsErr) -> Self {
        Self::DecodeAuthTransports(value)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "bin")))]
#[cfg(feature = "bin")]
impl From<DecodeStaticStateErr> for AggErr {
    #[inline]
    fn from(value: DecodeStaticStateErr) -> Self {
        Self::DecodeStaticState(value)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "bin")))]
#[cfg(feature = "bin")]
impl From<DecodeDynamicStateErr> for AggErr {
    #[inline]
    fn from(value: DecodeDynamicStateErr) -> Self {
        Self::DecodeDynamicState(value)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "bin")))]
#[cfg(feature = "bin")]
impl From<DecodeNicknameErr> for AggErr {
    #[inline]
    fn from(value: DecodeNicknameErr) -> Self {
        Self::DecodeNickname(value)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "bin")))]
#[cfg(feature = "bin")]
impl From<DecodeUsernameErr> for AggErr {
    #[inline]
    fn from(value: DecodeUsernameErr) -> Self {
        Self::DecodeUsername(value)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
#[cfg(feature = "serializable_server_state")]
impl From<DecodeRegistrationServerStateErr> for AggErr {
    #[inline]
    fn from(value: DecodeRegistrationServerStateErr) -> Self {
        Self::DecodeRegistrationServerState(value)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
#[cfg(feature = "serializable_server_state")]
impl From<DecodeAuthenticationServerStateErr> for AggErr {
    #[inline]
    fn from(value: DecodeAuthenticationServerStateErr) -> Self {
        Self::DecodeAuthenticationServerState(value)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
#[cfg(feature = "serializable_server_state")]
impl From<SystemTimeError> for AggErr {
    #[inline]
    fn from(value: SystemTimeError) -> Self {
        Self::EncodeRegistrationServerState(value)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
#[cfg(feature = "serializable_server_state")]
impl From<EncodeAuthenticationServerStateErr> for AggErr {
    #[inline]
    fn from(value: EncodeAuthenticationServerStateErr) -> Self {
        Self::EncodeAuthenticationServerState(value)
    }
}
#[cfg_attr(docsrs, doc(cfg(any(feature = "bin", feature = "custom"))))]
#[cfg(any(feature = "bin", feature = "custom"))]
impl From<CredentialErr> for AggErr {
    #[inline]
    fn from(value: CredentialErr) -> Self {
        Self::Credential(value)
    }
}
#[cfg_attr(docsrs, doc(cfg(any(feature = "bin", feature = "custom"))))]
#[cfg(any(feature = "bin", feature = "custom"))]
impl From<CredentialIdErr> for AggErr {
    #[inline]
    fn from(value: CredentialIdErr) -> Self {
        Self::CredentialId(value)
    }
}
impl Display for AggErr {
    #[inline]
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match *self {
            Self::AsciiDomain(err) => err.fmt(f),
            Self::Url(err) => err.fmt(f),
            Self::Scheme(err) => err.fmt(f),
            Self::DomainOrigin(ref err) => err.fmt(f),
            Self::Port(ref err) => err.fmt(f),
            Self::RequestOptions(err) => err.fmt(f),
            Self::SecondFactor(err) => err.fmt(f),
            Self::CreationOptions(err) => err.fmt(f),
            Self::Nickname(err) => err.fmt(f),
            Self::UserHandle(err) => err.fmt(f),
            Self::Username(err) => err.fmt(f),
            Self::RegCeremony(ref err) => err.fmt(f),
            Self::AuthCeremony(ref err) => err.fmt(f),
            Self::AttestationObject(err) => err.fmt(f),
            Self::RegAuthenticatorData(err) => err.fmt(f),
            Self::AuthAuthenticatorData(err) => err.fmt(f),
            Self::CollectedClientData(ref err) => err.fmt(f),
            #[cfg(feature = "serde_relaxed")]
            Self::SerdeJson(ref err) => err.fmt(f),
            Self::Aaguid(err) => err.fmt(f),
            #[cfg(feature = "bin")]
            Self::DecodeAuthTransports(err) => err.fmt(f),
            #[cfg(feature = "bin")]
            Self::DecodeStaticState(err) => err.fmt(f),
            #[cfg(feature = "bin")]
            Self::DecodeDynamicState(err) => err.fmt(f),
            #[cfg(feature = "bin")]
            Self::DecodeNickname(err) => err.fmt(f),
            #[cfg(feature = "bin")]
            Self::DecodeUsername(err) => err.fmt(f),
            #[cfg(feature = "serializable_server_state")]
            Self::DecodeRegistrationServerState(err) => err.fmt(f),
            #[cfg(feature = "serializable_server_state")]
            Self::DecodeAuthenticationServerState(err) => err.fmt(f),
            #[cfg(feature = "serializable_server_state")]
            Self::EncodeRegistrationServerState(ref err) => err.fmt(f),
            #[cfg(feature = "serializable_server_state")]
            Self::EncodeAuthenticationServerState(ref err) => err.fmt(f),
            #[cfg(any(feature = "bin", feature = "custom"))]
            Self::Credential(err) => err.fmt(f),
            #[cfg(any(feature = "bin", feature = "custom"))]
            Self::CredentialId(err) => err.fmt(f),
        }
    }
}
impl Error for AggErr {}
/// Calculates the number of bytes needed to encode an input of length `n` bytes into base64url.
///
/// # Panics
///
/// `panic`s iff `n >= 0x4000`.
const fn base64url_nopad_len(n: usize) -> usize {
    // `usize::MAX >= u16::MAX`; thus we conservatively cap `n` to the largest value that would not overflow
    // from multiplying by 4 on all platforms.
    assert!(
        n < 0x4000,
        "webauthn_rp::base64url_nopad_len must be passed an integer smaller than 0x4000"
    );
    // 256^n is the number of distinct values of the input. Let the base64 encoding in a URL safe
    // way without padding of the input be O. There are 64 possible values each byte in O can be; thus we must find
    // the minimum nonnegative integer m such that:
    // 64^m = (2^6)^m = 2^(6m) >= 256^n = (2^8)^n = 2^(8n)
    // <==>
    // lg(2^(6m)) = 6m >= lg(2^(8n)) = 8n   lg is defined on all positive reals which 2^(6m) and 2^(8n) are
    // <==>
    // m >= 8n/6 = 4n/3
    // Clearly that corresponds to m = ⌈4n/3⌉; thus:
    (n << 2).div_ceil(3)
}
/// Calculates the number of bytes a base64url-encoded input of length `n` bytes will be decoded into.
///
/// `Some` is returned iff the value could be calculated without overflow; otherwise `None` is returned.
///
/// Note this does not verify if `n` is a possible value.
#[expect(
    clippy::unseparated_literal_suffix,
    reason = "noisy, opinionated, and likely doesn't prevent bugs or improve APIs"
)]
#[cfg(feature = "serde")]
fn base64url_nopad_decode_len(n: usize) -> Option<usize> {
    // 64^n is the number of distinct values of the input. Let the decoded output be O.
    // There are 256 possible values each byte in O can be; thus we must find
    // the maximum nonnegative integer m such that:
    // 256^m = (2^8)^m = 2^(8m) <= 64^n = (2^6)^n = 2^(6n)
    // <==>
    // lg(2^(8m)) = 8m <= lg(2^(6n)) = 6n   lg is defined on all positive reals which 2^(8m) and 2^(6n) are
    // <==>
    // m <= 6n/8 = 3n/4
    // Clearly that corresponds to m = ⌊3n/4⌋; thus:
    n.checked_mul(3).map(|len| len >> 2u8)
}
// We cache a `static` instance for performance reasons.
/// Encoder/decoder for base64url.
const BASE64URL_NOPAD_ENC: &Encoding = &BASE64URL_NOPAD;
