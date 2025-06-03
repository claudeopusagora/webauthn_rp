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
//! ## `webauthn_rp` in action
//!
//! ```no_run
//! use core::convert;
//! use webauthn_rp::{
//!     AuthenticatedCredential64, DiscoverableAuthentication64, DiscoverableAuthenticationServerState,
//!     DiscoverableCredentialRequestOptions, CredentialCreationOptions64, RegisteredCredential64,
//!     Registration, RegistrationServerState64,
//!     hash::hash_set::FixedCapHashSet,
//!     request::{
//!         AsciiDomain, PublicKeyCredentialDescriptor, RpId,
//!         auth::AuthenticationVerificationOptions,
//!         register::{
//!             Nickname, PublicKeyCredentialUserEntity64, RegistrationVerificationOptions,
//!             UserHandle64, Username,
//!         },
//!     },
//!     response::{
//!         CredentialId,
//!         auth::error::AuthCeremonyErr,
//!         register::{CompressedPubKey, DynamicState, error::RegCeremonyErr},
//!     },
//! };
//! # #[cfg(feature = "serde")]
//! use serde::de::{Deserialize, Deserializer};
//! # #[cfg(feature = "serde_relaxed")]
//! use serde_json::Error as JsonErr;
//! /// The RP ID our application uses.
//! const RP_ID: &str = "example.com";
//! /// Error we return in our application when a function fails.
//! enum AppErr {
//!     /// WebAuthn registration ceremony failed.
//!     RegCeremony(RegCeremonyErr),
//!     /// WebAuthn authentication ceremony failed.
//!     AuthCeremony(AuthCeremonyErr),
//!     /// Unable to insert a WebAuthn ceremony.
//!     WebAuthnCeremonyCreation,
//!     /// WebAuthn ceremony does not exist; thus the ceremony could not be completed.
//!     MissingWebAuthnCeremony,
//!     /// General error related to JSON deserialization.
//!     # #[cfg(feature = "serde_relaxed")]
//!     Json(JsonErr),
//!     /// No account exists associated with a particular `UserHandle64`.
//!     NoAccount,
//!     /// No credential exists associated with a particular `CredentialId`.
//!     NoCredential,
//!     /// `CredentialId` exists but the associated `UserHandle64` does not match.
//!     CredentialUserIdMismatch,
//! }
//! # #[cfg(feature = "serde_relaxed")]
//! impl From<JsonErr> for AppErr {
//!     fn from(value: JsonErr) -> Self {
//!         Self::Json(value)
//!     }
//! }
//! impl From<RegCeremonyErr> for AppErr {
//!     fn from(value: RegCeremonyErr) -> Self {
//!         Self::RegCeremony(value)
//!     }
//! }
//! impl From<AuthCeremonyErr> for AppErr {
//!     fn from(value: AuthCeremonyErr) -> Self {
//!         Self::AuthCeremony(value)
//!     }
//! }
//! /// First-time account creation.
//! ///
//! /// This gets sent from the user after an account is created on their side. The registration ceremony
//! /// still has to be successfully completed for the account to be created server side. In the event of an error,
//! /// the user should delete the created passkey since it won't be usable.
//! struct AccountReg<'a, 'b> {
//!     registration: Registration,
//!     user_name: Username<'a>,
//!     user_display_name: Nickname<'b>,
//! }
//! # #[cfg(feature = "serde")]
//! impl<'de: 'a + 'b, 'a, 'b> Deserialize<'de> for AccountReg<'a, 'b> {
//!     fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
//!     where
//!         D: Deserializer<'de>,
//!     {
//!         // ⋮
//!         # panic!("");
//!     }
//! }
//! /// Starts account creation.
//! ///
//! /// This only makes sense for greenfield deployments since account information (e.g., user name) would likely
//! /// already exist otherwise. This is similar to credential creation except a random `UserHandle64` is generated and
//! /// will be used for subsequent credential registrations.
//! # #[cfg(feature = "serde_relaxed")]
//! fn start_account_creation(
//!     reg_ceremonies: &mut FixedCapHashSet<RegistrationServerState64>,
//! ) -> Result<Vec<u8>, AppErr> {
//!     let rp_id = RpId::Domain(
//!         AsciiDomain::try_from(RP_ID.to_owned())
//!             .unwrap_or_else(|_e| unreachable!("example.com is a valid domain")),
//!     );
//!     let user_id = UserHandle64::new();
//!     let (server, client) =
//!         CredentialCreationOptions64::first_passkey_with_blank_user_info(
//!             &rp_id, &user_id,
//!         )
//!         .start_ceremony()
//!         .unwrap_or_else(|_e| {
//!             unreachable!("we don't manually mutate the options and we assume the server clock is functioning; thus this won't error")
//!         });
//!     if reg_ceremonies.insert_remove_all_expired(server).is_some_and(convert::identity)
//!     {
//!         Ok(serde_json::to_vec(&client)
//!             .unwrap_or_else(|_e| unreachable!("bug in RegistrationClientState64::serialize")))
//!     } else {
//!         Err(AppErr::WebAuthnCeremonyCreation)
//!     }
//! }
//! /// Finishes account creation.
//! ///
//! /// Pending a successful registration ceremony, a new account associated with the randomly generated
//! /// `UserHandle64` will be created with a corresponding passkey entry. This passkey will be used to
//! /// log into the application.
//! ///
//! /// Note if this errors, then the user should be notified to delete the passkey created on their
//! /// authenticator.
//! # #[cfg(feature = "serde_relaxed")]
//! fn finish_account_creation(
//!     reg_ceremonies: &mut FixedCapHashSet<RegistrationServerState64>,
//!     client_data: Vec<u8>,
//! ) -> Result<(), AppErr> {
//!     let account = serde_json::from_slice::<AccountReg<'_, '_>>(client_data.as_slice())?;
//!     insert_account(
//!         &account,
//!         reg_ceremonies
//!             // `Registration::challenge_relaxed` is available iff `serde_relaxed` is enabled.
//!             .take(&account.registration.challenge_relaxed()?)
//!             .ok_or(AppErr::MissingWebAuthnCeremony)?
//!             .verify(
//!                 &RpId::Domain(
//!                     AsciiDomain::try_from(RP_ID.to_owned())
//!                         .unwrap_or_else(|_e| unreachable!("example.com is a valid domain")),
//!                 ),
//!                 &account.registration,
//!                 &RegistrationVerificationOptions::<&str, &str>::default(),
//!             )?,
//!     )
//! }
//! /// Starts passkey registration.
//! ///
//! /// This is used for _existing_ accounts where the user is already logged in and wants to register another
//! /// passkey. This is similar to account creation except we already have the user entity info and we need to
//! /// fetch the registered `PublicKeyCredentialDescriptor`s to avoid accidentally overwriting a passkey on
//! /// the authenticator.
//! # #[cfg(feature = "serde_relaxed")]
//! fn start_cred_registration(
//!     user_id: &UserHandle64,
//!     reg_ceremonies: &mut FixedCapHashSet<RegistrationServerState64>,
//! ) -> Result<Vec<u8>, AppErr> {
//!     let rp_id = RpId::Domain(
//!         AsciiDomain::try_from(RP_ID.to_owned())
//!             .unwrap_or_else(|_e| unreachable!("example.com is a valid domain")),
//!     );
//!     let (entity, creds) = select_user_info(user_id)?.ok_or_else(|| AppErr::NoAccount)?;
//!     let (server, client) = CredentialCreationOptions64::passkey(&rp_id, entity, creds)
//!         .start_ceremony()
//!         .unwrap_or_else(|_e| {
//!             unreachable!("we don't manually mutate the options and we assume the server clock is functioning; thus this won't error")
//!         });
//!     if reg_ceremonies.insert_remove_all_expired(server).is_some_and(convert::identity)
//!     {
//!         Ok(serde_json::to_vec(&client)
//!             .unwrap_or_else(|_e| unreachable!("bug in RegistrationClientState64::serialize")))
//!     } else {
//!         Err(AppErr::WebAuthnCeremonyCreation)
//!     }
//! }
//! /// Finishes passkey registration.
//! ///
//! /// Pending a successful registration ceremony, a new credential associated with the `UserHandle64`
//! /// will be created. This passkey can then be used to log into the application just like any other registered
//! /// passkey.
//! ///
//! /// Note if this errors, then the user should be notified to delete the passkey created on their
//! /// authenticator.
//! # #[cfg(feature = "serde_relaxed")]
//! fn finish_cred_registration(
//!     reg_ceremonies: &mut FixedCapHashSet<RegistrationServerState64>,
//!     client_data: Vec<u8>,
//! ) -> Result<(), AppErr> {
//!     // `Registration::from_json_custom` is available iff `serde_relaxed` is enabled.
//!     let registration = Registration::from_json_custom(client_data.as_slice())?;
//!     insert_credential(
//!         reg_ceremonies
//!             // `Registration::challenge_relaxed` is available iff `serde_relaxed` is enabled.
//!             .take(&registration.challenge_relaxed()?)
//!             .ok_or(AppErr::MissingWebAuthnCeremony)?
//!             .verify(
//!                 &RpId::Domain(
//!                     AsciiDomain::try_from(RP_ID.to_owned())
//!                         .unwrap_or_else(|_e| unreachable!("example.com is a valid domain")),
//!                 ),
//!                 &registration,
//!                 &RegistrationVerificationOptions::<&str, &str>::default(),
//!             )?,
//!     )
//! }
//! /// Starts the passkey authentication ceremony.
//! # #[cfg(feature = "serde_relaxed")]
//! fn start_auth(
//!     auth_ceremonies: &mut FixedCapHashSet<DiscoverableAuthenticationServerState>,
//! ) -> Result<Vec<u8>, AppErr> {
//!     let rp_id = RpId::Domain(
//!         AsciiDomain::try_from(RP_ID.to_owned())
//!             .unwrap_or_else(|_e| unreachable!("example.com is a valid domain")),
//!     );
//!     let (server, client) = DiscoverableCredentialRequestOptions::passkey(&rp_id)
//!         .start_ceremony()
//!         .unwrap_or_else(|_e| {
//!             unreachable!("we don't manually mutate the options and we assume the server clock is functioning; thus this won't error")
//!         });
//!     if auth_ceremonies.insert_remove_all_expired(server).is_some_and(convert::identity)
//!     {
//!         Ok(serde_json::to_vec(&client).unwrap_or_else(|_e| {
//!             unreachable!("bug in DiscoverableAuthenticationClientState::serialize")
//!         }))
//!     } else {
//!         Err(AppErr::WebAuthnCeremonyCreation)
//!     }
//! }
//! /// Finishes the passkey authentication ceremony.
//! # #[cfg(feature = "serde_relaxed")]
//! fn finish_auth(
//!     auth_ceremonies: &mut FixedCapHashSet<DiscoverableAuthenticationServerState>,
//!     client_data: Vec<u8>,
//! ) -> Result<(), AppErr> {
//!     // `DiscoverableAuthentication64::from_json_custom` is available iff `serde_relaxed` is enabled.
//!     let authentication =
//!         DiscoverableAuthentication64::from_json_custom(client_data.as_slice())?;
//!     let mut cred = select_credential(
//!         authentication.raw_id(),
//!         authentication.response().user_handle(),
//!     )?
//!     .ok_or_else(|| AppErr::NoCredential)?;
//!     if auth_ceremonies
//!         // `DiscoverableAuthentication64::challenge_relaxed` is available iff `serde_relaxed` is enabled.
//!         .take(&authentication.challenge_relaxed()?)
//!         .ok_or(AppErr::MissingWebAuthnCeremony)?
//!         .verify(
//!             &RpId::Domain(
//!                 AsciiDomain::try_from(RP_ID.to_owned())
//!                     .unwrap_or_else(|_e| unreachable!("example.com is a valid domain")),
//!             ),
//!             &authentication,
//!             &mut cred,
//!             &AuthenticationVerificationOptions::<&str, &str>::default(),
//!         )?
//!     {
//!         update_credential(cred.id(), cred.dynamic_state())
//!     } else {
//!         Ok(())
//!     }
//! }
//! /// Writes `account` and `cred` to storage.
//! ///
//! /// # Errors
//! ///
//! /// Errors iff writing `account` or `cred` errors,  there already exists a credential using the same
//! /// `CredentialId`, or there already exists an account using the same `UserHandle64`.
//! fn insert_account(
//!     account: &AccountReg<'_, '_>,
//!     cred: RegisteredCredential64<'_>,
//! ) -> Result<(), AppErr> {
//!     // ⋮
//!     # Ok(())
//! }
//! /// Fetches the user info and registered credentials associated with `user_id`.
//! ///
//! /// # Errors
//! ///
//! /// Errors iff fetching the data errors.
//! fn select_user_info<'a>(
//!     user_id: &'a UserHandle64,
//! ) -> Result<
//!     Option<(
//!         PublicKeyCredentialUserEntity64<'static, 'static, 'a>,
//!         Vec<PublicKeyCredentialDescriptor<Vec<u8>>>,
//!     )>,
//!     AppErr,
//! > {
//!     // ⋮
//!     # Ok(None)
//! }
//! /// Writes `cred` to storage.
//! ///
//! /// # Errors
//! ///
//! /// Errors iff writing `cred` errors, there already exists a credential using the same `CredentialId`,
//! /// or there does not exist an account under the `UserHandle64`.
//! fn insert_credential(
//!     cred: RegisteredCredential64<'_>,
//! ) -> Result<(), AppErr> {
//!     // ⋮
//!     # Ok(())
//! }
//! /// Fetches the `AuthenticatedCredential` associated with `cred_id` ensuring `user_id` matches the
//! /// `UserHandle64` associated with the account.
//! ///
//! /// # Errors
//! ///
//! /// Errors iff fetching the data errors or the `user_id` does not match the stored `UserHandle64`.
//! fn select_credential<'cred, 'user>(
//!     cred_id: CredentialId<&'cred [u8]>,
//!     user_id: &'user UserHandle64,
//! ) -> Result<
//!     Option<
//!         AuthenticatedCredential64<
//!             'cred,
//!             'user,
//!             CompressedPubKey<[u8; 32], [u8; 32], [u8; 48], Vec<u8>>,
//!         >,
//!     >,
//!     AppErr,
//! > {
//!     // ⋮
//!     # Ok(None)
//! }
//! /// Overwrites the current `DynamicState` associated with `cred_id` with `dynamic_state`.
//! ///
//! /// # Errors
//! ///
//! /// Errors iff writing errors or `cred_id` does not exist.
//! fn update_credential(
//!     cred_id: CredentialId<&[u8]>,
//!     dynamic_state: DynamicState,
//! ) -> Result<(), AppErr> {
//!     // ⋮
//!     # Ok(())
//! }
//! ```
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
//! This feature _strictly_ adheres to the JSON-motivated definitions. You _will_ encounter clients that send data
//! that cannot be deserialized using this feature. For many [`serde_relaxed`](#serde_relaxed) should be used
//! instead.
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
//! [`RegistrationServerState`], [`DiscoverableAuthenticationServerState`], and
//! [`NonDiscoverableAuthenticationServerState`]. Less accurate [`SystemTime`] is used instead of [`Instant`] for
//! timeout enforcement. This should be enabled if you don't desire to use in-memory collections to store the instances
//! of those types.
//!
//! Note even when written to persistent storage, an application should still periodically remove expired ceremonies.
//! If one is using a relational database (RDB); then one can achieve this by storing [`SentChallenge`],
//! the `Vec` returned from [`Encode::encode`], and [`TimedCeremony::expiration`] and periodically remove all rows
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
//! `RegistrationServerState` instances are as small as 48 bytes on `x86_64-unknown-linux-gnu` platforms. To avoid
//! issues related to incomplete ceremonies, RPs can periodically iterate the collection for expired ceremonies and
//! remove such data. Other techniques can be employed as well to mitigate OOM, but they are application specific
//! and out-of-scope. If this is undesirable, one can enable [`serializable_server_state`](#serializable_server_state)
//! so that `RegistrationServerState`, [`DiscoverableAuthenticationServerState`], and
//! [`NonDiscoverableAuthenticationServerState`] implement [`Encode`] and [`Decode`]. Another reason one may need to
//! store this information persistently is for load-balancing purposes where the server that started the ceremony is
//! not guaranteed to be the server that finishes the ceremony.
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
#[cfg(not(any(feature = "custom", all(feature = "bin", feature = "serde"))))]
compile_error!("'custom' must be enabled or both 'bin' and 'serde' must be enabled");
#[cfg(feature = "serializable_server_state")]
use crate::request::{
    auth::ser_server_state::{
        DecodeDiscoverableAuthenticationServerStateErr,
        DecodeNonDiscoverableAuthenticationServerStateErr,
        EncodeNonDiscoverableAuthenticationServerStateErr,
    },
    register::ser_server_state::DecodeRegistrationServerStateErr,
};
#[cfg(any(feature = "bin", feature = "custom"))]
use crate::response::error::CredentialIdErr;
#[cfg(feature = "serde_relaxed")]
use crate::response::ser_relaxed::SerdeJsonErr;
#[cfg(doc)]
use crate::{
    hash::hash_set::FixedCapHashSet,
    request::{
        AsciiDomain, DomainOrigin, Port, PublicKeyCredentialDescriptor, RpId, Scheme,
        TimedCeremony, Url,
        auth::{AllowedCredential, AllowedCredentials, PublicKeyCredentialRequestOptions},
        register::{
            CoseAlgorithmIdentifier, Nickname, PublicKeyCredentialCreationOptions,
            PublicKeyCredentialUserEntity, UserHandle16, UserHandle64, Username,
        },
    },
    response::{
        CollectedClientData, Flag, SentChallenge,
        auth::{self, Authentication, DiscoverableAuthenticatorAssertion},
        register::{
            self, Aaguid, Attestation, AttestationObject, AttestedCredentialData,
            AuthenticatorExtensionOutput, ClientExtensionsOutputs, CompressedPubKey,
            CredentialPropertiesOutput,
        },
    },
};
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
            ResidentKeyRequirement, USER_HANDLE_MAX_LEN, UserHandle,
            error::{CreationOptionsErr, NicknameErr, UsernameErr},
        },
    },
    response::{
        AuthTransports, CredentialId,
        auth::error::{AuthCeremonyErr, AuthenticatorDataErr as AuthAuthDataErr},
        error::CollectedClientDataErr,
        register::{
            CredentialProtectionPolicy, DynamicState, Metadata, StaticState, UncompressedPubKey,
            error::{
                AaguidErr, AttestationObjectErr, AuthenticatorDataErr as RegAuthDataErr,
                RegCeremonyErr,
            },
        },
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
    ops::Not,
};
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
/// Contains functionality for fixed-capacity hash maps and sets.
pub mod hash;
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
///   [`CredentialCreationOptions::second_factor`].
/// * [`Label 13`](#label13) is ideal for passkey setups as it allows for pleasant UX where a user does not have to type a
///   username nor password while still being secured with MFA with one of the factors being based on public-key
///   cryptography which for many is the most secure form of single-factor authentication. The easiest way to register
///   such a credential is with [`CredentialCreationOptions::passkey`].
///
/// Two other reasons one may prefer to construct client-side credentials is richer support for extensions (e.g.,
/// [`largeBlobKey`](https://fidoalliance.org/specs/fido-v2.2-rd-20230321/fido-client-to-authenticator-protocol-v2.2-rd-20230321.html#sctn-largeBlobKey-extension)
/// for CTAP 2.2 authenticators) and the ability to use both discoverable and nondiscoverable requests. The former is not
/// relevant for this library—at least currently—since the only extensions supported are applicable for both
/// client-side and server-side credentials. The latter can be important especially if an RP wants the ability to
/// seamlessly transition from a username and password scheme to a userless and passwordless one in the future.
///
/// Note the table is purely informative. While helper functions
/// (e.g., [`CredentialCreationOptions::passkey`]) only exist for [`Label 4`](#label4) and
/// [`Label 13`](#label13), one can create any credential since all fields in [`CredentialCreationOptions`]
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
            DiscoverableAuthenticationClientState, DiscoverableAuthenticationServerState,
            DiscoverableCredentialRequestOptions, NonDiscoverableAuthenticationClientState,
            NonDiscoverableAuthenticationServerState, NonDiscoverableCredentialRequestOptions,
        },
        register::{
            CredentialCreationOptions, CredentialCreationOptions16, CredentialCreationOptions64,
            RegistrationClientState, RegistrationClientState16, RegistrationClientState64,
            RegistrationServerState, RegistrationServerState16, RegistrationServerState64,
        },
    },
    response::{
        auth::{
            DiscoverableAuthentication, DiscoverableAuthentication16, DiscoverableAuthentication64,
            NonDiscoverableAuthentication, NonDiscoverableAuthentication16,
            NonDiscoverableAuthentication64,
        },
        register::Registration,
    },
};
/// Error returned in [`RegCeremonyErr::Credential`] and [`AuthenticatedCredential::new`].
#[derive(Clone, Copy, Debug)]
pub enum CredentialErr {
    /// Variant when [`CredentialProtectionPolicy::UserVerificationRequired`], but
    /// [`DynamicState::user_verified`] is `false`.
    CredProtectUserVerificationRequiredWithoutUserVerified,
    /// Variant when [`ClientExtensionsOutputs::prf`] is
    /// `Some(AuthenticationExtensionsPRFOutputs { enabled: true })` and
    /// [`DynamicState::user_verified`] is `false`.
    PrfWithoutUserVerified,
    /// Variant when [`AuthenticatorExtensionOutput::hmac_secret`] is `Some(true)`, but
    /// [`ClientExtensionsOutputs::prf`] is `Some(AuthenticationExtensionsPRFOutputs { enabled: false })`
    /// or `AuthenticatorExtensionOutput::hmac_secret` is `Some`, but
    /// `ClientExtensionsOutputs::prf` is `None`.
    HmacSecretWithoutPrf,
    /// Variant when [`ClientExtensionsOutputs::prf`] is
    /// `Some(AuthenticationExtensionsPRFOutputs { enabled: true })`, but
    /// [`AuthenticatorExtensionOutput::hmac_secret`] is `Some(false)`.
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
            Self::PrfWithoutUserVerified => "prf is enabled, but the user is not verified",
            Self::HmacSecretWithoutPrf => "hmac-secret was enabled but prf was not",
            Self::PrfWithoutHmacSecret => "prf was enabled, but hmac-secret was not",
            Self::ResidentKeyRequiredServerCredentialCreated => {
                "server-side credential was created, but a client-side credential is required"
            }
        })
    }
}
impl Error for CredentialErr {}
/// Checks if the `static_state` and `dynamic_state` are valid.
///
/// # Errors
///
/// Errors iff `static_state` or `dynamc_state` are invalid.
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
    } else if static_state
        .client_extension_results
        .prf
        .is_some_and(|prf| prf.enabled)
    {
        Err(CredentialErr::PrfWithoutUserVerified)
    } else {
        Ok(())
    }
    .and_then(|()| {
        static_state.client_extension_results.prf.map_or_else(
            || {
                if static_state.extensions.hmac_secret.is_none() {
                    Ok(())
                } else {
                    Err(CredentialErr::HmacSecretWithoutPrf)
                }
            },
            |prf| {
                if prf.enabled {
                    if static_state.extensions.hmac_secret.is_some_and(Not::not) {
                        Err(CredentialErr::PrfWithoutHmacSecret)
                    } else {
                        Ok(())
                    }
                } else if static_state
                    .extensions
                    .hmac_secret
                    .is_some_and(convert::identity)
                {
                    Err(CredentialErr::HmacSecretWithoutPrf)
                } else {
                    Ok(())
                }
            },
        )
    })
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
///       authentication ceremony via [`DiscoverableAuthenticationServerState::verify`] or
///       [`NonDiscoverableAuthenticationServerState::verify`] will likely be easier than alternatives.
/// * [`AuthTransports`]
///     * Fetching [`CredentialId`]s and associated `AuthTransports` by [`UserHandle`] will likely make credential
///       registration easier since one should set [`PublicKeyCredentialCreationOptions::exclude_credentials`] to
///       the [`PublicKeyCredentialDescriptor`]s belonging to a `UserHandle` in order to avoid accidentally
///       overwriting an existing credential on the authenticator.
///     * Fetching `CredentialId`s and associated `AuthTransports` by `UserHandle` will likely make starting
///       authentication ceremonies easier for [`NonDiscoverableCredentialRequestOptions`].
/// * [`UserHandle`]
///     * Fetching the [`AuthenticatedCredential`] by [`DiscoverableAuthentication::raw_id`] must also coincide with
///       verifying the associated `UserHandle` matches [`DiscoverableAuthenticatorAssertion::user_handle`].
///     * Fetching [`CredentialId`]s and associated [`AuthTransports`] by `UserHandle` will likely make credential
///       registration easier since one should set [`PublicKeyCredentialCreationOptions::exclude_credentials`] to
///       the [`PublicKeyCredentialDescriptor`]s belonging to a `UserHandle` in order to avoid accidentally
///       overwriting an existing credential on the authenticator.
///     * Fetching `CredentialId`s and associated `AuthTransports` by `UserHandle` will likely make starting
///       authentication ceremonies easier for [`NonDiscoverableCredentialRequestOptions`].
/// * [`DynamicState`]
///     * `DynamicState` is the only part that is ever updated after a successful authentication ceremony
///       via [`DiscoverableAuthenticationServerState::verify`] or
///       [`NonDiscoverableAuthenticationServerState::verify`]. It being separate allows for smaller and quicker
///       updates.
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
/// [`Self::id`], and [`StaticState::credential_public_key`] respectively. The [`PublicKeyCredentialUserEntity::id`]
/// associated with the [`CredentialCreationOptions`] used to create the `RegisteredCredential` via
/// [`RegistrationServerState::verify`] will be the source for [`Self::user_id`].
///
/// The only way to create this is via `RegistrationServerState::verify`.
#[derive(Debug)]
pub struct RegisteredCredential<'reg, const USER_LEN: usize> {
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
    user_id: UserHandle<USER_LEN>,
    /// Immutable state returned during registration.
    static_state: StaticState<UncompressedPubKey<'reg>>,
    /// State that can change during authentication ceremonies.
    dynamic_state: DynamicState,
    /// Metadata.
    metadata: Metadata<'reg>,
}
impl<'reg, const USER_LEN: usize> RegisteredCredential<'reg, USER_LEN> {
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
    pub const fn user_id(&self) -> &UserHandle<USER_LEN> {
        &self.user_id
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
    fn new<'a: 'reg>(
        id: CredentialId<&'a [u8]>,
        transports: AuthTransports,
        user_id: UserHandle<USER_LEN>,
        static_state: StaticState<UncompressedPubKey<'a>>,
        dynamic_state: DynamicState,
        metadata: Metadata<'a>,
    ) -> Result<Self, CredentialErr> {
        verify_static_and_dynamic_state(&static_state, dynamic_state).and_then(|()| {
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
    }
    /// Returns the contained data consuming `self`.
    #[inline]
    #[must_use]
    pub const fn into_parts(
        self,
    ) -> (
        CredentialId<&'reg [u8]>,
        AuthTransports,
        UserHandle<USER_LEN>,
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
    #[inline]
    #[must_use]
    pub const fn as_parts(
        &self,
    ) -> (
        CredentialId<&'reg [u8]>,
        AuthTransports,
        &UserHandle<USER_LEN>,
        StaticState<UncompressedPubKey<'reg>>,
        DynamicState,
        Metadata<'reg>,
    ) {
        (
            self.id,
            self.transports,
            &self.user_id,
            self.static_state,
            self.dynamic_state,
            self.metadata,
        )
    }
}
/// `RegisteredCredential` based on a [`UserHandle64`].
pub type RegisteredCredential64<'reg> = RegisteredCredential<'reg, USER_HANDLE_MAX_LEN>;
/// `RegisteredCredential` based on a [`UserHandle16`].
pub type RegisteredCredential16<'reg> = RegisteredCredential<'reg, 16>;
/// Credential used in authentication ceremonies.
///
/// Similar to [`RegisteredCredential`] except designed to only contain the necessary data to complete
/// authentication ceremonies. In particular there is no [`AuthTransports`] or [`Metadata`],
/// [`StaticState::credential_public_key`] is [`CompressedPubKey`] that can own or borrow its data, [`Self::id`] is
/// based on the [`CredentialId`] passed to [`Self::new`] which itself must be from [`Authentication::raw_id`], and
/// [`Self::user_id`] is based on the [`UserHandle`] passed to [`Self::new`] which itself must be the value in
/// persistent storage associated with the `CredentialId`.
///
/// When [`DiscoverableAuthentication`] is used, one can use [`DiscoverableAuthenticatorAssertion::user_handle`]
/// for `Self::user_id` so long as it matches the value in persistent storage.
///
/// Note `PublicKey` should be `CompressedPubKey` for this to be useful.
///
/// The only way to create this is via `Self::new`.
#[derive(Debug)]
pub struct AuthenticatedCredential<'cred, 'user, const USER_LEN: usize, PublicKey> {
    /// The credential ID.
    ///
    /// For client-side credentials, this is a unique identifier; but for server-side
    /// credentials, this _is_ the credential (i.e., the encrypted private key and necessary information).
    id: CredentialId<&'cred [u8]>,
    /// The identifier for the user.
    ///
    /// Unlike [`Self::id`] which is globally unique for an RP, this is unique up to "user" (i.e.,
    /// multiple [`CredentialId`]s will often exist for the same `UserHandle`).
    user_id: &'user UserHandle<USER_LEN>,
    /// Immutable state returned during registration.
    static_state: StaticState<PublicKey>,
    /// State that can change during authentication ceremonies.
    dynamic_state: DynamicState,
}
impl<'cred, 'user, const USER_LEN: usize, PublicKey>
    AuthenticatedCredential<'cred, 'user, USER_LEN, PublicKey>
{
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
    pub const fn user_id(&self) -> &'user UserHandle<USER_LEN> {
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
        user_id: &'user UserHandle<USER_LEN>,
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
    #[inline]
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        CredentialId<&'cred [u8]>,
        &'user UserHandle<USER_LEN>,
        StaticState<PublicKey>,
        DynamicState,
    ) {
        (self.id, self.user_id, self.static_state, self.dynamic_state)
    }
    /// Returns the contained data.
    #[inline]
    #[must_use]
    pub const fn as_parts(
        &self,
    ) -> (
        CredentialId<&'cred [u8]>,
        &'user UserHandle<USER_LEN>,
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
/// `AuthenticatedCredential` based on a [`UserHandle64`].
pub type AuthenticatedCredential64<'cred, 'user, PublicKey> =
    AuthenticatedCredential<'cred, 'user, USER_HANDLE_MAX_LEN, PublicKey>;
/// `AuthenticatedCredential` based on a [`UserHandle16`].
pub type AuthenticatedCredential16<'cred, 'user, PublicKey> =
    AuthenticatedCredential<'cred, 'user, 16, PublicKey>;
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
    /// Variant when [`DiscoverableCredentialRequestOptions::start_ceremony`] or
    /// [`NonDiscoverableCredentialRequestOptions::start_ceremony`]
    /// error.
    RequestOptions(RequestOptionsErr),
    /// Variant when [`NonDiscoverableCredentialRequestOptions::second_factor`] errors.
    SecondFactor(SecondFactorErr),
    /// Variant when [`CredentialCreationOptions::start_ceremony`] errors.
    CreationOptions(CreationOptionsErr),
    /// Variant when [`Nickname::try_from`] errors.
    Nickname(NicknameErr),
    /// Variant when [`Username::try_from`] errors.
    Username(UsernameErr),
    /// Variant when [`RegistrationServerState::verify`] errors.
    RegCeremony(RegCeremonyErr),
    /// Variant when [`DiscoverableAuthenticationServerState::verify`] or.
    /// [`NonDiscoverableAuthenticationServerState::verify`] error.
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
    /// Variant when [`DiscoverableAuthenticationServerState::decode`] errors.
    #[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
    #[cfg(feature = "serializable_server_state")]
    DecodeDiscoverableAuthenticationServerState(DecodeDiscoverableAuthenticationServerStateErr),
    /// Variant when [`NonDiscoverableAuthenticationServerState::decode`] errors.
    #[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
    #[cfg(feature = "serializable_server_state")]
    DecodeNonDiscoverableAuthenticationServerState(
        DecodeNonDiscoverableAuthenticationServerStateErr,
    ),
    /// Variant when [`RegistrationServerState::encode`] errors.
    #[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
    #[cfg(feature = "serializable_server_state")]
    EncodeRegistrationServerState(SystemTimeError),
    /// Variant when [`DiscoverableAuthenticationServerState::encode`] errors.
    #[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
    #[cfg(feature = "serializable_server_state")]
    EncodeDiscoverableAuthenticationServerState(SystemTimeError),
    /// Variant when [`NonDiscoverableAuthenticationServerState::encode`] errors.
    #[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
    #[cfg(feature = "serializable_server_state")]
    EncodeNonDiscoverableAuthenticationServerState(
        EncodeNonDiscoverableAuthenticationServerStateErr,
    ),
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
impl From<DecodeDiscoverableAuthenticationServerStateErr> for AggErr {
    #[inline]
    fn from(value: DecodeDiscoverableAuthenticationServerStateErr) -> Self {
        Self::DecodeDiscoverableAuthenticationServerState(value)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
#[cfg(feature = "serializable_server_state")]
impl From<DecodeNonDiscoverableAuthenticationServerStateErr> for AggErr {
    #[inline]
    fn from(value: DecodeNonDiscoverableAuthenticationServerStateErr) -> Self {
        Self::DecodeNonDiscoverableAuthenticationServerState(value)
    }
}
#[cfg_attr(docsrs, doc(cfg(feature = "serializable_server_state")))]
#[cfg(feature = "serializable_server_state")]
impl From<EncodeNonDiscoverableAuthenticationServerStateErr> for AggErr {
    #[inline]
    fn from(value: EncodeNonDiscoverableAuthenticationServerStateErr) -> Self {
        Self::EncodeNonDiscoverableAuthenticationServerState(value)
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
            Self::DecodeDiscoverableAuthenticationServerState(err) => err.fmt(f),
            #[cfg(feature = "serializable_server_state")]
            Self::DecodeNonDiscoverableAuthenticationServerState(err) => err.fmt(f),
            #[cfg(feature = "serializable_server_state")]
            Self::EncodeRegistrationServerState(ref err) => err.fmt(f),
            #[cfg(feature = "serializable_server_state")]
            Self::EncodeDiscoverableAuthenticationServerState(ref err) => err.fmt(f),
            #[cfg(feature = "serializable_server_state")]
            Self::EncodeNonDiscoverableAuthenticationServerState(ref err) => err.fmt(f),
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
/// `Some` is returned iff the encoded length does not exceed [`isize::MAX`].
#[expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::integer_division,
    clippy::integer_division_remainder_used,
    reason = "proof and comment justifies their correctness"
)]
const fn base64url_nopad_len(n: usize) -> Option<usize> {
    // 256^n is the number of distinct values of the input. Let the base64 encoding in a URL safe
    // way without padding of the input be O. There are 64 possible values each byte in O can be; thus we must find
    // the minimum nonnegative integer m such that:
    // 64^m = (2^6)^m = 2^(6m) >= 256^n = (2^8)^n = 2^(8n)
    // <==>
    // lg(2^(6m)) = 6m >= lg(2^(8n)) = 8n   lg is defined on all positive reals which 2^(6m) and 2^(8n) are
    // <==>
    // m >= 8n/6 = 4n/3
    // Clearly that corresponds to m = ⌈4n/3⌉; thus:

    let (quot, rem) = (n / 3, n % 3);
    // Actual construction of the encoded output requires the allocation to take no more than `isize::MAX`
    // bytes; thus we must detect overflow of it and not `usize::MAX`.
    // isize::MAX = usize::MAX / 2 >= usize::MAX / 3; thus this `as` conversion is lossless.
    match (quot as isize).checked_mul(4) {
        // If multiplying by 4 caused overflow, then multiplying by 4 and adding by 3 would also.
        None => None,
        // This won't overflow since this maxes at `isize::MAX` since
        // `n` <= ⌊3*isize::MAX/4⌋; thus `quot` <= ⌊isize::MAX/4⌋.
        // `n` can be partitioned into 4 possibilities:
        // (1) n ≡ 0 (mod 4) = 4quot + 0
        // (2) n ≡ 1 (mod 4) = 4quot + 1
        // (3) n ≡ 2 (mod 4) = 4quot + 2
        // (4) n ≡ 3 (mod 4) = 4quot + 3
        // For (1), rem is 0; thus 4quot + 0 = `n` which is fine.
        // For (2), rem is 1; thus 4quot + 2 = n - 1 + 2 = n + 1 <= ⌊3*isize::MAX/4⌋ + 1 <= isize::MAX for
        // isize::MAX > 0. Clearly `isize::MAX > 0`; otherwise we couldn't allocate anything.
        // For (3), rem is 2; thus 4quot + 3 = n - 2 + 3 = n + 1 <= ⌊3*isize::MAX/4⌋ + 1 <= isize::MAX for
        // isize::MAX > 0. Clearly `isize::MAX > 0`; otherwise we couldn't allocate anything.
        // For (4), rem is 3; thus 4quot + 4 = n - 3 + 4 = n + 1 <= ⌊3*isize::MAX/4⌋ + 1 <= isize::MAX for
        // isize::MAX > 0. Clearly `isize::MAX > 0`; otherwise we couldn't allocate anything.
        //
        // `val >= 0`; thus we can cast it to `usize` via `as` in a lossless way.
        // Thus this is free from overflow, underflow, and a lossy conversion.
        Some(val) => Some(val as usize + (4 * rem).div_ceil(3)),
    }
}
/// Calculates the number of bytes a base64url-encoded input of length `n` bytes will be decoded into.
///
/// `Some` is returned iff `n` is a valid input length.
///
/// Note `n` must not only be a valid length mathematically but also represent a possible allocation of that
/// many bytes. Since only allocations <= [`isize::MAX`] are possible, this will always return `None` when
/// `n > isize::MAX`.
#[cfg(feature = "serde")]
#[expect(
    clippy::arithmetic_side_effects,
    clippy::as_conversions,
    clippy::integer_division_remainder_used,
    reason = "proof and comment justifies their correctness"
)]
const fn base64url_nopad_decode_len(n: usize) -> Option<usize> {
    // 64^n is the number of distinct values of the input. Let the decoded output be O.
    // There are 256 possible values each byte in O can be; thus we must find
    // the maximum nonnegative integer m such that:
    // 256^m = (2^8)^m = 2^(8m) <= 64^n = (2^6)^n = 2^(6n)
    // <==>
    // lg(2^(8m)) = 8m <= lg(2^(6n)) = 6n   lg is defined on all positive reals which 2^(8m) and 2^(6n) are
    // <==>
    // m <= 6n/8 = 3n/4
    // Clearly that corresponds to m = ⌊3n/4⌋.
    //
    // There are three partitions for m:
    // (1) m ≡ 0 (mod 3) = 3i
    // (2) m ≡ 1 (mod 3) = 3i + 1
    // (3) m ≡ 2 (mod 3) = 3i + 2
    //
    // From `crate::base64url_nopad_len`, we know that the encoded length, n, of an input of length m is n = ⌈4m/3⌉.
    // The encoded length of (1) is thus n = ⌈4(3i)/3⌉ = ⌈4i⌉ = 4i ≡ 0 (mod 4).
    // The encoded length of (2) is thus n = ⌈4(3i + 1)/3⌉ = ⌈4i + 4/3⌉ = 4i + 2 ≡ 2 (mod 4).
    // The encoded length of (3) is thus n = ⌈4(3i + 2)/3⌉ = ⌈4i + 8/3⌉ = 4i + 3 ≡ 3 (mod 4).
    //
    // Thus if n ≡ 1 (mod 4), it is never a valid length.
    //
    // Let n be the length of a possible encoded output of an input of length m.
    // We know from above that n ≢ 1 (mod 4), this leaves three possibilities:
    // (1) n ≡ 0 (mod 4) = 4i
    // (2) n ≡ 2 (mod 4) = 4i + 2
    // (3) n ≡ 3 (mod 4) = 4i + 3
    //
    // For (1) an input of length 3i is the inverse since ⌈4(3i)/3⌉ = 4i.
    // For (2) an input of length 3i + 1 is the inverse since ⌈4(3i + 1)/3⌉ = ⌈4i + 4/3⌉ = 4i + 2.
    // For (3) an input of length 3i + 2 is the inverse since ⌈4(3i + 2)/3⌉ = ⌈4i + 8/3⌉ = 4i + 3.
    //
    // Consequently n is a valid length of an encoded output iff n ≢ 1 (mod 4).

    // `isize::MAX >= 0 >= usize::MIN`; thus this conversion is lossless.
    if n % 4 == 1 || n > isize::MAX as usize {
        None
    } else {
        let (quot, rem) = (n >> 2u8, n % 4);
        // 4quot + rem = n
        // rem <= 3
        // 3rem <= 9
        // 3rem/4 <= 2
        // 3quot + 3rem/4 <= 4quot + rem
        // Thus no operation causes overflow or underflow.
        Some((3 * quot) + ((3 * rem) >> 2u8))
    }
}
