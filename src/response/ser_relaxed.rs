extern crate alloc;
#[cfg(test)]
mod tests;
#[cfg(doc)]
use super::{Challenge, LimitedVerificationParser};
use super::{
    ClientDataJsonParser, CollectedClientData, Origin, SentChallenge,
    ser::{
        AuthenticationExtensionsPrfValues, AuthenticationExtensionsPrfValuesVisitor,
        PRF_VALUES_FIELDS,
    },
};
use alloc::borrow::Cow;
use core::{
    fmt::{self, Formatter},
    marker::PhantomData,
};
use serde::de::{Deserialize, Deserializer, Error, IgnoredAny, MapAccess, Unexpected, Visitor};
#[cfg(doc)]
use serde_json::de;
/// Category returned by [`SerdeJsonErr::classify`].
pub use serde_json::error::Category;
/// Error returned by [`CollectedClientData::from_client_data_json_relaxed`] or any of the [`Deserialize`]
/// implementations when relying on [`de::Deserializer`] or [`de::StreamDeserializer`].
pub use serde_json::error::Error as SerdeJsonErr;
/// "Relaxed" [`ClientDataJsonParser`].
///
/// Unlike [`LimitedVerificationParser`] which requires
/// [JSON-compatible serialization of client data](https://www.w3.org/TR/webauthn-3/#collectedclientdata-json-compatible-serialization-of-client-data)
/// to be parsed _exactly_ as required by
/// the [limited verification algorithm](https://www.w3.org/TR/webauthn-3/#clientdatajson-verification),
/// this is a "relaxed" parser.
///
/// L1 clients predate the JSON-compatible serialization of client data; additionally there are L2 and L3 clients
/// that don't adhere to the JSON-compatible serialization of client data despite being required to. These clients
/// serialize `CollectedClientData` so that it's valid JSON and conforms to the Web IDL `dictionary` and nothing more.
/// Furthermore the spec requires that data be decoded in a way equivalent
/// to [UTF-8 decode](https://encoding.spec.whatwg.org/#utf-8-decode) which both interprets a leading zero
/// width no-breaking space (i.e., U+FEFF) as a byte-order mark (BOM) as well as replaces any sequences of invalid
/// UTF-8 code units with the replacement character (i.e., U+FFFD). That is precisely what this parser does.
///
/// In particular the parser errors iff any of the following is true:
///
/// * The payload is not valid JSON _after_ ignoring a leading U+FEFF and replacing any sequences of invalid
///   UTF-8 code units with U+FFFD.
/// * The JSON does not conform to the Web IDL `dictionary`.
/// * [`type`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-type) is not `"webauthn.create"`
///   or `"webauthn.get"` when `REGISTRATION` and `!REGISTRATION` respectively.
/// * [`challenge`](https://www.w3.org/TR/webauthn-3/#dom-collectedclientdata-challenge) is not a
///   base64url-encoded [`Challenge`].
/// * Existence of duplicate keys in the root object _including_ keys that otherwise would have been ignored.
pub(super) struct RelaxedClientDataJsonParser<const REGISTRATION: bool>;
impl<const R: bool> ClientDataJsonParser for RelaxedClientDataJsonParser<R> {
    type Err = SerdeJsonErr;
    fn parse(json: &[u8]) -> Result<CollectedClientData<'_>, Self::Err> {
        /// U+FEFF encoded in UTF-8.
        const BOM: [u8; 3] = [0xef, 0xbb, 0xbf];
        // We avoid first calling `String::from_utf8_lossy` since `CDataJsonHelper` relies on
        // [`Deserializer::deserialize_bytes`] instead of [`Deserializer::deserialize_str`] and
        // [`Deserializer::deserialize_identifier`]. Additionally [`CollectedClientData::origin`] and
        // [`CollectedClientData::top_origin`] are the only fields that need to actually replace invalid
        // UTF-8 code units, and this is achieved via the inner `OriginWrapper` type.
        serde_json::from_slice::<CDataJsonHelper<'_, R>>(json.split_at_checked(BOM.len()).map_or(
            json,
            |(bom, rem)| {
                if bom == BOM { rem } else { json }
            },
        ))
        .map(|val| val.0)
    }
    fn get_sent_challenge(json: &[u8]) -> Result<SentChallenge, Self::Err> {
        /// U+FEFF encoded in UTF-8.
        const BOM: [u8; 3] = [0xef, 0xbb, 0xbf];
        // We avoid first calling `String::from_utf8_lossy` since `Chall` relies on
        // [`Deserializer::deserialize_bytes`] instead of [`Deserializer::deserialize_identifier`].
        serde_json::from_slice::<Chall>(json.split_at_checked(BOM.len()).map_or(
            json,
            |(bom, rem)| {
                if bom == BOM { rem } else { json }
            },
        ))
        .map(|c| c.0)
    }
}
/// Used by [`RelaxedClientDataJsonParser::get_sent_challenge`] to minimally deserialize the JSON.
struct Chall(SentChallenge);
impl<'de> Deserialize<'de> for Chall {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        /// `Visitor` for `Chall`.
        struct ChallVisitor;
        impl<'d> Visitor<'d> for ChallVisitor {
            type Value = Chall;
            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str("Chall")
            }
            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'d>,
            {
                /// Fields in `clientDataJSON`.
                enum Field {
                    /// `"challenge"`.
                    Challenge,
                    /// All other fields.
                    Other,
                }
                impl<'e> Deserialize<'e> for Field {
                    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
                    where
                        D: Deserializer<'e>,
                    {
                        /// `Visitor` for `Field`.
                        struct FieldVisitor;
                        impl Visitor<'_> for FieldVisitor {
                            type Value = Field;
                            fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                                write!(formatter, "'{CHALLENGE}'")
                            }
                            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                            where
                                E: Error,
                            {
                                if v == b"challenge" {
                                    Ok(Field::Challenge)
                                } else {
                                    Ok(Field::Other)
                                }
                            }
                        }
                        deserializer.deserialize_bytes(FieldVisitor)
                    }
                }
                let mut chall = None;
                while let Some(key) = map.next_key()? {
                    match key {
                        Field::Challenge => {
                            if chall.is_some() {
                                return Err(Error::duplicate_field(CHALLENGE));
                            }
                            chall = map.next_value().map(Some)?;
                        }
                        Field::Other => map.next_value::<IgnoredAny>().map(|_| ())?,
                    }
                }
                chall
                    .ok_or_else(|| Error::missing_field(CHALLENGE))
                    .map(Chall)
            }
        }
        /// Fields we care about.
        const FIELDS: &[&str; 1] = &[CHALLENGE];
        deserializer.deserialize_struct("Chall", FIELDS, ChallVisitor)
    }
}
/// "type".
const TYPE: &str = "type";
/// "challenge".
const CHALLENGE: &str = "challenge";
/// "origin".
const ORIGIN: &str = "origin";
/// "crossOrigin".
const CROSS_ORIGIN: &str = "crossOrigin";
/// "topOrigin".
const TOP_ORIGIN: &str = "topOrigin";
/// Fields for `CollectedClientData`.
const FIELDS: &[&str; 5] = &[TYPE, CHALLENGE, ORIGIN, CROSS_ORIGIN, TOP_ORIGIN];
/// Helper for [`RelaxedClientDataJsonParser`].
struct RelaxedHelper<'a, const REGISTRATION: bool>(PhantomData<fn() -> &'a ()>);
impl<'de: 'a, 'a, const R: bool> Visitor<'de> for RelaxedHelper<'a, R> {
    type Value = CollectedClientData<'a>;
    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("CollectedClientData")
    }
    #[expect(
        clippy::too_many_lines,
        reason = "don't want to move code to an outer scope"
    )]
    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        /// "webauthn.create".
        const CREATE: &str = "webauthn.create";
        /// "webauthn.get".
        const GET: &str = "webauthn.get";
        /// `CollectedClientData` fields.
        enum Field {
            /// "type" field.
            Type,
            /// "challenge" field.
            Challenge,
            /// "origin" field.
            Origin,
            /// "crossOrigin" field.
            CrossOrigin,
            /// "topOrigin" field.
            TopOrigin,
            /// Unknown field.
            Other,
        }
        impl<'d> Deserialize<'d> for Field {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'d>,
            {
                /// `Visitor` for `Field`.
                struct FieldVisitor;
                impl Visitor<'_> for FieldVisitor {
                    type Value = Field;
                    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                        write!(
                            formatter,
                            "'{TYPE}', '{CHALLENGE}', '{ORIGIN}', '{CROSS_ORIGIN}', or '{TOP_ORIGIN}'"
                        )
                    }
                    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        match v {
                            b"type" => Ok(Field::Type),
                            b"challenge" => Ok(Field::Challenge),
                            b"origin" => Ok(Field::Origin),
                            b"crossOrigin" => Ok(Field::CrossOrigin),
                            b"topOrigin" => Ok(Field::TopOrigin),
                            _ => Ok(Field::Other),
                        }
                    }
                }
                // MUST NOT call `Deserializer::deserialize_identifier` since that will call
                // `FieldVisitor::visit_str` which obviously requires decoding the field as UTF-8 first.
                deserializer.deserialize_bytes(FieldVisitor)
            }
        }
        /// Deserializes the type value.
        /// Contains `true` iff the type is `"webauthn.create"`; otherwise the
        /// value is `"webauthn.get"`.
        struct Type(bool);
        impl<'d> Deserialize<'d> for Type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'d>,
            {
                /// `Visitor` for `Type`.
                struct TypeVisitor;
                impl Visitor<'_> for TypeVisitor {
                    type Value = Type;
                    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                        write!(formatter, "'{CREATE}' or '{GET}'")
                    }
                    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        match v {
                            b"webauthn.create" => Ok(Type(true)),
                            b"webauthn.get" => Ok(Type(false)),
                            _ => Err(Error::invalid_value(
                                Unexpected::Bytes(v),
                                &format!("'{CREATE}' or '{GET}'").as_str(),
                            )),
                        }
                    }
                }
                deserializer.deserialize_bytes(TypeVisitor)
            }
        }
        /// `newtype` around `Origin` that implements [`Deserialize`] such that invalid UTF-8 code units are first
        /// replaced with the replacement character. We don't do this for `Origin` since we want its public API
        /// to forbid invalid UTF-8.
        struct OriginWrapper<'d>(Origin<'d>);
        impl<'d: 'e, 'e> Deserialize<'d> for OriginWrapper<'e> {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'d>,
            {
                /// `Visitor` for `OriginWrapper`.
                struct OriginWrapperVisitor<'f>(PhantomData<fn() -> &'f ()>);
                impl<'f: 'g, 'g> Visitor<'f> for OriginWrapperVisitor<'g> {
                    type Value = OriginWrapper<'g>;
                    fn expecting(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                        formatter.write_str("OriginWrapper")
                    }
                    fn visit_borrowed_bytes<E>(self, v: &'f [u8]) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        Ok(OriginWrapper(Origin(String::from_utf8_lossy(v))))
                    }
                    fn visit_byte_buf<E>(self, v: Vec<u8>) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        Ok(OriginWrapper(Origin(Cow::Owned(
                            String::from_utf8_lossy(v.as_slice()).into_owned(),
                        ))))
                    }
                    fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                    where
                        E: Error,
                    {
                        self.visit_byte_buf(v.to_owned())
                    }
                }
                deserializer.deserialize_bytes(OriginWrapperVisitor(PhantomData))
            }
        }
        let mut typ = false;
        let mut chall = None;
        let mut orig = None;
        let mut cross = None;
        let mut top_orig = None;
        while let Some(key) = map.next_key()? {
            match key {
                Field::Type => {
                    if typ {
                        return Err(Error::duplicate_field(TYPE));
                    }
                    typ = map.next_value::<Type>().and_then(|v| {
                        if v.0 {
                            if R {
                                Ok(true)
                            } else {
                                Err(Error::invalid_value(Unexpected::Str(CREATE), &GET))
                            }
                        } else if R {
                            Err(Error::invalid_value(Unexpected::Str(GET), &CREATE))
                        } else {
                            Ok(true)
                        }
                    })?;
                }
                Field::Challenge => {
                    if chall.is_some() {
                        return Err(Error::duplicate_field(CHALLENGE));
                    }
                    chall = map.next_value().map(Some)?;
                }
                Field::Origin => {
                    if orig.is_some() {
                        return Err(Error::duplicate_field(ORIGIN));
                    }
                    orig = map.next_value::<OriginWrapper<'_>>().map(|o| Some(o.0))?;
                }
                Field::CrossOrigin => {
                    if cross.is_some() {
                        return Err(Error::duplicate_field(CROSS_ORIGIN));
                    }
                    cross = map.next_value().map(Some)?;
                }
                Field::TopOrigin => {
                    if top_orig.is_some() {
                        return Err(Error::duplicate_field(TOP_ORIGIN));
                    }
                    top_orig = map.next_value::<Option<OriginWrapper<'_>>>().map(Some)?;
                }
                // `IgnoredAny` ignores invalid UTF-8 in and only in JSON strings.
                Field::Other => map.next_value::<IgnoredAny>().map(|_| ())?,
            }
        }
        if typ {
            chall
                .ok_or_else(|| Error::missing_field(CHALLENGE))
                .and_then(|challenge| {
                    orig.ok_or_else(|| Error::missing_field(ORIGIN))
                        .map(|origin| CollectedClientData {
                            challenge,
                            origin,
                            cross_origin: cross.flatten().unwrap_or_default(),
                            top_origin: top_orig.flatten().map(|o| o.0),
                        })
                })
        } else {
            Err(Error::missing_field(TYPE))
        }
    }
}
/// `newtype` around [`CollectedClientData`] to avoid implementing [`Deserialize`] for `CollectedClientData`.
struct CDataJsonHelper<'a, const REGISTRATION: bool>(CollectedClientData<'a>);
impl<'de: 'a, 'a, const R: bool> Deserialize<'de> for CDataJsonHelper<'a, R> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_struct(
                "CollectedClientData",
                FIELDS,
                RelaxedHelper::<R>(PhantomData),
            )
            .map(Self)
    }
}
/// `newtype` around `AuthenticationExtensionsPrfValues` with a "relaxed" [`Self::deserialize`] implementation.
pub(super) struct AuthenticationExtensionsPrfValuesRelaxed(pub AuthenticationExtensionsPrfValues);
impl<'de> Deserialize<'de> for AuthenticationExtensionsPrfValuesRelaxed {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer
            .deserialize_struct(
                "AuthenticationExtensionsPrfValuesRelaxed",
                PRF_VALUES_FIELDS,
                AuthenticationExtensionsPrfValuesVisitor::<true>,
            )
            .map(Self)
    }
}
