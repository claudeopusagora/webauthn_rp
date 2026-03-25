/// A [`u64`].
const UINT: u8 = 0b000_00000;
/// A negative integer whose value _m ∈ [-2^64 - 1, -1]_ is represented as _|m| - 1_.
const NEG: u8 = 0b001_00000;
/// A byte string.
pub(super) const BYTES: u8 = 0b010_00000;
/// A text string.
const TEXT: u8 = 0b011_00000;
/// A map of key-value pairs.
const MAP: u8 = 0b101_00000;
/// Simple values.
const SIMPLE: u8 = 0b111_00000;
/// [`UINT`] value `1`.
pub(super) const ONE: u8 = UINT | 1;
/// [`UINT`] value `2`.
pub(super) const TWO: u8 = UINT | 2;
/// [`UINT`] value `3`.
pub(super) const THREE: u8 = UINT | 3;
/// [`UINT`] value `6`.
pub(super) const SIX: u8 = UINT | 6;
/// [`UINT`] value `7`.
pub(super) const SEVEN: u8 = UINT | 7;
/// [`NEG`] value `-1`.
pub(super) const NEG_ONE: u8 = NEG;
/// [`NEG`] value `-2`.
pub(super) const NEG_TWO: u8 = NEG | 1;
/// [`NEG`] value `-3`.
pub(super) const NEG_THREE: u8 = NEG | 2;
/// [`NEG`] value `-7`.
pub(super) const NEG_SEVEN: u8 = NEG | 6;
/// [`NEG`] value `-8`.
pub(super) const NEG_EIGHT: u8 = NEG | 7;
/// [`NEG`] value less than `-24` but greater than `-257`.
pub(super) const NEG_INFO_24: u8 = NEG | 24;
/// [`NEG`] value less than `-256` but greater than `-65537`.
pub(super) const NEG_INFO_25: u8 = NEG | 25;
/// [`BYTES`] length greater than `23` but less than `256`.
pub(super) const BYTES_INFO_24: u8 = BYTES | 24;
/// [`BYTES`] length greater than `255` but less than `65536`.
pub(super) const BYTES_INFO_25: u8 = BYTES | 25;
/// [`TEXT`] length `3`.
pub(super) const TEXT_3: u8 = TEXT | 3;
/// [`TEXT`] length `4`.
pub(super) const TEXT_4: u8 = TEXT | 4;
/// [`TEXT`] length `6`.
pub(super) const TEXT_6: u8 = TEXT | 6;
/// [`TEXT`] length `7`.
pub(super) const TEXT_7: u8 = TEXT | 7;
/// [`TEXT`] length `8`.
pub(super) const TEXT_8: u8 = TEXT | 8;
/// [`TEXT`] length `11`.
pub(super) const TEXT_11: u8 = TEXT | 11;
/// [`TEXT`] length `12`.
pub(super) const TEXT_12: u8 = TEXT | 12;
/// [`TEXT`] length `14`.
pub(super) const TEXT_14: u8 = TEXT | 14;
/// [`MAP`] length `0`.
pub(super) const MAP_0: u8 = MAP;
/// [`MAP`] length `1`.
pub(super) const MAP_1: u8 = MAP | 1;
/// [`MAP`] length `2`.
pub(super) const MAP_2: u8 = MAP | 2;
/// [`MAP`] length `3`.
pub(super) const MAP_3: u8 = MAP | 3;
/// [`MAP`] length `4`.
pub(super) const MAP_4: u8 = MAP | 4;
/// [`MAP`] length `5`.
pub(super) const MAP_5: u8 = MAP | 5;
/// [`SIMPLE`] value `false`.
pub(super) const SIMPLE_FALSE: u8 = SIMPLE | 20;
/// [`SIMPLE`] value `true`.
pub(super) const SIMPLE_TRUE: u8 = SIMPLE | 21;
/// [`TEXT`] value hmac-secret.
pub(super) const HMAC_SECRET: [u8; 12] = [
    TEXT_11, b'h', b'm', b'a', b'c', b'-', b's', b'e', b'c', b'r', b'e', b't',
];
