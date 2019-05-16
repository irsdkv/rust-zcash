// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Bitcoin Transaction
//!
//! A transaction describes a transfer of money. It consumes previously-unspent
//! transaction outputs and produces new ones, satisfying the condition to spend
//! the old outputs (typically a digital signature with a specific key must be
//! provided) and defining the condition to spend the new ones. The use of digital
//! signatures ensures that coins cannot be spent by unauthorized parties.
//!
//! This module provides the structures and functions needed to support transactions.
//!

#[cfg(feature = "serde")] use serde;

#[cfg(feature = "serde")] extern crate rustc_serialize;

use byteorder::{LittleEndian, WriteBytesExt};
use std::default::Default;
use std::fmt;
use blake2_rfc::blake2b::{Blake2b, Blake2bResult};
#[cfg(feature="bitcoinconsensus")] use std::collections::HashMap;

use std::hash::{Hash, Hasher};
use util::hash::Sha256dHash;
#[cfg(feature="bitcoinconsensus")] use blockdata::script;
use blockdata::script::Script;
use network::serialize::{self, serialize, BitcoinHash, SimpleEncoder, SimpleDecoder};
use network::encodable::{ConsensusEncodable, ConsensusDecodable, VarInt};

static ZCASH_PREVOUTS_HASH_PERSONALIZATION: &[u8] = b"ZcashPrevoutHash";
static ZCASH_SEQUENCE_HASH_PERSONALIZATION: &[u8] = b"ZcashSequencHash";
static ZCASH_OUTPUTS_HASH_PERSONALIZATION: &[u8] = b"ZcashOutputsHash";
#[allow(dead_code)]
static ZCASH_JOINSPLITS_HASH_PERSONALIZATION: &[u8] = b"ZcashJSplitsHash";
static ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION: &[u8] = b"ZcashSSpendsHash";
static ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION: &[u8] = b"ZcashSOutputHash";
static ZCASH_TX_HASH_PERSONALIZATION: &[u8] = b"ZcashSigHash";

static ZCASH_SAPLING_CONSENSUS_BRANCH_ID: u32 = 1991772603; // 0x76b809bb; // 1991772603;


// Overwinter version group id
#[allow(dead_code)]
static OVERWINTER_VERSION_GROUP_ID: u32= 0x03C48270;

// Sapling version group id
#[allow(dead_code)]
static SAPLING_VERSION_GROUP_ID: u32 = 0x892F2085;

/// https://github.com/zcash/zips/blob/master/zip-0202.rst#version-group-id
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum BranchId {
    /// https://github.com/zcash/zcash/issues/3413
    Overwinter = 0x5ba81b19,
    /// https://github.com/zcash/zcash/issues/3413
    Sapling    = 0x76b809bb
}

/// A reference to a transaction output
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct OutPoint {
    /// The referenced transaction's txid
    pub txid: Sha256dHash,
    /// The index of the referenced output in its transaction's vout
    pub vout: u32,
}
serde_struct_impl!(OutPoint, txid, vout);

/// https://github.com/zcash/zips/blob/master/zip-0202.rst#header-field
#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash, FromPrimitive, ToPrimitive)]
pub enum TxHeader {
    /// Empty
    Empty	              = 0x00000000,
    /// v2
    Second 	              = 0x00000002,
    /// v3
    Third                 = 0x00000003,
    /// v3 and Overwintered flag
    ThirdAndOverwintered  = 0x80000003,
    /// v4 and Overwintered flag
    FourthAndOverwintered = 0x80000004,
}

#[cfg(feature = "serde")]
impl serde::Serialize for TxHeader {
    /// User-facing serialization for `Script`.
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let val = match self {
            TxHeader::Empty	                => 0x00000000u32,
            TxHeader::Second 	            => 0x00000002u32,
            TxHeader::Third                 => 0x00000003u32,
            TxHeader::ThirdAndOverwintered  => 0x80000003u32,
            TxHeader::FourthAndOverwintered => 0x80000004u32,
        };
        serializer.serialize_str(&format!("{:x}", val as u32))
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for TxHeader {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::fmt::{self, Formatter};

        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = TxHeader;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("a header")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let v: u32 = v.parse::<u32>().unwrap();
                match v {
                    0x00000000u32 => Ok(TxHeader::Empty),
                    0x00000002u32 => Ok(TxHeader::Second),
                    0x00000003u32 => Ok(TxHeader::Third),
                    0x80000003u32 => Ok(TxHeader::ThirdAndOverwintered),
                    0x80000004u32 => Ok(TxHeader::FourthAndOverwintered),
                    _ => Err(serde::de::Error::custom("Bad header value"))
                }
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}
impl<S: SimpleEncoder> ConsensusEncodable<S> for TxHeader {
    fn consensus_encode(&self, s: &mut S) -> Result <(), serialize::Error> {
        s.emit_u32(*self as u32)
    }
}
impl<D: SimpleDecoder> ConsensusDecodable<D> for TxHeader {
    fn consensus_decode(d: &mut D) -> Result<TxHeader, serialize::Error> {
        Ok(match d.read_u32()? {
            0x00000000u32 => TxHeader::Empty,
            0x00000002u32 => TxHeader::Second,
            0x00000003u32 => TxHeader::Third,
            0x80000003u32 => TxHeader::ThirdAndOverwintered,
            0x80000004u32 => TxHeader::FourthAndOverwintered,
            _ => panic!("Header bad value")
        })
    }
}
impl OutPoint {
    /// Creates a "null" `OutPoint`.
    ///
    /// This value is used for coinbase transactions because they don't have
    /// any previous outputs.
    #[inline]
    pub fn null() -> OutPoint {
        OutPoint {
            txid: Default::default(),
            vout: u32::max_value(),
        }
    }

    /// Checks if an `OutPoint` is "null".
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::blockdata::constants::genesis_block;
    /// use bitcoin::network::constants::Network;
    ///
    /// let block = genesis_block(Network::Bitcoin);
    /// let tx = &block.txdata[0];
    ///
    /// // Coinbase transactions don't have any previous output.
    /// assert_eq!(tx.input[0].previous_output.is_null(), true);
    /// ```
    #[inline]
    pub fn is_null(&self) -> bool {
        *self == OutPoint::null()
    }
}

impl Default for OutPoint {
    fn default() -> Self {
        OutPoint::null()
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

/// A transaction input, which defines old coins to be consumed
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct TxIn {
    /// The reference to the previous output that is being used an an input
    pub previous_output: OutPoint,
    /// The script which pushes values on the stack which will cause
    /// the referenced output's script to accept
    pub script_sig: Script,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behaviour cannot be enforced.
    pub sequence: u32,
    /// Witness data: an array of byte-arrays.
    /// Note that this field is *not* (de)serialized with the rest of the TxIn in
    /// ConsensusEncodable/ConsennsusDecodable, as it is (de)serialized at the end of the full
    /// Transaction. It *is* (de)serialized with the rest of the TxIn in other (de)serializationn
    /// routines.
    pub witness: Vec<Vec<u8>>
}
serde_struct_impl!(TxIn, previous_output, script_sig, sequence, witness);

/// A transaction output, which defines new coins to be created from old ones.
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct TxOut {
    /// The value of the output, in satoshis
    pub value: u64,
    /// The script which must satisfy for the output to be spent
    pub script_pubkey: Script
}
serde_struct_impl!(TxOut, value, script_pubkey);

// This is used as a "null txout" in consensus signing code
impl Default for TxOut {
    fn default() -> TxOut {
        TxOut { value: 0xffffffffffffffff, script_pubkey: Script::new() }
    }
}

/// Spend Description
#[derive(Clone)]
pub struct SpendDescription {
    /// Description
    pub shielded_spend_stub: [u8; 384],
}

#[cfg(feature = "serde")]
impl serde::Serialize for SpendDescription {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        use self::rustc_serialize::hex::ToHex;
        let mut state = serializer.serialize_struct("SpendDescription", 1)?;
        state.serialize_field("shielded_spend_stub", &self.shielded_spend_stub.to_vec().to_hex())?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for SpendDescription {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::fmt::{self, Formatter};

        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = SpendDescription;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("struct SpendDescription")
            }
            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let v: Vec<u8> = ::hex::decode(v).map_err(E::custom)?;
                let mut shielded_spend_stub = [0; 384];
                let _bytes = &v[..shielded_spend_stub.len()]; // panics if not enough data
                shielded_spend_stub.copy_from_slice(&v);
                Ok(SpendDescription {shielded_spend_stub})
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for SpendDescription {
    fn consensus_encode(&self, s: &mut S) -> Result <(), serialize::Error> {
        for u in self.shielded_spend_stub.iter() {
            s.emit_u8(*u)?;
        }
        Ok(())
    }
}
impl<D: SimpleDecoder> ConsensusDecodable<D> for SpendDescription {
    fn consensus_decode(d: &mut D) -> Result<SpendDescription, serialize::Error> {
        let mut shielded_spend_stub: [u8; 384] = [0; 384];
        for i in 0..384 {
            shielded_spend_stub[i] = d.read_u8()?;
        }
        Ok(SpendDescription {shielded_spend_stub})
    }
}

impl Hash for SpendDescription {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.shielded_spend_stub.hash(state);
    }
}

impl fmt::Debug for SpendDescription {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.shielded_spend_stub[..].fmt(formatter)
    }
}

impl Eq for SpendDescription {}

impl PartialEq for SpendDescription {
    fn eq(&self, other: &SpendDescription) -> bool {
        self.shielded_spend_stub.iter().zip(other.shielded_spend_stub.iter()).all(|(a,b)| a == b)
    }
}

/// Output Description
#[derive(Clone)]
pub struct OutputDescription {
    /// Description
    pub shielded_output_stub: [u8; 948]
}

#[cfg(feature = "serde")]
impl serde::Serialize for OutputDescription {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        use blockdata::transaction::rustc_serialize::hex::ToHex;
        let mut state = serializer.serialize_struct("OutputDescription", 1)?;
        state.serialize_field("shielded_output_stub", &self.shielded_output_stub.to_hex())?;
        state.end()
    }
}
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for OutputDescription {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::fmt::{self, Formatter};

        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = OutputDescription;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("struct OutputDescription")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let v: Vec<u8> = ::hex::decode(v).map_err(E::custom)?;
                let mut shielded_output_stub = [0; 948];
                let _bytes = &v[..shielded_output_stub.len()]; // panics if not enough data
                shielded_output_stub.copy_from_slice(&v);
                Ok(OutputDescription {shielded_output_stub})
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for OutputDescription {
    fn consensus_encode(&self, s: &mut S) -> Result <(), serialize::Error> {
        for u in self.shielded_output_stub.iter() {
            s.emit_u8(*u)?;
        }
        Ok(())
    }
}
impl<D: SimpleDecoder> ConsensusDecodable<D> for OutputDescription {
    fn consensus_decode(d: &mut D) -> Result<OutputDescription, serialize::Error> {
        let mut shielded_output_stub: [u8; 948] = [0; 948];
        for i in 0..948 {
            shielded_output_stub[i] = d.read_u8()?;
        }
        Ok(OutputDescription {shielded_output_stub})
    }
}

impl Hash for OutputDescription {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.shielded_output_stub.hash(state);
    }
}

impl fmt::Debug for OutputDescription {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.shielded_output_stub[..].fmt(formatter)
    }
}

impl Eq for OutputDescription {}

impl PartialEq for OutputDescription {
    fn eq(&self, other: &OutputDescription) -> bool {
        self.shielded_output_stub.iter().zip(other.shielded_output_stub.iter()).all(|(a,b)| a == b)
    }
}

/// JSDescriptionPHGR13
#[derive(Clone)]
pub struct JSDescriptionPHGR13 {
    /// Description
    pub join_split_stub: [u8; 1698]
}
#[cfg(feature = "serde")]
impl serde::Serialize for JSDescriptionPHGR13 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        use self::rustc_serialize::hex::ToHex;
        let mut state = serializer.serialize_struct("JSDescriptionPHGR13", 1)?;
        state.serialize_field("join_split_stub", &self.join_split_stub.to_hex())?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for JSDescriptionPHGR13 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::fmt::{self, Formatter};

        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = JSDescriptionPHGR13;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("struct JSDescriptionPHGR13")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let v: Vec<u8> = ::hex::decode(v).map_err(E::custom)?;
                let mut join_split_stub = [0; 1698];
                let _bytes = &v[..join_split_stub.len()]; // panics if not enough data
                join_split_stub.copy_from_slice(&v);
                Ok(JSDescriptionPHGR13 {join_split_stub})
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for JSDescriptionPHGR13 {
    fn consensus_encode(&self, s: &mut S) -> Result <(), serialize::Error> {
        for u in self.join_split_stub.iter() {
            s.emit_u8(*u)?;
        }
        Ok(())
    }
}
impl<D: SimpleDecoder> ConsensusDecodable<D> for JSDescriptionPHGR13 {
    fn consensus_decode(d: &mut D) -> Result<JSDescriptionPHGR13, serialize::Error> {
        let mut join_split_stub: [u8; 1698] = [0; 1698];
        for i in 0..1698 {
            join_split_stub[i] = d.read_u8()?;
        }
        Ok(JSDescriptionPHGR13 {join_split_stub})
    }
}

impl Hash for JSDescriptionPHGR13 {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.join_split_stub.hash(state);
    }
}

impl fmt::Debug for JSDescriptionPHGR13 {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.join_split_stub[..].fmt(formatter)
    }
}

impl Eq for JSDescriptionPHGR13 {}

impl PartialEq for JSDescriptionPHGR13 {
    fn eq(&self, other: &JSDescriptionPHGR13) -> bool {
        self.join_split_stub.iter().zip(other.join_split_stub.iter()).all(|(a,b)| a == b)
    }
}

#[derive(Clone)]
/// JoinSplitPubKey
pub struct JoinSplitPubKey {
    /// Key
    val: [u8; 32]
}
#[cfg(feature = "serde")]
impl serde::Serialize for JoinSplitPubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        use self::rustc_serialize::hex::ToHex;
        let mut state = serializer.serialize_struct("JoinSplitPubKey", 1)?;
        state.serialize_field("val", &self.val.to_hex())?;
        state.end()
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for JoinSplitPubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::fmt::{self, Formatter};

        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = JoinSplitPubKey;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("struct JoinSplitPubKey")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let v: Vec<u8> = ::hex::decode(v).map_err(E::custom)?;
                let mut val = [0; 32];
                let _bytes = &v[..val.len()]; // panics if not enough data
                val.copy_from_slice(&v);
                Ok(JoinSplitPubKey {val})
            }
            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for JoinSplitPubKey {
    fn consensus_encode(&self, s: &mut S) -> Result <(), serialize::Error> {
        for u in self.val.iter() {
            s.emit_u8(*u)?;
        }
        Ok(())
    }
}
impl<D: SimpleDecoder> ConsensusDecodable<D> for JoinSplitPubKey {
    fn consensus_decode(d: &mut D) -> Result<JoinSplitPubKey, serialize::Error> {
        let mut val: [u8; 32] = [0; 32];
        for i in 0..32 {
            val[i] = d.read_u8()?;
        }
        Ok(JoinSplitPubKey {val})
    }
}
impl Hash for JoinSplitPubKey {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.val.hash(state);
    }
}
impl fmt::Debug for JoinSplitPubKey {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.val[..].fmt(formatter)
    }
}
impl Eq for JoinSplitPubKey {}
impl PartialEq for JoinSplitPubKey {
    fn eq(&self, other: &JoinSplitPubKey) -> bool {
        self.val.iter().zip(other.val.iter()).all(|(a,b)| a == b)
    }
}

#[derive(Clone)]
/// JoinSplitSig
pub struct JoinSplitSig {
    /// Sig
    val: [u8; 64]
}

#[cfg(feature = "serde")]
impl serde::Serialize for JoinSplitSig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        use self::rustc_serialize::hex::ToHex;
        let mut state = serializer.serialize_struct("JoinSplitSig", 1)?;
        state.serialize_field("val", &self.val.to_hex())?;
        state.end()
    }
}
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for JoinSplitSig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::fmt::{self, Formatter};

        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = JoinSplitSig;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("struct JoinSplitSig")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let v: Vec<u8> = ::hex::decode(v).map_err(E::custom)?;
                let mut val = [0; 64];
                let _bytes = &v[..val.len()]; // panics if not enough data
                val.copy_from_slice(&v);
                Ok(JoinSplitSig {val})
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}
impl<S: SimpleEncoder> ConsensusEncodable<S> for JoinSplitSig {
    fn consensus_encode(&self, s: &mut S) -> Result <(), serialize::Error> {
        for u in self.val.iter() {
            s.emit_u8(*u)?;
        }
        Ok(())
    }
}
impl<D: SimpleDecoder> ConsensusDecodable<D> for JoinSplitSig {
    fn consensus_decode(d: &mut D) -> Result<JoinSplitSig, serialize::Error> {
        let mut val: [u8; 64] = [0; 64];
        for i in 0..64 {
            val[i] = d.read_u8()?;
        }
        Ok(JoinSplitSig {val})
    }
}
impl Hash for JoinSplitSig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.val.hash(state);
    }
}
impl fmt::Debug for JoinSplitSig {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.val[..].fmt(formatter)
    }
}
impl Eq for JoinSplitSig {}
impl PartialEq for JoinSplitSig {
    fn eq(&self, other: &JoinSplitSig) -> bool {
        self.val.iter().zip(other.val.iter()).all(|(a,b)| a == b)
    }
}

#[derive(Clone)]
/// JoinSplitPubKey
pub struct BindingSig {
    /// Sig
    val: [u8; 64]
}

#[cfg(feature = "serde")]
impl serde::Serialize for BindingSig {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeStruct;
        use self::rustc_serialize::hex::ToHex;
        let mut state = serializer.serialize_struct("BindingSig", 1)?;
        state.serialize_field("val", &self.val.to_hex())?;
        state.end()
    }
}
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for BindingSig {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use std::fmt::{self, Formatter};

        struct Visitor;
        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = BindingSig;

            fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
                formatter.write_str("struct BindingSig")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let v: Vec<u8> = ::hex::decode(v).map_err(E::custom)?;
                let mut val = [0; 64];
                let _bytes = &v[..val.len()]; // panics if not enough data
                val.copy_from_slice(&v);
                Ok(BindingSig {val})
            }

            fn visit_borrowed_str<E>(self, v: &'de str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(v)
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_str(&v)
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}
impl<S: SimpleEncoder> ConsensusEncodable<S> for BindingSig {
    fn consensus_encode(&self, s: &mut S) -> Result <(), serialize::Error> {
        for u in self.val.iter() {
            s.emit_u8(*u)?;
        }
        Ok(())
    }
}
impl<D: SimpleDecoder> ConsensusDecodable<D> for BindingSig {
    fn consensus_decode(d: &mut D) -> Result<BindingSig, serialize::Error> {
        let mut val: [u8; 64] = [0; 64];
        for i in 0..64 {
            val[i] = d.read_u8()?;
        }
        Ok(BindingSig {val})
    }
}
impl Hash for BindingSig {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.val.hash(state);
    }
}
impl fmt::Debug for BindingSig {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        self.val[..].fmt(formatter)
    }
}
impl Eq for BindingSig {}
impl PartialEq for BindingSig {
    fn eq(&self, other: &BindingSig) -> bool {
        self.val.iter().zip(other.val.iter()).all(|(a,b)| a == b)
    }
}

/// A Zcash Sapling transaction, which describes an authenticated movement of coins
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct Transaction {
    /// Contains:
    ///    · fOverwintered flag (bit 31)
    ///    · version (bits 30 .. 0) – transaction version
    pub header: TxHeader,
    /// Version group ID (nonzero)
    /// [Overwinter only, pre-Sapling] The transaction version number MUST be 3 and the version group ID MUST be 0x03C48270.
    /// [Sapling onward] The transaction version number MUST be 4 and the version group ID MUST be 0x892F2085.
    pub version_group_id: u32,
    /// Block number before which this transaction is valid, or 0 for valid immediately.
    pub lock_time: u32,
    /// A block height in the range {1 .. 499999999}
    /// after which the transaction will expire, or 0 to
    /// disable expiry ([ZIP-203])
    pub expiry_height: u32,
    /// The net value of Sapling Spend transfers minus Output transfers
    ///  [Sapling onward] If version ≥ 4 and nShieldedSpend + nShieldedOutput = 0, then valueBalance MUST be 0.
    pub value_balance: i64,
    /// An encoding of a JoinSplitSig public verification key.
    pub join_split_pubkey: Option<JoinSplitPubKey>,
    /// A signature on a prefix of the transaction encoding, to be verified using joinSplitPubKey.
    pub join_split_sig: Option<JoinSplitSig>,
    /// A signature on the SIGHASH transaction hash
    pub binding_sig: Option<BindingSig>,
    /// List of inputs
    pub input: Vec<TxIn>,
    /// List of outputs
    pub output: Vec<TxOut>,
    /// A sequence of Spend descriptions
    pub shielded_spend: Vec<SpendDescription>,
    /// A sequence of Output descriptions
    pub shielded_output: Vec<OutputDescription>,
    /// A sequence of Spend descriptions
    pub join_split: Vec<JSDescriptionPHGR13>,
}
serde_struct_impl!(Transaction, header, version_group_id, input, output, lock_time, expiry_height,
    value_balance, shielded_spend, shielded_output, join_split, join_split_pubkey, join_split_sig,
    binding_sig);

impl Transaction {

    /// From raw tx
    #[cfg(feature = "serde")]
    pub fn from_str(raw_tx: &str) -> Result<Self, serialize::Error> {
        use util::misc::hex_bytes;
        use network::serialize::deserialize;
        let hex_tx = hex_bytes(raw_tx).unwrap();
        deserialize(&hex_tx)
    }

    fn split_overwintered_flag(header: TxHeader) -> (u32, bool) {
        match header {
            TxHeader::Second                  => (0x02, false),
            TxHeader::Third                   => (0x03, false),
            TxHeader::ThirdAndOverwintered    => (0x03, true),
            TxHeader::FourthAndOverwintered   => (0x04, true),
            _ => (0x00, false)
        }
    }

    fn hash_prevouts(&self) -> Blake2bResult {
        let mut hash_prevouts = Blake2b::with_params(32, &[], &[], ZCASH_PREVOUTS_HASH_PERSONALIZATION);
        for input in self.input.iter() {
            hash_prevouts.update(serialize(&input.previous_output).unwrap().as_slice());
        }
        hash_prevouts.finalize()
    }

    fn hash_sequence(&self) -> Blake2bResult {
        let mut hash_sequence = Blake2b::with_params(32, &[], &[], ZCASH_SEQUENCE_HASH_PERSONALIZATION);
        for input in self.input.iter() {
            hash_sequence.update(serialize(&input.sequence).unwrap().as_slice());
        }
        hash_sequence.finalize()
    }

    fn hash_outputs(&self) -> Blake2bResult {
        let mut hash_outputs = Blake2b::with_params(32, &[], &[], ZCASH_OUTPUTS_HASH_PERSONALIZATION);
        for output in self.output.iter() {
            hash_outputs.update(serialize(output).unwrap().as_slice());
        }
        hash_outputs.finalize()
    }

    fn hash_output(&self, output_index: usize) -> Blake2bResult {
        let mut hash_output = Blake2b::with_params(32, &[], &[], ZCASH_OUTPUTS_HASH_PERSONALIZATION);
        hash_output.update(serialize(&self.output[output_index]).unwrap().as_slice());
        hash_output.finalize()
    }

    fn hash_join_splits(&self) -> Blake2bResult {
        let mut hash_join_splits = Blake2b::with_params(32, &[], &[], ZCASH_JOINSPLITS_HASH_PERSONALIZATION);
        for join_split in self.join_split.iter() {
            hash_join_splits.update(serialize(join_split).unwrap().as_slice());
        }
        match self.join_split_pubkey.clone() {
            Some(pubkey) => hash_join_splits.update(&pubkey.val[..]),
            None => {}
        }
        hash_join_splits.finalize()
    }

    fn hash_shielded_spends(&self) -> Blake2bResult {
        let mut hash_shielded_spends = Blake2b::with_params(32, &[], &[], ZCASH_SHIELDED_SPENDS_HASH_PERSONALIZATION);
        for shielded_spend in self.shielded_spend.iter() {
            hash_shielded_spends.update(&shielded_spend.shielded_spend_stub[..320]);
        }
        hash_shielded_spends.finalize()
    }

    fn hash_shielded_outputs(&self) -> Blake2bResult {
        let mut hash_shielded_outputs = Blake2b::with_params(32, &[], &[], ZCASH_SHIELDED_OUTPUTS_HASH_PERSONALIZATION);
        for shielded_output in self.shielded_output.iter() {
            hash_shielded_outputs.update(serialize(shielded_output).unwrap().as_slice());
        }
        hash_shielded_outputs.finalize()
    }
    /// Computes a signature hash for a given input index with a given sighash flag.
    /// To actually produce a scriptSig, this hash needs to be run through an
    /// ECDSA signer, the SigHashType appended to the resulting sig, and a
    /// script written around this, but this is the general (and hard) part.
    ///
    /// *Warning* This does NOT attempt to support OP_CODESEPARATOR. In general
    /// this would require evaluating `script_pubkey` to determine which separators
    /// get evaluated and which don't, which we don't have the information to
    /// determine.
    ///
    /// # Panics
    /// Panics if `input_index` is greater than or equal to `self.input.len()`
    ///
    pub fn signature_hash(&self,
        input_index: usize,
        script_pubkey: &Script,
        sighash_u32: u32,
        not_an_input_i32: i32,
        amount: u64) -> Blake2bResult {
        //assert!(input_index < self.input.len());  // Panic on OOB
        let (version, overwintered) = Self::split_overwintered_flag(self.header);
        match version {
            0x04 => {},
            _ => panic!("Tx version {} are not supported!", version)
        }
        match overwintered {
            true => {},
            false => panic!("Transactions that have not overwintered are not supported!")
        }
        let (sighash, anyone_can_pay) = SigHashType::from_u32(sighash_u32).split_anyonecanpay_flag();

        // Special-case sighash_single bug because this is easy enough.
        if sighash == SigHashType::Single && input_index >= self.output.len() {
            unimplemented!();
        }

        let mut wtr: Vec<u8> = vec![];
        let mut personalization: Vec<u8> = vec![];
        let mut hash_prevouts: Vec<u8> = vec![0; 32];
        let mut hash_sequence: Vec<u8> = vec![0; 32];
        let mut hash_outputs: Vec<u8> = vec![0; 32];
        let mut hash_join_splits: Vec<u8> = vec![0; 32];
        let mut hash_shielded_spends: Vec<u8> = vec![0; 32];
        let mut hash_shielded_outputs: Vec<u8> = vec![0; 32];


        // HashPrevouts (32-byte hash)
        if anyone_can_pay == false {
            hash_prevouts = self.hash_prevouts().as_bytes().to_vec();
        }

        if anyone_can_pay == false
                    && sighash != SigHashType::Single
                    && sighash != SigHashType::None {
            hash_sequence = self.hash_sequence().as_bytes().to_vec();
        }

        if sighash != SigHashType::Single && sighash != SigHashType::None {
            hash_outputs = self.hash_outputs().as_bytes().to_vec();
        } else if sighash == SigHashType::Single && input_index < self.output.len() {
            hash_outputs = self.hash_output(input_index).as_bytes().to_vec();
        }

        if self.join_split.len() != 0 {
            hash_join_splits = self.hash_join_splits().as_bytes().to_vec();
        }
        if self.shielded_spend.len() != 0 {
            hash_shielded_spends = self.hash_shielded_spends().as_bytes().to_vec();
        }
        if self.shielded_output.len() != 0 {
            hash_shielded_outputs = self.hash_shielded_outputs().as_bytes().to_vec();
        }

        personalization.append(&mut ZCASH_TX_HASH_PERSONALIZATION.clone().to_vec());
        personalization.write_u32::<LittleEndian>(ZCASH_SAPLING_CONSENSUS_BRANCH_ID).unwrap();
        let mut context = Blake2b::with_params(32, &[], &[], &personalization.as_slice());

        // Header of the transaction (4-byte little endian)
        wtr.write_u32::<LittleEndian>(self.header as u32).unwrap();
        // nVersionGroupId of the transaction (4-byte little endian)
        wtr.write_u32::<LittleEndian>(self.version_group_id).unwrap();
        // Input prevouts/nSequence (none/all, depending on flags)
        wtr.append(&mut hash_prevouts);
        wtr.append(&mut hash_sequence);
        // Outputs (none/one/all, depending on flags)
        wtr.append(&mut hash_outputs);
        // HashJoinSplits (32-byte hash)
        wtr.append(&mut hash_join_splits);
        // HashShieldedSpends (32-byte hash)
        wtr.append(&mut hash_shielded_spends);
        // HashShieldedOutputs (32-byte hash)
        wtr.append(&mut hash_shielded_outputs);
        // LockTime of the transaction (4-byte little endian)
        wtr.write_u32::<LittleEndian>(self.lock_time).unwrap();
        // ExpiryHeight of the transaction (4-byte little endian)
        wtr.write_u32::<LittleEndian>(self.expiry_height).unwrap();
        // ValueBalance of the transaction (8-byte little endian)
        wtr.write_i64::<LittleEndian>(self.value_balance).unwrap();
        // Sighash type of the signature (4-byte little endian)
        wtr.write_u32::<LittleEndian>(sighash_u32).unwrap();

        if not_an_input_i32 == 0 {
            // If we are serializing an input (i.e. this is not a JoinSplit signature hash):

            // Outpoint (32-byte hash + 4-byte little endian)
            let mut prevout = serialize(&self.input[input_index].previous_output).unwrap();
            wtr.append(&mut prevout);
            // ScriptCode of the input (serialized as scripts inside CTxOuts)
            if script_pubkey.len() <= 252 {
                wtr.write_u8(script_pubkey.len() as u8).unwrap();
            }else {
                unimplemented!();
            }

            wtr.append(&mut script_pubkey.as_bytes().clone().to_vec());

            // Value of the output spent by this input (8-byte little endian)
            wtr.write_u64::<LittleEndian>(amount).unwrap();
            // nSequence of the input (4-byte little endian)
            wtr.write_u32::<LittleEndian>(self.input[input_index].sequence).unwrap();
        }
        context.update(&wtr);
        context.finalize()

    }

    /// Gets the "weight" of this transaction, as defined by BIP141. For transactions with an empty
    /// witness, this is simply the consensus-serialized size times 4. For transactions with a
    /// witness, this is the non-witness consensus-serialized size multiplied by 3 plus the
    /// with-witness consensus-serialized size.
    /// TODO: add new fields weight
    #[inline]
    pub fn get_weight(&self) -> u64 {
        let mut input_weight = 0;
        let mut inputs_with_witnesses = 0;
        for input in &self.input {
            input_weight += 4*(32 + 4 + 4 + // outpoint (32+4) + nSequence
                VarInt(input.script_sig.len() as u64).encoded_length() +
                input.script_sig.len() as u64);
            if !input.witness.is_empty() {
                inputs_with_witnesses += 1;
                input_weight += VarInt(input.witness.len() as u64).encoded_length();
                for elem in &input.witness {
                    input_weight += VarInt(elem.len() as u64).encoded_length() + elem.len() as u64;
                }
            }
        }
        let mut output_size = 0;
        for output in &self.output {
            output_size += 8 + // value
                VarInt(output.script_pubkey.len() as u64).encoded_length() +
                output.script_pubkey.len() as u64;
        }
        let non_input_size =
        // version:
        4 +
        // count varints:
        VarInt(self.input.len() as u64).encoded_length() +
        VarInt(self.output.len() as u64).encoded_length() +
        output_size +
        // lock_time
        4;
        if inputs_with_witnesses == 0 {
            non_input_size * 4 + input_weight
        } else {
            non_input_size * 4 + input_weight + self.input.len() as u64 - inputs_with_witnesses + 2
        }
    }

    #[cfg(feature="bitcoinconsensus")]
    /// Verify that this transaction is able to spend some outputs of spent transactions
    pub fn verify(&self, spent: &HashMap<Sha256dHash, Transaction>) -> Result<(), script::Error> {
        if let Ok(tx) = serialize(&*self) {
            for (idx, input) in self.input.iter().enumerate() {
                if let Some(ref s) = spent.get(&input.previous_output.txid) {
                    if let Some(ref output) = s.output.get(input.previous_output.vout as usize) {
                        output.script_pubkey.verify(idx, output.value, tx.as_slice())?;
                    } else {
                        return Err(script::Error::WrongSpentOutputIndex(input.previous_output.vout as usize));
                    }
                } else {
                    return Err(script::Error::UnknownSpentTransaction(input.previous_output.txid));
                }
            }
            Ok(())
        }
        else {
            Err(script::Error::SerializationError)
        }
    }

    /// Is this a coin base transaction?
    pub fn is_coin_base(&self) -> bool {
        self.input.len() == 1 && self.input[0].previous_output.is_null()
    }
}

impl BitcoinHash for Transaction {
    fn bitcoin_hash(&self) -> Sha256dHash {
        use util::hash::Sha256dEncoder;
        let mut enc = Sha256dEncoder::new();
        self.consensus_encode(&mut enc).unwrap();
        enc.into_hash()
    }
}

impl_consensus_encoding!(TxOut, value, script_pubkey);

impl<S: SimpleEncoder> ConsensusEncodable<S> for OutPoint {
    fn consensus_encode(&self, s: &mut S) -> Result <(), serialize::Error> {
        self.txid.consensus_encode(s)?;
        self.vout.consensus_encode(s)
    }
}
impl<D: SimpleDecoder> ConsensusDecodable<D> for OutPoint {
    fn consensus_decode(d: &mut D) -> Result<OutPoint, serialize::Error> {
        Ok(OutPoint {
            txid: ConsensusDecodable::consensus_decode(d)?,
            vout: ConsensusDecodable::consensus_decode(d)?,
        })
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for TxIn {
    fn consensus_encode(&self, s: &mut S) -> Result <(), serialize::Error> {
        self.previous_output.consensus_encode(s)?;
        self.script_sig.consensus_encode(s)?;
        self.sequence.consensus_encode(s)
    }
}
impl<D: SimpleDecoder> ConsensusDecodable<D> for TxIn {
    fn consensus_decode(d: &mut D) -> Result<TxIn, serialize::Error> {
        Ok(TxIn {
            previous_output: ConsensusDecodable::consensus_decode(d)?,
            script_sig: ConsensusDecodable::consensus_decode(d)?,
            sequence: ConsensusDecodable::consensus_decode(d)?,
            witness: vec![],
        })
    }
}

impl<S: SimpleEncoder> ConsensusEncodable<S> for Transaction {
    fn consensus_encode(&self, s: &mut S) -> Result <(), serialize::Error> {
        self.header.consensus_encode(s)?;
        self.version_group_id.consensus_encode(s)?;
        self.input.consensus_encode(s)?;
        self.output.consensus_encode(s)?;
        self.lock_time.consensus_encode(s)?;
        self.expiry_height.consensus_encode(s)?;
        self.value_balance.consensus_encode(s)?;
        self.shielded_spend.consensus_encode(s)?;
        self.shielded_output.consensus_encode(s)?;
        self.join_split.consensus_encode(s)
    }
}

impl<D: SimpleDecoder> ConsensusDecodable<D> for Transaction {
    fn consensus_decode(d: &mut D) -> Result<Transaction, serialize::Error> {

        let header: TxHeader = ConsensusDecodable::consensus_decode(d)?;
        let version_group_id: u32 = ConsensusDecodable::consensus_decode(d)?;
        let input: Vec<TxIn> = ConsensusDecodable::consensus_decode(d)?;
        let output: Vec<TxOut> = ConsensusDecodable::consensus_decode(d)?;
        let lock_time: u32 = ConsensusDecodable::consensus_decode(d)?;
        let expiry_height: u32 = ConsensusDecodable::consensus_decode(d)?;
        let value_balance: i64 = ConsensusDecodable::consensus_decode(d)?;
        let shielded_spend: Vec<SpendDescription> = ConsensusDecodable::consensus_decode(d)?;
        let shielded_output: Vec<OutputDescription> = ConsensusDecodable::consensus_decode(d)?;
        let join_split: Vec<JSDescriptionPHGR13> = ConsensusDecodable::consensus_decode(d)?;
        let join_split_pubkey: Option<JoinSplitPubKey> =
            if header as u32 >= 2 && join_split.len() > 0 {
                Some(ConsensusDecodable::consensus_decode(d)?)
            } else {
                None
            };
        let join_split_sig: Option<JoinSplitSig> =
            if header as u32 >= 2 && join_split.len() > 0 {
                Some(ConsensusDecodable::consensus_decode(d)?)
            } else {
                None
            };
        let binding_sig: Option<BindingSig> = if (header == TxHeader::FourthAndOverwintered)
                                                    && (shielded_spend.len() + shielded_output.len()) > 0 {
            Some(ConsensusDecodable::consensus_decode(d)?)
        } else {
            None
        };
        Ok(Transaction {
            header,
            version_group_id,
            input,
            output,
            lock_time,
            expiry_height,
            value_balance,
            shielded_spend,
            shielded_output,
            binding_sig,
            join_split_pubkey,
            join_split_sig,
            join_split,
        })
    }
}

/// Hashtype of a transaction, encoded in the last byte of a signature
/// Fixed values so they can be casted as integer types for encoding
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum SigHashType {
    /// 0x1: Sign all outputs
    All		= 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination
    None	= 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single	= 0x03,
    /// 0x81: Sign all outputs but only this input
    AllPlusAnyoneCanPay		= 0x81,
    /// 0x82: Sign no outputs and only this input
    NonePlusAnyoneCanPay	= 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means)
    SinglePlusAnyoneCanPay	= 0x83
}

impl SigHashType {
     /// Break the sighash flag into the "real" sighash flag and the ANYONECANPAY boolean
     fn split_anyonecanpay_flag(&self) -> (SigHashType, bool) {
         match *self {
             SigHashType::All		=> (SigHashType::All, false),
             SigHashType::None		=> (SigHashType::None, false),
             SigHashType::Single	=> (SigHashType::Single, false),
             SigHashType::AllPlusAnyoneCanPay		=> (SigHashType::All, true),
             SigHashType::NonePlusAnyoneCanPay		=> (SigHashType::None, true),
             SigHashType::SinglePlusAnyoneCanPay	=> (SigHashType::Single, true)
         }
     }

     /// Reads a 4-byte uint32 as a sighash type
     pub fn from_u32(n: u32) -> SigHashType {
         match n & 0x9f {
             // "real" sighashes
             0x01 => SigHashType::All,
             0x02 => SigHashType::None,
             0x03 => SigHashType::Single,
             0x81 => SigHashType::AllPlusAnyoneCanPay,
             0x82 => SigHashType::NonePlusAnyoneCanPay,
             0x83 => SigHashType::SinglePlusAnyoneCanPay,
             // catchalls
             x if x & 0x80 == 0x80 => SigHashType::AllPlusAnyoneCanPay,
             _ => SigHashType::All
         }
     }

     /// Converts to a u32
     pub fn as_u32(&self) -> u32 { *self as u32 }
}


#[cfg(test)]
mod tests {
    extern crate rustc_serialize;
    #[cfg(all(feature = "serde", feature = "strason"))]
    use strason::Json;

    use super::{Transaction, TxIn, ZCASH_PREVOUTS_HASH_PERSONALIZATION, ZCASH_OUTPUTS_HASH_PERSONALIZATION,
                                   ZCASH_SAPLING_CONSENSUS_BRANCH_ID, TxHeader};
    #[allow(unused_imports)]
    use self::rustc_serialize::hex::FromHex;
    #[allow(unused_imports)]
    use self::rustc_serialize::hex::ToHex;
    #[allow(unused_imports)]
    use blockdata::script::Script;
    #[allow(unused_imports)]
    use network::serialize::{self, serialize, BitcoinHash, SimpleEncoder, SimpleDecoder};
    #[cfg(all(feature = "serde", feature = "strason"))]
    use network::serialize::serialize;
    use network::serialize::deserialize;
    #[allow(unused_imports)]
    use util::hash::Sha256dHash;
    use util::misc::hex_bytes;
    #[allow(unused_imports)]
    use blake2_rfc::blake2b::{Blake2b, Blake2bResult, blake2b};
    #[allow(unused_imports)]
    use byteorder::{LittleEndian, BigEndian, WriteBytesExt, ReadBytesExt};
    use std::io::Cursor;

    #[test]
    fn test_txin() {
        let txin: Result<TxIn, _> = deserialize(&hex_bytes("a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff").unwrap());
        assert!(txin.is_ok());
    }

    #[allow(dead_code)]
    fn signer() {

    }

    #[test]
    fn test_signer() {

    }


    #[test]
    fn test_transaction() {
        let hex_tx = hex_bytes("0400008085202f8901e9f7b47c2a612e30a6e2cae39e1d4763901fedd076e9450c5df0f0d087d25\
                    e45010000006b483045022100a4553c79e56d119c50c73055d4e6d6a4f8faa2e257a6762c8f9e2758f208d774022\
                    0250257e51bbeb50ecd8e27b65d976b5108c3bf62ead19984a6377963bcdfd3de012103804a8e414c7c541d7a0720\
                    de5330e1fc51a696286b1523051286058ee9e724c3feffffff02650400000000000017a91466db59c466b84e64eda\
                    5db42cc48c5c8fc927cd4871148e111000000001976a914060277e4e1c2ab568d17ba769dcfc489a9c973a088ac09\
                    8b0400288b04000000000000000000000000").unwrap();
        let tx: Result<Transaction, _> = deserialize(&hex_tx);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        // All these tests aren't really needed because if they fail, the hash check at the end
        // will also fail. But these will show you where the failure is so I'll leave them in.
        assert_eq!(realtx.header, TxHeader::FourthAndOverwintered);
        assert_eq!(realtx.version_group_id, 0x892F2085);
        assert_eq!(realtx.input.len(), 1);
        assert_eq!(realtx.output.len(), 2);
        assert_eq!(realtx.lock_time, 297737);
        assert_eq!(realtx.expiry_height, 297768);
        assert_eq!(realtx.join_split.len(), 0);
        assert_eq!(realtx.shielded_output.len(), 0);
        assert_eq!(realtx.shielded_spend.len(), 0);
        assert_eq!(realtx.binding_sig, None);
        assert_eq!(realtx.join_split_pubkey, None);
        assert_eq!(realtx.join_split_sig, None);
    }

    #[test]
    fn test_blake2b_basic() {
        let mut hash = Blake2b::with_params(32, &[], &[], &ZCASH_PREVOUTS_HASH_PERSONALIZATION);
        assert_eq!(hash.finalize().as_bytes().to_hex(), "d53a633bbecf82fe9e9484d8a0e727c73bb9e68c96e72dec30144f6a84afa136");
        hash = Blake2b::with_params(32, &[], &[], &ZCASH_OUTPUTS_HASH_PERSONALIZATION);
        hash.update("8f739811893e0000095200ac6551ac636565b1a45a0805750200025151".from_hex().unwrap().as_slice());
        assert_eq!(hash.finalize().as_bytes().to_hex(), "ec55f4afc6cebfe1c35bdcded7519ff6efb381ab1d5a8dd0060c13b2a512932b");
    }

    #[test]
    fn test_tmp() {
        let mut wtr = vec![];
        wtr.write_u32::<LittleEndian>(ZCASH_SAPLING_CONSENSUS_BRANCH_ID).unwrap();
        println!("ZCASH_SAPLING_CONSENSUS_BRANCH_ID: 0x{:x}", ZCASH_SAPLING_CONSENSUS_BRANCH_ID);
        println!("wtr: {:?}", wtr);
    }

    #[test]
    fn test_tx_decode() {
        let hex_tx = hex_bytes("0400008085202f8901f3f783c96b13300b5e367932bf6b1564a70618533a560883\
        c45135befcd34ae4000000006b483045022100d87c30f166735d066c042102dfc84cacd752d52d120b8d8874be\
        fd311e929b620220232a98a43fa5caaaa632ce2d146b33eeab03a0745e3053499d331a077fb3c0c2012103f9a7\
        e5382eebb78faacfd5670b03510157818d5167e1e193a860cdced855971cfeffffff02f04902000000000017a9\
        14b6d8b6eb2655e56e5d98dcd6f4e4e7c80d20f2bb8729260b3b000000001976a914a767bab91d8ce7a869d69c\
        d956e35a526d45d82888aca5110000c41100000000000000000000000000").unwrap();
        let tx: Result<Transaction, _> = deserialize(&hex_tx);
        assert!(tx.is_ok());
        let realtx = tx.unwrap();
        println!("tx: {:?}",  realtx);
        assert_eq!(realtx.version_group_id, 0x892f2085);
        assert_eq!(realtx.lock_time, 4517);
        assert_eq!(realtx.expiry_height, 4548);
        assert_eq!(realtx.input.len(), 1);
        assert_eq!({
                    let mut hash_vec = realtx.input[0].previous_output.txid.as_bytes().clone();
                    hash_vec.reverse();
                    hash_vec
                    }.to_hex(), "e44ad3fcbe3551c48308563a531806a764156bbf3279365e0b30136bc983f7f3");
        assert_eq!(realtx.input[0].previous_output.vout, 0);
        assert_eq!(realtx.input[0].script_sig.to_bytes(), "483045022100d87c30f166735d066c042102dfc84ca\
            cd752d52d120b8d8874befd311e929b620220232a98a43fa5caaaa632ce2d146b33eeab03a0745e3053499\
            d331a077fb3c0c2012103f9a7e5382eebb78faacfd5670b03510157818d5167e1e193a860cdced855971c"
            .from_hex().unwrap());
        assert_eq!(realtx.input[0].sequence, 4294967294);
        assert_eq!(realtx.output.len(), 2);
        assert_eq!(realtx.output[0].value, 150000);
        assert_eq!(realtx.output[0].script_pubkey.to_bytes(),
            "a914b6d8b6eb2655e56e5d98dcd6f4e4e7c80d20f2bb87".from_hex().unwrap());
        assert_eq!(realtx.output[1].value, 990586409);
        assert_eq!(realtx.output[1].script_pubkey.to_bytes(),
            "76a914a767bab91d8ce7a869d69cd956e35a526d45d82888ac".from_hex().unwrap());
        assert_eq!(realtx.join_split.len(), 0);
        assert_eq!(realtx.shielded_spend.len(), 0);
        assert_eq!(realtx.shielded_output.len(), 0);
        assert_eq!(realtx.value_balance, 0);

        assert_eq!(serialize::serialize(&realtx).unwrap().to_hex(), "0400008085202f8901f3f783c96b1\
        3300b5e367932bf6b1564a70618533a560883\
        c45135befcd34ae4000000006b483045022100d87c30f166735d066c042102dfc84cacd752d52d120b8d8874be\
        fd311e929b620220232a98a43fa5caaaa632ce2d146b33eeab03a0745e3053499d331a077fb3c0c2012103f9a7\
        e5382eebb78faacfd5670b03510157818d5167e1e193a860cdced855971cfeffffff02f04902000000000017a9\
        14b6d8b6eb2655e56e5d98dcd6f4e4e7c80d20f2bb8729260b3b000000001976a914a767bab91d8ce7a869d69c\
        d956e35a526d45d82888aca5110000c41100000000000000000000000000");
    }

        #[test]
        /// https://github.com/zcash/zips/blob/master/zip-0243.rst#test-vector-1
        fn test_sig_check_vector_1() {
            let hex_tx = hex_bytes("0400008085202f890002e7719811893e0000095200ac6551ac636565b2835a0805\
                750200025151481cdd86b3cc4318442117623ceb0500031b3d1a027c2c40590958b7eb13d742a997738c46\
                a458965baf276ba92f272c721fe01f7e9c8e36d6a5e29d4e30a73594bf5098421c69378af1e40f64e12594\
                6f62c2fa7b2fecbcb64b6968912a6381ce3dc166d56a1d62f5a8d7551db5fd9313e8c7203d996af7d47708\
                3756d59af80d06a745f44ab023752cb5b406ed8985e18130ab33362697b0e4e4c763ccb8f676495c222f7f\
                ba1e31defa3d5a57efc2e1e9b01a035587d5fb1a38e01d94903d3c3e0ad3360c1d3710acd20b183e31d49f\
                25c9a138f49b1a537edcf04be34a9851a7af9db6990ed83dd64af3597c04323ea51b0052ad8084a8b9da94\
                8d320dadd64f5431e61ddf658d24ae67c22c8d1309131fc00fe7f235734276d38d47f1e191e00c7a1d48af\
                046827591e9733a97fa6b679f3dc601d008285edcbdae69ce8fc1be4aac00ff2711ebd931de518856878f7\
                3476f21a482ec9378365c8f7393c94e2885315eb4671098b79535e790fe53e29fef2b3766697ac32b4f473\
                f468a008e72389fc03880d780cb07fcfaabe3f1a15825b7acb4d6b57a61bc68f242b52e4fbf85cf1a09cc4\
                5b6d6bb3a391578f499486a7afd04a0d9c74c2995d96b4de37b36046a1ef6d190b916b1111c92887311a20\
                da8aba18d1dbebbc862ded42435e92476930d069896cff30eb414f727b89e001afa2fb8dc3436d75a4a6f2\
                6572504b192232ecb9f0c02411e52596bc5e90457e745939ffedbd12863ce71a02af117d417adb3d15cc54\
                dcb1fce467500c6b8fb86b12b56da9c382857deecc40a98d5f2935395ee4762dd21afdbb5d47fa9a6dd984\
                d567db2857b927b7fae2db587105415d4642789d38f50b8dbcc129cab3d17d19f3355bcf73cecb8cb8a5da\
                01307152f13936a270572670dc82d39026c6cb4cd4b0f7f5aa2a4f5a5341ec5dd715406f2fdd2afa733f5f\
                641c8c21862a1bafce2609d9eecfa158cfb5cd79f88008e315dc7d8388e76c1782fd2795d18a763624c25f\
                a959cc97489ce75745824b77868c53239cfbdf73caec65604037314faaceb56218c6bd30f8374ac1338679\
                3f21a9fb80ad03bc0cda4a44946c00e1b102c78f11876b7065212183199fb5979ca77d2c24c738fe5145f0\
                2602053bb4c2f6556df6ed4b4ddd3d9a69f53357d7767f4f5ccbdbc596631277f8fecd08cb056b95e3025b\
                9792fff7f244fc716269b926d62e9596fa825c6bf21aff9e68625a192440ea06828123d97884806f15fa08\
                da52754a1095e3ff1abd5ce4fddfccfc3a6128aef784a64610a89d1a7099216d0814d3a2d452431c32d411\
                ac1cce82ad0229407bbc48985675e3f874a4533f1d63a84dfa3e0f460fe2f57e34fbc75423c3737f5b2a06\
                15f5722db041a3ef66fa483afd3c2e19e59444a64add6df1d963f5dd5b5010d3d025f0287c4cf19c75f33d\
                51ddddba5d657b43ee8da645443814cc7329f3e9b4e54c236c29af3923101756d9fa4bd0f7d2ddaacb6b0f\
                86a2658e0a07a05ac5b950051cd24c47a88d13d659ba2a46ca1830816d09cd7646f76f716abec5de07fe9b\
                523410806ea6f288f8736c23357c85f45791e1708029d9824d90704607f387a03e49bf9836574431345a78\
                77efaa8a08e73081ef8d62cb780a010fa3207ee2f0408097d563da1b2146819edf88d33e7753664fb71d12\
                2a6e36998fbd467f75b780149ae8808f4e68f50c0536acddf6f1aeab016b6bc1ec144b4e59aeb77eef49d0\
                0e5fbb67101cdd41e6bc9cf641a52fca98be915f8440a410d74cb30e15914f01bc6bc2307b488d2556d7b7\
                380ea4ffd712f6b02fe806b94569cd4059f396bf29b99d0a40e5e1711ca944f72d436a102fca4b97693da0\
                b086fe9d2e7162470d02e0f05d4bec9512bfb3f38327296efaa74328b118c27402c70c3a90b49ad4bbc68e\
                37c0aa7d9b3fe17799d73b841e751713a02943905aae0803fd69442eb7681ec2a05600054e92eed555028f\
                21b6a155268a2dd6640a69301a52a38d4d9f9f957ae35af7167118141ce4c9be0a6a492fe79f1581a155fa\
                3a2b9dafd82e650b386ad3a08cb6b83131ac300b0846354a7eef9c410e4b62c47c5426907dfc6685c5c99b\
                7141ac626ab4761fd3f41e728e1a28f89db89ffdeca364dd2f0f0739f0534556483199c71f189341ac9b78\
                a269164206a0ea1ce73bfb2a942e7370b247c046f8e75ef8e3f8bd821cf577491864e20e6d08fd2e32b555\
                c92c661f19588b72a89599710a88061253ca285b6304b37da2b5294f5cb354a894322848ccbdc7c2545b7d\
                a568afac87ffa005c312241c2d57f4b45d6419f0d2e2c5af33ae243785b325cdab95404fc7aed70525cddb\
                41872cfcc214b13232edc78609753dbff930eb0dc156612b9cb434bc4b693392deb87c530435312edcedc6\
                a961133338d786c4a3e103f60110a16b1337129704bf4754ff6ba9fbe65951e610620f71cda8fc877625f2\
                c5bb04cbe1228b1e886f4050afd8fe94e97d2e9e85c6bb748c0042d3249abb1342bb0eebf62058bf3de080\
                d94611a3750915b5dc6c0b3899d41222bace760ee9c8818ded599e34c56d7372af1eb86852f2a732104bdb\
                750739de6c2c6e0f9eb7cb17f1942bfc9f4fd6ebb6b4cdd4da2bca26fac4578e9f543405acc7d86ff59158\
                bd0cba3aef6f4a8472d144d99f8b8d1dedaa9077d4f01d4bb27bbe31d88fbefac3dcd4797563a26b1d61fc\
                d9a464ab21ed550fe6fa09695ba0b2f10eea6468cc6e20a66f826e3d14c5006f0563887f5e1289be1b2004\
                caca8d3f34d6e84bf59c1e04619a7c23a996941d889e4622a9b9b1d59d5e319094318cd405ba27b7e2c084\
                762d31453ec4549a4d97729d033460fcf89d6494f2ffd789e98082ea5ce9534b3acd60fe49e37e4f666931\
                677319ed89f85588741b3128901a93bd78e4be0225a9e2692c77c969ed0176bdf9555948cbd5a332d045de\
                6ba6bf4490adfe7444cd467a09075417fc0200000000000000000000000000000000062e49f008c51ad422\
                7439c1b4476ccd8e97862dab7be1e8d399c05ef27c6e22ee273e15786e394c8f1be31682a30147963ac8da\
                8d41d804258426a3f70289b8ad19d8de13be4eebe3bd4c8a6f55d6e0c373d456851879f5fbc282db9e1348\
                06bff71e11bc33ab75dd6ca067fb73a043b646a7cf39cab4928386786d2f24141ee120fdc34d6764eafc66\
                880ee0204f53cc1167ed20b43a52dea3ca7cff8ef35cd8e6d7c111a68ef44bcd0c1513ad47ca61c659cc5d\
                325b440f6b9f59aff66879bb6688fd2859362b182f207b3175961f6411a493bffd048e7d0d87d82fe6f990\
                a2b0a25f5aa0111a6e68f37bf6f3ac2d26b84686e569d58d99c1383597fad81193c4c1b16e6a90e2d507cd\
                fe6fbdaa86163e9cf5de3100fbca7e8da047b090db9f37952fbfee76af61668190bd52ed490e677b515d01\
                4384af07219c7c0ee7fc7bfc79f325644e4df4c0d7db08e9f0bd024943c705abff8994bfa605cfbc7ed746\
                a7d3f7c37d9e8bdc433b7d79e08a12f738a8f0dbddfef2f2657ef3e47d1b0fd11e6a13311fb799c79c641d\
                9da43b33e7ad012e28255398789262275f1175be8462c01491c4d842406d0ec4282c9526174a09878fe8fd\
                de33a29604e5e5e7b2a025d6650b97dbb52befb59b1d30a57433b0a351474444099daa371046613260cf33\
                54cfcdada663ece824ffd7e44393886a86165ddddf2b4c41773554c86995269408b11e6737a4c447586f69\
                173446d8e48bf84cbc000a807899973eb93c5e819aad669413f8387933ad1584aa35e43f4ecd1e2d0407c0\
                b1b89920ffdfdb9bea51ac95b557af71b89f903f5d9848f14fcbeb1837570f544d6359eb23faf38a0822da\
                36ce426c4a2fbeffeb0a8a2e297a9d19ba15024590e3329d9fa9261f9938a4032dd34606c9cf9f3dd33e57\
                6f05cd1dd6811c6298757d77d9e810abdb226afcaa4346a6560f8932b3181fd355d5d391976183f8d99388\
                839632d6354f666d09d3e5629ea19737388613d38a34fd0f6e50ee5a0cc9677177f50028c141378187bd28\
                19403fc534f80076e9380cb4964d3b6b45819d3b8e9caf54f051852d671bf8c1ffde2d1510756418cb4810\
                936aa57e6965d6fb656a760b7f19adf96c173488552193b147ee58858033dac7cd0eb204c06490bbdedf5f\
                7571acb2ebe76acef3f2a01ee987486dfe6c3f0a5e234c127258f97a28fb5d164a8176be946b8097d0e317\
                287f33bf9c16f9a545409ce29b1f4273725fc0df02a04ebae178b3414fb0a82d50deb09fcf4e6ee9d180ff\
                4f56ff3bc1d3601fc2dc90d814c3256f4967d3a8d64c83fea339c51f5a8e5801fbb97835581b602465dee0\
                4b5922c2761b54245bec0c9eef2db97d22b2b3556cc969fbb13d06509765a52b3fac54b93f421bf08e18d5\
                2ddd52cc1c8ca8adfaccab7e5cc2f4573fbbf8239bb0b8aedbf8dad16282da5c9125dba1c059d0df8abf62\
                1078f02d6c4bc86d40845ac1d59710c45f07d585eb48b32fc0167ba256e73ca3b9311c62d109497957d8db\
                e10aa3e866b40c0baa2bc492c19ad1e6372d9622bf163fbffeaeee796a3cd9b6fbbfa4d792f34d7fd6e763\
                cd5859dd26833d21d9bc5452bd19515dff9f4995b35bc0c1f876e6ad11f2452dc9ae85aec01fc56f8cbfda\
                75a7727b75ebbd6bbffb43b63a3b1b671e40feb0db002974a3c3b1a788567231bf6399ff89236981149d42\
                3802d2341a3bedb9ddcbac1fe7b6435e1479c72e7089d029e7fbbaf3cf37e9b9a6b776791e4c5e6fda57e8\
                d5f14c8c35a2d270846b9dbe005cda16af4408f3ab06a916eeeb9c9594b70424a4c1d171295b6763b22f47\
                f80b53ccbb904bd68fd65fbd3fbdea1035e98c21a7dbc91a9b5bc7690f05ec317c97f8764eb48e911d428e\
                c8d861b708e8298acb62155145155ae95f0a1d1501034753146e22d05f586d7f6b4fe12dad9a17f5db70b1\
                db96b8d9a83edadc966c8a5466b61fc998c31f1070d9a5c9a6d268d304fe6b8fd3b4010348611abdcbd49f\
                e4f85b623c7828c71382e1034ea67bc8ae97404b0c50b2a04f559e49950afcb0ef462a2ae024b0f0224dfd\
                73684b88c7fbe92d02b68f759c4752663cd7b97a14943649305521326bde085630864629291bae25ff8822\
                a14c4b666a9259ad0dc42a8290ac7bc7f53a16f379f758e5de750f04fd7cad47701c8597f97888bea6fa0b\
                f2999956fbfd0ee68ec36e4688809ae231eb8bc4369f5fe1573f57e099d9c09901bf39caac48dc11956a8a\
                e905ead86954547c448ae43d315e669c4242da565938f417bf43ce7b2b30b1cd4018388e1a910f0fc41fb0\
                877a5925e466819d375b0a912d4fe843b76ef6f223f0f7c894f38f7ab780dfd75f669c8c06cffa00000000\
                00000000000000000000000043eb47565a50e3b1fa45ad61ce9a1c4727b7aaa53562f523e73952bbf33d8a\
                4104078ade3eaaa49699a69fdf1c5ac7732146ee5e1d6b6ca9b9180f964cc9d0878ae1373524d7d510e582\
                27df6de9d30d271867640177b0f1856e28d5c8afb095ef6184fed651589022eeaea4c0ce1fa6f085092b04\
                979489172b3ef8194a798df5724d6b05f1ae000013a08d612bca8a8c31443c10346dbf61de8475c0bbec51\
                04b47556af3d514458e2321d146071789d2335934a680614e83562f82dfd405b54a45eb32c165448d4d5d6\
                1ca2859585369f53f1a137e9e82b67b8fdaf01bda54a317311896ae10280a032440c420a421e944d1e952b\
                70d5826cd3b08b7db9630fe4fd5f22125de840fcc40b98038af11d55be25432597b4b65b9ec1c7a8bbfd05\
                2cbf7e1c1785314934b262d5853754f1f17771cfb7503072655753fa3f54ecc587e9f83b581916092df26e\
                63e18994cb0db91a0bbdc7b6119b32222adf5e61d8d8ae89dae4954b54813bb33f08d562ba513fee1b09c0\
                fcd516055419474dd7fda038a89c84ea7b9468287f0eb0c10c4b132520194d3d8d5351fc10d09c15c8cc10\
                1aa1663bbf17b84111f38bb439f07353bdea3596d15e713e1e2e7d3f1c383135b47fa7f81f46df7a902a40\
                4699ec912f5656c35b85763e4de583aecaa1dfd5d2677d9c8ffee877f63f40a5ca0d67f6e554124739f805\
                af876aeede53aa8b0f8e5604a73c30cbd09dad963d6f8a5dcc40def40797342113ba206fae8ebe4f3bc3ca\
                f69259e462eff9ba8b3f4bfaa1300c26925a8729cd32915bfc966086f0d5560bbe32a598c22adfb48cef72\
                ba5d4287c0cefbacfd8ce195b4963c34a94bba7a175dae4bbe3ef4863d53708915090f47a068e227433f9e\
                49d3aa09e356d8d66d0c0121e91a3c4aa3f27fa1b63396e2b41db908fdab8b18cc7304e94e970568f9421c\
                0dbbbaf84598d972b0534f48a5e52670436aaa776ed2482ad703430201e53443c36dcfd34a0cb663787610\
                5e79bf3bd58ec148cb64970e3223a91f71dfcfd5a04b667fbaf3d4b3b908b9828820dfecdd753750b5f9d2\
                216e56c615272f854464c0ca4b1e85aedd038292c4e1a57744ebba010b9ebfbb011bd6f0b78805025d27f3\
                c17746bae116c15d9f471f0f6288a150647b2afe9df7cccf01f5cde5f04680bbfed87f6cf429fb27ad6bab\
                e791766611cf5bc20e48bef119259b9b8a0e39c3df28cb9582ea338601cdc481b32fb82adeebb3dade25d1\
                a3df20c37e712506b5d996c49a9f0f30ddcb91fe9004e1e83294a6c9203d94e8dc2cbb449de4155032604e\
                47997016b304fd437d8235045e255a19b743a0a9f2e336b44cae307bb3987bd3e4e777fbb34c0ab8cc3d67\
                466c0a88dd4ccad18a07a8d1068df5b629e5718d0f6df5c957cf71bb00a5178f175caca944e635c5159f73\
                8e2402a2d21aa081e10e456afb00b9f62416c8b9c0f7228f510729e0be3f305313d77f7379dc2af24869c6\
                c74ee4471498861d192f0ff0f508285dab6b6a36ccf7d12256cc76b95503720ac672d08268d2cf7773b6ba\
                2a5f664847bf707f2fc10c98f2f006ec22ccb5a8c8b7c40c7c2d49a6639b9f2ce33c25c04bc461e744dfa5\
                36b00d94baddf4f4d14044c695a33881477df124f0fcf206a9fb2e65e304cdbf0c4d2390170c130ab849c2\
                f22b5cdd3921640c8cf1976ae1010b0dfd9cb2543e45f99749cc4d61f2e8aabfe98bd905fa39951b33ea76\
                9c45ab9531c57209862ad12fd76ba4807e65417b6cd12fa8ec916f013ebb8706a96effeda06c4be24b0484\
                6392e9d1e6930eae01fa21fbd700583fb598b92c8f4eb8a61aa6235db60f2841cf3a1c6ab54c6706684471\
                1d091eb931a1bd6281aedf2a0e8fab18817202a9be06402ed9cc720c16bfe881e4df4255e87afb7fc62f38\
                116bbe03cd8a3cb11a27d568414782f47b1a44c97c680467694bc9709d32916c97e8006cbb07ba0e4180a3\
                738038c374c4cce8f32959afb25f303f5815c4533124acf9d18940e77522ac5dc4b9570aae8f47b7f57fd8\
                767bea1a24ae7bed65b4afdc8f1278c30e2db98fd172730ac6bbed4f1127cd32b04a95b205526cfcb4c4e1\
                cc955175b3e8de1f5d81b18669692350aaa1a1d797617582e54d7a5b57a683b32fb1098062dad7b0c2eb51\
                8f6862e83db25e3dbaf7aed504de932acb99d735992ce62bae9ef893ff6acc0ffcf8e3483e146b9d49dd8c\
                7835f43a37dca0787e3ec9f6605223d5ba7ae0ab9025b73bc03f7fac36c009a56d4d95d1e81d3b3ebca7e5\
                4cc1a12d127b57c8138976e791013b015f06a624f521b6ee04ec980893c7e5e01a336203594094f82833d7\
                445fe2d09130f63511da54832de9136b39f4599f5aa5dfbb45da60cdceab7eefde89be63f3f7c0d2324847\
                cce1405def7c469b0e272494e5df54f568656cb9c8818d92b72b8bc34db7bb3112487e746eefe4e808bbb2\
                87d99bf07d00dabededc5e5f074ffeae0cba7da3a516c173be1c513323e119f635e8209a074b216b7023fa\
                dc2d25949c90037e71e3e550726d210a2c688342e52440635e9cc14afe10102621a9c9accb782e9e4a5fa8\
                7f0a956f5b").unwrap();
                let tx: Result<Transaction, _> = deserialize(&hex_tx);
                assert!(tx.is_ok());
                let realtx = tx.unwrap();
                //println!("tx: {:?}",  realtx);
                assert_eq!(realtx.header, TxHeader::FourthAndOverwintered);
                assert_eq!(realtx.version_group_id,
                    Cursor::new(&"85202f89".from_hex().unwrap()).read_u32::<LittleEndian>().unwrap());
                assert_eq!(realtx.lock_time,
                    Cursor::new(&"481cdd86".from_hex().unwrap()).read_u32::<LittleEndian>().unwrap());
                assert_eq!(realtx.expiry_height,
                    Cursor::new(&"b3cc4318".from_hex().unwrap()).read_u32::<LittleEndian>().unwrap());
                assert_eq!(realtx.value_balance,
                    Cursor::new(&"442117623ceb0500".from_hex().unwrap()).read_i64::<LittleEndian>().unwrap());
                assert_eq!(realtx.input.len(), 0);
                assert_eq!(realtx.output.len(), 2);
                assert_eq!(serialize(&realtx.output[0]).unwrap(),
                    "e7719811893e0000095200ac6551ac636565".from_hex().unwrap());
                assert_eq!(serialize(&realtx.output[1]).unwrap(),
                    "b2835a0805750200025151".from_hex().unwrap());
                assert_eq!(realtx.shielded_spend.len(), 3);
                assert_eq!(serialize(&realtx.shielded_spend[0]).unwrap(),
                    "1b3d1a027c2c40590958b7eb13d742a997738c46a458965baf276ba92f272c72\
                     1fe01f7e9c8e36d6a5e29d4e30a73594bf5098421c69378af1e40f64e125946f\
                     62c2fa7b2fecbcb64b6968912a6381ce3dc166d56a1d62f5a8d7551db5fd9313\
                     e8c7203d996af7d477083756d59af80d06a745f44ab023752cb5b406ed8985e1\
                     8130ab33362697b0e4e4c763ccb8f676495c222f7fba1e31defa3d5a57efc2e1e9b01a035587d5fb1\
                        a38e01d94903d3c3e0ad3360c1d3710acd20b183e31d49f25c9a138f49b1a537edcf04be34a985\
                        1a7af9db6990ed83dd64af3597c04323ea51b0052ad8084a8b9da948d320dadd64f5431e61ddf6\
                        58d24ae67c22c8d1309131fc00fe7f235734276d38d47f1e191e00c7a1d48af046827591e9733a\
                        97fa6b679f3dc601d008285edcbdae69ce8fc1be4aac00ff2711ebd931de518856878\
                    f73476f21a482ec9378365c8f7393c94e2885315eb4671098b79535e790fe53e29fef2b3766697ac32\
                        b4f473f468a008e72389fc03880d780cb07fcfaabe3f1a
                     ".from_hex().unwrap());
                 assert_eq!(serialize(&realtx.shielded_spend[1]).unwrap(),
                     "15825b7acb4d6b57a61bc68f242b52e4fbf85cf1a09cc45b6d6bb3a391578f49\
                      9486a7afd04a0d9c74c2995d96b4de37b36046a1ef6d190b916b1111c9288731\
                      1a20da8aba18d1dbebbc862ded42435e92476930d069896cff30eb414f727b89\
                      e001afa2fb8dc3436d75a4a6f26572504b192232ecb9f0c02411e52596bc5e90\
                      457e745939ffedbd12863ce71a02af117d417adb3d15cc54dcb1fce467500c6b8fb86b12b56da9c3\
                        82857deecc40a98d5f2935395ee4762dd21afdbb5d47fa9a6dd984d567db2857b927b7fae2db58\
                        7105415d4642789d38f50b8dbcc129cab3d17d19f3355bcf73cecb8cb8a5da01307152f13936a2\
                        70572670dc82d39026c6cb4cd4b0f7f5aa2a4f5a5341ec5dd715406f2fdd2afa733f5f641c8c21\
                        862a1bafce2609d9eecfa158cfb5cd79f88008e315dc7d8388e76c1782fd2795d18a76\
                     3624c25fa959cc97489ce75745824b77868c53239cfbdf73caec65604037314faaceb56218c6bd30f\
                        8374ac13386793f21a9fb80ad03bc0cda4a44946c00e1b1
                      ".from_hex().unwrap());
                  assert_eq!(serialize(&realtx.shielded_spend[2]).unwrap(),
                      "02c78f11876b7065212183199fb5979ca77d2c24c738fe5145f02602053bb4c2\
                       f6556df6ed4b4ddd3d9a69f53357d7767f4f5ccbdbc596631277f8fecd08cb05\
                       6b95e3025b9792fff7f244fc716269b926d62e9596fa825c6bf21aff9e68625a\
                       192440ea06828123d97884806f15fa08da52754a1095e3ff1abd5ce4fddfccfc\
                       3a6128aef784a64610a89d1a7099216d0814d3a2d452431c32d411ac1cce82ad0229407bbc48985\
                         675e3f874a4533f1d63a84dfa3e0f460fe2f57e34fbc75423c3737f5b2a0615f5722db041a3ef\
                         66fa483afd3c2e19e59444a64add6df1d963f5dd5b5010d3d025f0287c4cf19c75f33d51ddddb\
                         a5d657b43ee8da645443814cc7329f3e9b4e54c236c29af3923101756d9fa4bd0f7d2ddaacb6b\
                         0f86a2658e0a07a05ac5b950051cd24c47a88d13d659ba2a46ca1830816d09cd7646f76f71\
                      6abec5de07fe9b523410806ea6f288f8736c23357c85f45791e1708029d9824d90704607f387a03e4\
                        9bf9836574431345a7877efaa8a08e73081ef8d62cb780a
                       ".from_hex().unwrap());
                   assert_eq!(realtx.shielded_output.len(), 1);
                   assert_eq!(serialize(&realtx.shielded_output[0]).unwrap(),
                       "0fa3207ee2f0408097d563da1b2146819edf88d33e7753664fb71d122a6e3699\
                        8fbd467f75b780149ae8808f4e68f50c0536acddf6f1aeab016b6bc1ec144b4e\
                        59aeb77eef49d00e5fbb67101cdd41e6bc9cf641a52fca98be915f8440a410d7\
                        4cb30e15914f01bc6bc2307b488d2556d7b7380ea4ffd712f6b02fe806b94569cd4059f396bf29\
                            b99d0a40e5e1711ca944f72d436a102fca4b97693da0b086fe9d2e7162470d02e0f05d4bec\
                            9512bfb3f38327296efaa74328b118c27402c70c3a90b49ad4bbc68e37c0aa7d9b3fe17799\
                            d73b841e751713a02943905aae0803fd69442eb7681ec2a05600054e92eed555028f21b6a1\
                            55268a2dd6640a69301a52a38d4d9f9f957ae35af7167118141ce4c9be0a6a492fe79f1581\
                            a155fa3a2b9dafd82e650b386ad3a08cb6b83131ac300b0846354a7eef9c410e4b62c47c54\
                            26907dfc6685c5c99b7141ac626ab4761fd3f41e728e1a28f89db89ffdeca364dd2f0f0739\
                            f0534556483199c71f189341ac9b78a269164206a0ea1ce73bfb2a942e7370b247c046f8e7\
                            5ef8e3f8bd821cf577491864e20e6d08fd2e32b555c92c661f19588b72a89599710a880612\
                            53ca285b6304b37da2b5294f5cb354a894322848ccbdc7c2545b7da568afac87ffa005c312\
                            241c2d57f4b45d6419f0d2e2c5af33ae243785b325cdab95404fc7aed70525cddb41872cfc\
                            c214b13232edc78609753dbff930eb0dc156612b9cb434bc4b693392deb87c530435312edc\
                            edc6a961133338d786c4a3e103f60110a16b1337129704bf4754ff6ba9fbe65951e610620f\
                            71cda8fc877625f2c5bb04cbe1228b1e886f4050afd8fe94e97d2e9e85c6bb748c0042d324\
                            9abb1342bb0eebf62058bf3de080d94611a3750915b5dc6c0b3899d41222bace760ee9c881\
                            8ded599e34c56d7372af1eb86852f2a732104bdb750739\
                       de6c2c6e0f9eb7cb17f1942bfc9f4fd6ebb6b4cdd4da2bca26fac4578e9f543405acc7d86ff5915\
                            8bd0cba3aef6f4a8472d144d99f8b8d1dedaa9077d4f01d4bb27bbe31d88fbefac3dcd4797\
                            563a26b\
                       1d61fcd9a464ab21ed550fe6fa09695ba0b2f10eea6468cc6e20a66f826e3d14c5006f0563887f5\
                            e1289be1b2004caca8d3f34d6e84bf59c1e04619a7c23a996941d889e4622a9b9b1d59d5e3\
                            19094318cd405ba27b7e2c084762d31453ec4549a4d97729d033460fcf89d6494f2ffd789e\
                            98082ea5ce9534b3acd60fe49e37e4f666931677319ed89f85588741b3128901a93bd78e4b\
                            e0225a9e2692c77c969ed0176bdf9555948cbd5a332d045de6ba6bf4490adfe7444cd467a0\
                            9075417fc
                        ".from_hex().unwrap());
                    assert_eq!(realtx.join_split.len(), 2);
                    assert_eq!(serialize(&realtx.join_split[0]).unwrap(),
                        "0000000000000000\
                         0000000000000000\
                         062e49f008c51ad4227439c1b4476ccd8e97862dab7be1e8d399c05ef27c6e22\
                         ee273e15786e394c8f1be31682a30147963ac8da8d41d804258426a3f70289b8\
                            ad19d8de13be4eebe3bd4c8a6f55d6e0c373d456851879f5fbc282db9e134806\
                         bff71e11bc33ab75dd6ca067fb73a043b646a7cf39cab4928386786d2f24141e\
                            e120fdc34d6764eafc66880ee0204f53cc1167ed20b43a52dea3ca7cff8ef35c\
                         d8e6d7c111a68ef44bcd0c1513ad47ca61c659cc5d325b440f6b9f59aff66879\
                         bb6688fd2859362b182f207b3175961f6411a493bffd048e7d0d87d82fe6f990\
                         a2b0a25f5aa0111a6e68f37bf6f3ac2d26b84686e569d58d99c1383597fad811\
                            93c4c1b16e6a90e2d507cdfe6fbdaa86163e9cf5de3100fbca7e8da047b090db\
                         9f37952fbfee76af61668190bd52ed490e677b515d014384af07219c7c0ee7fc7bfc79f325644\
                            e4df4c0d7db08e9f0bd024943c705abff8994bfa605cfbc7ed746a7d3f7c37d9e8bdc433b7\
                            d79e08a12f738a8f0dbddfef2f2657ef3e47d1b0fd11e6a13311fb799c79c641d9da43b33e\
                            7ad012e28255398789262275f1175be8462c01491c4d842406d0ec4282c9526174a09878fe\
                            8fdde33a29604e5e5e7b2a025d6650b97dbb52befb59b1d30a57433b0a351474444099daa3\
                            71046613260\
                        cf3354cfcdada663ece824ffd7e44393886a86165ddddf2b4c41773554c86995269408b11e6737\
                            a4c447586f69173446d8e48bf84cbc000a807899973eb93c5e819aad669413f8387933ad15\
                            84aa35e43f4ecd1e2d0407c0b1b89920ffdfdb9bea51ac95b557af71b89f903f5d9848f14f\
                            cbeb1837570f544d6359eb23faf38a0822da36ce426c4a2fbeffeb0a8a2e297a9d19ba1502\
                            4590e3329d9fa9261f9938a4032dd34606c9cf9f3dd33e576f05cd1dd6811c6298757d77d9\
                            e810abdb226afcaa4346a6560f8932b3181fd355d5d391976183f8d99388839632d6354f66\
                            6d09d3e5629ea19737388613d38a34fd0f6e50ee5a0cc9677177f50028c141378187bd2819\
                            403fc534f80076e9380cb4964d3b6b45819d3b8e9caf54f051852d671bf8c1ffde2d151075\
                            6418cb4810936aa57e6965d6fb656a760b7f19adf96c173488552193b147ee58858033dac7\
                            cd0eb204c06490bbdedf5f7571acb2ebe76acef3f2a01ee987486dfe6c3f0a5e234c127258\
                            f97a28fb5d164a8176be946b8097d0e317287f33bf9c16f9a545409ce29b1f4273725fc0df\
                            02a04ebae178b3414fb0a82d50deb09fcf4e6ee9d180ff4f56ff3bc1d3601fc2dc90d814c3\
                            256f4967d3a8d64c83fea339c51f5a8e5801fbb97835581b602465dee04b5922c2761b5424\
                            5bec0c9eef2db97d22b2b3556cc969fbb13d06509765a52b3fac54b93f421bf08e18d52ddd\
                            52cc1c8ca8adfaccab7e5cc2f4573fbbf8239bb0b8aedbf8dad16282da5c9125dba1c059d0\
                            df8abf621078f02d6c4bc86d40845ac1d59710c45f07d585eb48b32fc0167ba256e73ca3b9\
                            311c62d1094979\
                        57d8dbe10aa3e866b40c0baa2bc492c19ad1e6372d9622bf163fbffeaeee796a3cd9b6fbbfa4d7\
                            92f34d7fd6e763cd5859dd26833d21d9bc5452bd19515dff9f4995b35bc0c1f876e6ad11f2\
                            452dc9ae85aec01fc56f8cbfda75a7727b75ebbd6bbffb43b63a3b1b671e40feb0db002974\
                            a3c3b1a788567231bf6399ff89236981149d423802d2341a3bedb9ddcbac1fe7b6435e1479\
                            c72e7089d029e7fbbaf3cf37e9b9a6b776791e4c5e6fda57e8d5f14c8c35a2d270846b9dbe\
                            005cda16af4408f3ab06a916eeeb9c9594b70424a4c1d171295b6763b22f47f80b53ccbb90\
                            4bd68fd65fbd3fbdea1035e98c21a7dbc91a9b5bc7690f05ec317c97f8764eb48e911d428e\
                            c8d861b708e8298acb62155145155ae95f0a1d1501034753146e22d05f586d7f6b4fe12dad\
                            9a17f5db70b1db96b8d9a83edadc966c8a5466b61fc998c31f1070d9a5c9a6d268d304fe6b\
                            8fd3b4010348611abdcbd49fe4f85b623c7828c71382e1034ea67bc8ae97404b0c50b2a04f\
                            559e49950afcb0ef462a2ae024b0f0224dfd73684b88c7fbe92d02b68f759c4752663cd7b9\
                            7a14943649305521326bde085630864629291bae25ff8822a14c4b666a9259ad0dc42a8290\
                            ac7bc7f53a16f379f758e5de750f04fd7cad47701c8597f97888bea6fa0bf2999956fbfd0e\
                            e68ec36e4688809ae231eb8bc4369f5fe1573f57e099d9c09901bf39caac48dc11956a8ae9\
                            05ead86954547c448ae43d315e669c4242da565938f417bf43ce7b2b30b1cd4018388e1a91\
                            0f0fc41fb0877a5925e466819d375b0a912d4fe843b76ef6f223f0f7c894f38f7ab780dfd7\
                            5f669c8c06cffa\
                         ".from_hex().unwrap());

                    assert_eq!(serialize(&realtx.join_split[1]).unwrap(),
                       "0000000000000000\
                        0000000000000000\
                        43eb47565a50e3b1fa45ad61ce9a1c4727b7aaa53562f523e73952bbf33d8a41\
                        04078ade3eaaa49699a69fdf1c5ac7732146ee5e1d6b6ca9b9180f964cc9d087\
                            8ae1373524d7d510e58227df6de9d30d271867640177b0f1856e28d5c8afb095\
                        ef6184fed651589022eeaea4c0ce1fa6f085092b04979489172b3ef8194a798d\
                            f5724d6b05f1ae000013a08d612bca8a8c31443c10346dbf61de8475c0bbec51\
                        04b47556af3d514458e2321d146071789d2335934a680614e83562f82dfd405b\
                        54a45eb32c165448d4d5d61ca2859585369f53f1a137e9e82b67b8fdaf01bda5\
                        4a317311896ae10280a032440c420a421e944d1e952b70d5826cd3b08b7db963\
                            0fe4fd5f22125de840fcc40b98038af11d55be25432597b4b65b9ec1c7a8bbfd\
                        052cbf7e1c1785314934b262d5853754f1f17771cfb7503072655753fa3f54ecc587e9f83b5819\
                            16092df26e63e18994cb0db91a0bbdc7b6119b32222adf5e61d8d8ae89dae4954b54813bb3\
                            3f08d562ba513fee1b09c0fcd516055419474dd7fda038a89c84ea7b9468287f0eb0c10c4b\
                            132520194d3d8d5351fc10d09c15c8cc101aa1663bbf17b84111f38bb439f07353bdea3596\
                            d15e713e1e2e7d3f1c383135b47fa7f81f46df7a902a404699ec912f5656c35b85763e4de5\
                            83aecaa1df\
                        d5d2677d9c8ffee877f63f40a5ca0d67f6e554124739f805af876aeede53aa8b0f8e5604a73c30\
                            cbd09dad963d6f8a5dcc40def40797342113ba206fae8ebe4f3bc3caf69259e462eff9ba8b\
                            3f4bfaa1300c26925a8729cd32915bfc966086f0d5560bbe32a598c22adfb48cef72ba5d42\
                            87c0cefbacfd8ce195b4963c34a94bba7a175dae4bbe3ef4863d53708915090f47a068e227\
                            433f9e49d3aa09e356d8d66d0c0121e91a3c4aa3f27fa1b63396e2b41db908fdab8b18cc73\
                            04e94e970568f9421c0dbbbaf84598d972b0534f48a5e52670436aaa776ed2482ad7034302\
                            01e53443c36dcfd34a0cb6637876105e79bf3bd58ec148cb64970e3223a91f71dfcfd5a04b\
                            667fbaf3d4b3b908b9828820dfecdd753750b5f9d2216e56c615272f854464c0ca4b1e85ae\
                            dd038292c4e1a57744ebba010b9ebfbb011bd6f0b78805025d27f3c17746bae116c15d9f47\
                            1f0f6288a150647b2afe9df7cccf01f5cde5f04680bbfed87f6cf429fb27ad6babe7917666\
                            11cf5bc20e48bef119259b9b8a0e39c3df28cb9582ea338601cdc481b32fb82adeebb3dade\
                            25d1a3df20c37e712506b5d996c49a9f0f30ddcb91fe9004e1e83294a6c9203d94e8dc2cbb\
                            449de4155032604e47997016b304fd437d8235045e255a19b743a0a9f2e336b44cae307bb3\
                            987bd3e4e777fbb34c0ab8cc3d67466c0a88dd4ccad18a07a8d1068df5b629e5718d0f6df5\
                            c957cf71bb00a5178f175caca944e635c5159f738e2402a2d21aa081e10e456afb00b9f624\
                            16c8b9c0f7228f510729e0be3f305313d77f7379dc2af24869c6c74ee4471498861d192f0f\
                            f0f508285dab6b\
                        6a36ccf7d12256cc76b95503720ac672d08268d2cf7773b6ba2a5f664847bf707f2fc10c98f2f0\
                            06ec22ccb5a8c8b7c40c7c2d49a6639b9f2ce33c25c04bc461e744dfa536b00d94baddf4f4\
                            d14044c695a33881477df124f0fcf206a9fb2e65e304cdbf0c4d2390170c130ab849c2f22b\
                            5cdd3921640c8cf1976ae1010b0dfd9cb2543e45f99749cc4d61f2e8aabfe98bd905fa3995\
                            1b33ea769c45ab9531c57209862ad12fd76ba4807e65417b6cd12fa8ec916f013ebb8706a9\
                            6effeda06c4be24b04846392e9d1e6930eae01fa21fbd700583fb598b92c8f4eb8a61aa623\
                            5db60f2841cf3a1c6ab54c67066844711d091eb931a1bd6281aedf2a0e8fab18817202a9be\
                            06402ed9cc720c16bfe881e4df4255e87afb7fc62f38116bbe03cd8a3cb11a27d568414782\
                            f47b1a44c97c680467694bc9709d32916c97e8006cbb07ba0e4180a3738038c374c4cce8f3\
                            2959afb25f303f5815c4533124acf9d18940e77522ac5dc4b9570aae8f47b7f57fd8767bea\
                            1a24ae7bed65b4afdc8f1278c30e2db98fd172730ac6bbed4f1127cd32b04a95b205526cfc\
                            b4c4e1cc955175b3e8de1f5d81b18669692350aaa1a1d797617582e54d7a5b57a683b32fb1\
                            098062dad7b0c2eb518f6862e83db25e3dbaf7aed504de932acb99d735992ce62bae9ef893\
                            ff6acc0ffcf8e3483e146b9d49dd8c7835f43a37dca0787e3ec9f6605223d5ba7ae0ab9025\
                            b73bc03f7fac36c009a56d4d95d1e81d3b3ebca7e54cc1a12d127b57c8138976e791013b01\
                            5f06a624f521b6ee04ec980893c7e5e01a336203594094f82833d7445fe2d09130f63511da\
                            54832de9136b39\
                          ".from_hex().unwrap());
                      assert_eq!(serialize(&realtx.join_split_pubkey.clone().unwrap()).unwrap(),
                        "f4599f5aa5dfbb45da60cdceab7eefde89be63f3f7c0d2324847cce1405def7c"
                        .from_hex().unwrap());
                      assert_eq!(serialize(&realtx.join_split_sig.clone().unwrap()).unwrap(),
                          "469b0e272494e5df54f568656cb9c8818d92b72b8bc34db7bb3112487e746eefe4e808bbb28\
                                7d99bf07d00dabededc5e5f074ffeae0cba7da3a516c173be1c51"
                            .from_hex().unwrap());
                      assert_eq!(serialize(&realtx.binding_sig.clone().unwrap()).unwrap(),
                          "3323e119f635e8209a074b216b7023fadc2d25949c90037e71e3e550726d210a2c688342e52\
                                440635e9cc14afe10102621a9c9accb782e9e4a5fa87f0a956f5b"
                            .from_hex().unwrap());

                    assert_eq!(realtx.hash_prevouts().as_bytes().to_vec(),
                        "d53a633bbecf82fe9e9484d8a0e727c73bb9e68c96e72dec30144f6a84afa136"
                        .from_hex().unwrap());

                    assert_eq!(realtx.hash_sequence().as_bytes().to_vec(),
                        "a5f25f01959361ee6eb56a7401210ee268226f6ce764a4f10b7f29e54db37272"
                        .from_hex().unwrap());

                    assert_eq!(realtx.hash_outputs().as_bytes().to_vec(),
                        "ab6f7f6c5ad6b56357b5f37e16981723db6c32411753e28c175e15589172194a"
                        .from_hex().unwrap());

                    assert_eq!(realtx.hash_join_splits().as_bytes().to_vec(),
                        "67d37848addb5173bd2df213b14b4747dc9f357e15a12556837ff8f45a972da1"
                        .from_hex().unwrap());

                    assert_eq!(realtx.hash_shielded_spends().as_bytes().to_vec(),
                        "3012a695042e5b9c9bb234037b006ec954db1f07ff055036966f7518aba9e914"
                        .from_hex().unwrap());

                    assert_eq!(realtx.hash_shielded_outputs().as_bytes().to_vec(),
                        "70b02d2877233c22690b7c6f08fdfe777c13f4b29315f40ad3ecaeec8b1cad1f"
                        .from_hex().unwrap());

                    assert_eq!(realtx.signature_hash(0, &Script::new(), 1, 1, 0).as_bytes().to_vec(),
                        "9d22cdd88b921232e158b91a07c0e93251f01b4d7d1340450d0c802c1479f199"
                        .from_hex().unwrap());
        }

        #[test]
        /// https://github.com/zcash/zips/blob/master/zip-0243.rst#test-vector-2
        fn test_sig_check_vector_2() {
            let hex_tx = hex_bytes("0400008085202f890256e551406a7ee8355656a21e43e38ce129fdadb759ed\
                dfa08f00fc8e567cef93c6792d010763656300ac63ac8df042451a33590d3e8cf49b2627218f0c292f\
                a66ada945fa55bb23548e33a83a562957a3149a993086a5352516a65006a78d97ce402e91cb65a63b7\
                010009516a6a656aac6365655cc7c9aae5bd030002636a675cb83e43e29c1744b8b5b99ce3050003b0\
                f5b874a6ecabe6c56ee58b67d02f5d47db8cc3458435d5088d69b2240c28f371c012c415d2382a6eeb\
                c8b3db07ea1cbf28288daaa91538de4552eeeef72c24c85d83db20efad48be8996fb1bff591efff360\
                fe1199056c56e5feec61a7b8b9f699d6012c2849232f329fef95c7af370098ffe4918e0ca1df47f275\
                867b739e0a514d3209325e217045927b479c1ce2e5d54f25488cad1513e3f44a21266cfd841633327d\
                ee6cf810fbf7393e317d9e53d1be1d5ae7839b66b943b9ed18f2c530e975422332c3439cce49a29f2a\
                336a4851263c5e9bd13d731109e844b7f8c392a5c1dcaa2ae5f50ff63fab9765e016702c35a67cd736\
                4d3fab552fb349e35c15c50250453fd18f7b855992632e2c76c0fbf1ef963ea80e3223de3277bc5592\
                51725829ec03f213ba8955cab2822ff21a9b0a4904d668fcd77224bde3dd01f6ffc4828f6b64230b35\
                c6a049873494276ea1d7ed5e92cb4f90ba83a9e49601b194042f2900d99d312d7b70508cf176066d15\
                4dbe96ef9d4367e4c840e4a17b5e26bca7fdd7cc43201c56f468fadc42cff0d81a966417ad8f097ebf\
                3b25879e55c23e34da91c816d8d1790dfe34bdce040db1727af24d59ef78d3f4aac2b59822d6f12f24\
                fd364496b3be0871ca3dd9625348a614b59bde45885649bae36de34def8fcec85343475d976ae1e9b2\
                7829ce2ac5efd0b399a8b448be6504294ee6b3c1c6a5342d7c01ae9d8ad3070c2b1a91573af5e0c5e4\
                cbbf4acdc6b54c9272200d9970250c17c1036f06085c41858ed3a0c48150bc697e4a695fef335f7ad0\
                7e1a46dc767ff822db70e6669080b9816b2232c81a4c66cc586abfe1eaa8ca6cf41fc3c3e6c7b886fb\
                6dac9f4822b4fc6fff9d0513d61a21c80a377671d135a668a0ae2bb934c82c4142da69d12ca7de9a7d\
                f706400ec79878d868e17e8f71ea31495af819a016cc419e07c501aa8309b2e6c85b79b2763733a37b\
                bc0420d42537b871b4294a65d3e055ff718dd9dc8c75e7e5b2efe442637371b7c48f6ee99e3ea38a4b\
                0f2f67fc2b908cda657eae754e037e262e9a9f9bd7ec4267ed8e96930eeb89a85980f97d7faaed78d8\
                f38beb624b774c73a46ced614be219b3d94873b60df7fc90b579abf62037975edd6aacc442190a0ba5\
                5b15f81f86bade794ace2a9d9a816baf728a955b960b7701fa626687dc3c9cba646337b53e29816e94\
                82ddf5578a8768aae477fce410ac2d5de6095861c111d7feb3e6bb4fbb5a54955495972798350a253f\
                05f66c2ecfcbc0ed43f5ec2e6d8dba15a51254d97b1821107c07dd9a16ef8406f943e282b95d4b3625\
                30c913d6ba421df6027de5af1e4745d5868106954be6c1962780a2941072e95131b1679df063762504\
                2c37d48ffb152e5ebc185c8a2b7d4385f1c95af937df78dfd8757fab434968b0b57c66574468f160b4\
                47ac8221e5060676a842a1c6b7172dd3340f764070ab1fe091c5c74c95a5dc043390723a4c127da14c\
                dde1dc2675a62340b3e6afd0522a31de26e7d1ec3a9c8a091ffdc75b7ecfdc7c12995a5e37ce3488bd\
                29f8629d68f696492448dd526697476dc061346ebe3f677217ff9c60efce943af28dfd3f9e59692598\
                a6047c0000c01400f1ab5730eac0ae8d5843d5051c376240172af218d7a1ecfe65b4f75100638983c1\
                4de4974755dade8018c9b8f4543fb095961513e67c61dbc59c607f9b").unwrap();
                let tx: Result<Transaction, _> = deserialize(&hex_tx);
                assert!(tx.is_ok());
                let realtx = tx.unwrap();
                //println!("tx: {:?}",  realtx);
                assert_eq!(realtx.header, TxHeader::FourthAndOverwintered);
                assert_eq!(realtx.version_group_id,
                    Cursor::new(&"85202f89".from_hex().unwrap()).read_u32::<LittleEndian>().unwrap());
                assert_eq!(realtx.lock_time,
                    Cursor::new(&"675cb83e".from_hex().unwrap()).read_u32::<LittleEndian>().unwrap());
                assert_eq!(realtx.expiry_height,
                    Cursor::new(&"43e29c17".from_hex().unwrap()).read_u32::<LittleEndian>().unwrap());
                assert_eq!(realtx.value_balance,
                    Cursor::new(&"44b8b5b99ce30500".from_hex().unwrap()).read_i64::<LittleEndian>().unwrap());
                assert_eq!(realtx.input.len(), 2);
                assert_eq!(serialize(&realtx.input[0]).unwrap(),
                    "56e551406a7ee8355656a21e43e38ce129fdadb759eddfa08f00fc8e567cef93\
                    c6792d01\
                    0763656300ac63ac\
                    8df04245"
                    .from_hex().unwrap());
                assert_eq!(serialize(&realtx.input[1]).unwrap(),
                    "1a33590d3e8cf49b2627218f0c292fa66ada945fa55bb23548e33a83a562957a\
                    3149a993\
                    086a5352516a65006a\
                    78d97ce4"
                    .from_hex().unwrap());
                assert_eq!(realtx.output.len(), 2);
                assert_eq!(serialize(&realtx.output[0]).unwrap(),
                    "e91cb65a63b7010009516a6a656aac636565".from_hex().unwrap());
                    assert_eq!(serialize(&realtx.output[1]).unwrap(),
                        "5cc7c9aae5bd030002636a".from_hex().unwrap());
                assert_eq!(realtx.shielded_spend.len(), 3);
                assert_eq!(realtx.shielded_output.len(), 0);
                assert_eq!(realtx.join_split.len(), 0);
                assert_eq!(realtx.join_split_pubkey.clone(), None);
                assert_eq!(realtx.join_split_sig.clone(), None);
                assert_eq!(serialize(&realtx.binding_sig.clone().unwrap()).unwrap(),
                  "c01400f1ab5730eac0ae8d5843d5051c376240172af218d7a1ecfe65b4f75100638983c14de4974\
                    755dade8018c9b8f4543fb095961513e67c61dbc59c607f9b"
                    .from_hex().unwrap());

                assert_eq!(realtx.hash_prevouts().as_bytes().to_vec(),
                    "8929386726e262b1136559f209042854930ffc0d191e4c47ea75801409b0658b"
                    .from_hex().unwrap());

                assert_eq!(realtx.hash_shielded_spends().as_bytes().to_vec(),
                    "3937e4360cebab36ddfe34c520e4cf58b8ef99d6fcd2767e438550221001c79b"
                    .from_hex().unwrap());

                assert_eq!(realtx.signature_hash(0,
                                                 &Script::from([1, 0].to_vec()),
                                                 2,
                                                 0,
                                                 Cursor::new(&"9628edf980ad0500".from_hex()
                                                    .unwrap()).read_u64::<LittleEndian>()
                                                    .unwrap()
                                                ).as_bytes().to_vec(),
                    "2a3aaa9a36355bfc74f8fd576a446837ad009f8e1289ec60ed3f57b89b57951a"
                    .from_hex().unwrap());
        }
}
