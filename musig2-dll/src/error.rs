use std::str::Utf8Error;

use hex::FromHexError;
use light_bitcoin::mast::error::MastError;

#[derive(Debug)]
#[allow(clippy::enum_variant_names)]
pub enum Error {
    // normal error
    NormalError,
    // null pointer errors
    NullKeypair,
    NullRound1State,
    EncodeFail,
    InvalidPublicBytes,
    // invalid transaction
    InvalidTransaction,
    // invalid txid
    InvalidTxid,
    // invalid tx input
    InvalidTxInput,
    // invalid tx output
    InvalidTxOutput,
    // invalid address
    InvalidAddress,
    // common sighash fail
    ComputeSighashFail,
    // invalid signature
    InvalidSignature,
    // invalid signature version
    InvalidSigversion,
    // construct tx fail
    ConstructTxFail,
    // invalid sevret
    InvalidSecret,
    // invalid phrase
    InvalidPhrase,
}

impl From<Utf8Error> for Error {
    fn from(_: Utf8Error) -> Self {
        Self::NormalError
    }
}

impl From<FromHexError> for Error {
    fn from(_: FromHexError) -> Self {
        Self::NormalError
    }
}

impl From<musig2::Error> for Error {
    fn from(_: musig2::Error) -> Self {
        Self::NormalError
    }
}

impl From<MastError> for Error {
    fn from(_e: MastError) -> Self {
        Self::NormalError
    }
}

impl From<Error> for String {
    fn from(e: Error) -> Self {
        match e {
            Error::NormalError => "Normal Error".to_owned(),
            Error::NullKeypair => "Null KeyPair Pointer".to_owned(),
            Error::NullRound1State => "Null Round1 State Pointer".to_owned(),
            Error::EncodeFail => "Encode Fail".to_owned(),
            Error::InvalidPublicBytes => "Invalid Public Bytes".to_owned(),
            Error::InvalidTransaction => "Invalid Transaction".to_owned(),
            Error::InvalidTxid => "Invalid Txid".to_owned(),
            Error::InvalidTxInput => "Invalid Tx Input".to_owned(),
            Error::InvalidTxOutput => "Invalid Tx Output".to_owned(),
            Error::InvalidAddress => "Invalid Address".to_owned(),
            Error::InvalidSignature => "Invalid Signature".to_owned(),
            Error::ComputeSighashFail => "Compute Sighash Fail".to_owned(),
            Error::InvalidSigversion => "Invalid Signature Version".to_owned(),
            Error::ConstructTxFail => "Construct Tx Fail".to_owned(),
            Error::InvalidSecret => "Invalid Secret".to_owned(),
            Error::InvalidPhrase => "Invalid Phrase".to_owned(),
        }
    }
}
