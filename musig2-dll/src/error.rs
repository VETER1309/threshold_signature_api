use std::{
    ffi::{CString, NulError},
    str::Utf8Error,
};

use hex::FromHexError;
use light_bitcoin::mast::error::MastError;

#[derive(Debug)]
pub enum Error {
    // normal error
    NormalError,
    // null pointer errors
    NullKeypair,
    // null round1 state
    NullRound1State,
    // encode faile
    EncodeFail,
    // invalid secret key
    InvalidSecret,
    // invalid public key
    InvalidPublicBytes,
    // invalid address
    InvalidAddr,
    // invalid tx
    InvalidTransaction,
    // invalid taproot script pubkey
    InvalidTaprootScript,
    // invaild txid
    InvalidTxid,
    // invaild signature
    InvalidSignature,
    // invaild sigversion
    InvalidSigversion,
    // invalid tx input
    InvalidTxInput,
    // invalid tx output
    InvalidTxOutput,
    // compute sighash fail
    ComputeSighashFail,
    // construct tx fail
    ConstructTxFail,
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

impl From<NulError> for Error {
    fn from(_: NulError) -> Self {
        Self::NormalError
    }
}

impl From<MastError> for Error {
    fn from(e: MastError) -> Self {
        Self::NormalError
    }
}

impl From<bitcoin_wallet::error::Error> for Error {
    fn from(_: bitcoin_wallet::error::Error) -> Self {
        Self::InvalidPhrase
    }
}

impl From<Error> for *mut i8 {
    fn from(e: Error) -> Self {
        match e {
            Error::NormalError => unsafe {
                CString::from_vec_unchecked(b"Normal Error".to_vec()).into_raw()
            },
            Error::NullKeypair => unsafe {
                CString::from_vec_unchecked(b"Null KeyPair Pointer".to_vec()).into_raw()
            },
            Error::NullRound1State => unsafe {
                CString::from_vec_unchecked(b"Null Round1 State Pointer".to_vec()).into_raw()
            },
            Error::EncodeFail => unsafe {
                CString::from_vec_unchecked(b"Encode Fail".to_vec()).into_raw()
            },
            Error::InvalidPublicBytes => unsafe {
                CString::from_vec_unchecked(b"Invalid Public Bytes".to_vec()).into_raw()
            },
            Error::InvalidTransaction => unsafe {
                CString::from_vec_unchecked(b"Invalid Transaction".to_vec()).into_raw()
            },
            Error::InvalidTaprootScript => unsafe {
                CString::from_vec_unchecked(b"Invalid Taproot Script Pubkey".to_vec()).into_raw()
            },
            Error::InvalidAddr => unsafe {
                CString::from_vec_unchecked(b"Invalid Address".to_vec()).into_raw()
            },
            Error::InvalidTxid => unsafe {
                CString::from_vec_unchecked(b"Invalid txid".to_vec()).into_raw()
            },
            Error::InvalidSignature => unsafe {
                CString::from_vec_unchecked(b"Invalid Signature".to_vec()).into_raw()
            },
            Error::InvalidSigversion => unsafe {
                CString::from_vec_unchecked(b"Invalid Sigversion".to_vec()).into_raw()
            },
            Error::InvalidTxInput => unsafe {
                CString::from_vec_unchecked(b"Invalid Transaction Input".to_vec()).into_raw()
            },
            Error::InvalidTxOutput => unsafe {
                CString::from_vec_unchecked(b"Invalid Transaction Output".to_vec()).into_raw()
            },
            Error::ComputeSighashFail => unsafe {
                CString::from_vec_unchecked(b"Compute Sighash Fail".to_vec()).into_raw()
            },
            Error::ConstructTxFail => unsafe {
                CString::from_vec_unchecked(b"Construct Transaction Fail".to_vec()).into_raw()
            },
            Error::InvalidSecret => unsafe {
                CString::from_vec_unchecked(b"Construct Secret Key".to_vec()).into_raw()
            },
            Error::InvalidPhrase => unsafe {
                CString::from_vec_unchecked(b"Invalid Phrase".to_vec()).into_raw()
            },
        }
    }
}
