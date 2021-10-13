use std::{
    ffi::{CString, NulError},
    str::Utf8Error,
};

use hex::FromHexError;
use mast::error::MastError;
use schnorrkel::SignatureError;

pub enum Error {
    NormalError,
    NullMusig,
    EncodeFail,
    InvalidSecretBytes,
    InvalidPublicBytes,
    InvalidCommitBytes,
    IncorrectCommitNum,
    InvalidRevealBytes,
    IncorrectRevealNum,
    InvalidCosignBytes,
    IncorrectCosignNum,
    InvalidSignature,
}

impl From<Utf8Error> for Error {
    fn from(e: Utf8Error) -> Self {
        match e {
            _ => Self::NormalError,
        }
    }
}

impl From<FromHexError> for Error {
    fn from(e: FromHexError) -> Self {
        match e {
            _ => Self::NormalError,
        }
    }
}

impl From<SignatureError> for Error {
    fn from(e: SignatureError) -> Self {
        match e {
            _ => Self::NormalError,
        }
    }
}

impl From<NulError> for Error {
    fn from(e: NulError) -> Self {
        match e {
            _ => Self::NormalError,
        }
    }
}

impl From<MastError> for Error {
    fn from(e: MastError) -> Self {
        match e {
            _ => Self::NormalError,
        }
    }
}

impl From<Error> for *mut i8 {
    fn from(e: Error) -> Self {
        match e {
            Error::NormalError => unsafe {
                CString::from_vec_unchecked(b"Normal Error".to_vec()).into_raw()
            },
            Error::NullMusig => unsafe {
                CString::from_vec_unchecked(b"Null Musig".to_vec()).into_raw()
            },
            Error::InvalidSecretBytes => unsafe {
                CString::from_vec_unchecked(b"Invalid Secret Bytes".to_vec()).into_raw()
            },
            Error::InvalidPublicBytes => unsafe {
                CString::from_vec_unchecked(b"Invalid Public Bytes".to_vec()).into_raw()
            },
            Error::InvalidCommitBytes => unsafe {
                CString::from_vec_unchecked(b"Invalid Commit Bytes".to_vec()).into_raw()
            },
            Error::IncorrectCommitNum => unsafe {
                CString::from_vec_unchecked(b"Invalid Commit Num".to_vec()).into_raw()
            },
            Error::InvalidRevealBytes => unsafe {
                CString::from_vec_unchecked(b"Invalid Reveal Bytes".to_vec()).into_raw()
            },
            Error::IncorrectRevealNum => unsafe {
                CString::from_vec_unchecked(b"Invalid Reveal Num".to_vec()).into_raw()
            },
            Error::InvalidCosignBytes => unsafe {
                CString::from_vec_unchecked(b"Invalid Cosign Bytes".to_vec()).into_raw()
            },
            Error::IncorrectCosignNum => unsafe {
                CString::from_vec_unchecked(b"Invalid Cosign Num".to_vec()).into_raw()
            },
            Error::InvalidSignature => unsafe {
                CString::from_vec_unchecked(b"Invalid Signature".to_vec()).into_raw()
            },
            Error::EncodeFail => unsafe {
                CString::from_vec_unchecked(b"Encode Fail".to_vec()).into_raw()
            },
        }
    }
}
