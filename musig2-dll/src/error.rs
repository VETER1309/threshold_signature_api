use std::{
    ffi::{CString, NulError},
    str::Utf8Error,
};

use hex::FromHexError;

#[derive(Debug)]
pub enum Error {
    // normal error
    NormalError,
    // null pointer errors
    NullKeypair,
    NullRound1State,
    NullRound2State,
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
            Error::NullRound2State => unsafe {
                CString::from_vec_unchecked(b"Null Round2 State Pointer".to_vec()).into_raw()
            },
        }
    }
}
