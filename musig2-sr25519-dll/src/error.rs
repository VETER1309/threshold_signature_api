use std::str::Utf8Error;

use hex::FromHexError;
use mast::error::MastError;
use schnorrkel::SignatureError;

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

impl From<SignatureError> for Error {
    fn from(_e: SignatureError) -> Self {
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
            Error::InvalidPhrase => "Invalid Phrase".to_owned(),
        }
    }
}
