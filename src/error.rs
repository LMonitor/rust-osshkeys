use failure::{Backtrace, Error as FailureError, Fail};
use std::fmt::{Debug, Display, Formatter, Result as FmtResult};

pub type OsshResult<T> = Result<T, Error>;

pub struct Error {
    kind: ErrorKind,
    inner: Option<FailureError>,
    bt: Backtrace,
}

impl Error {
    pub(crate) fn from_kind(kind: ErrorKind) -> Self {
        Error {
            kind,
            inner: None,
            bt: Backtrace::new(),
        }
    }

    pub(crate) fn with_failure<F: Fail>(kind: ErrorKind, failure: F) -> Self {
        Error {
            kind,
            inner: Some(failure.into()),
            bt: Backtrace::new(),
        }
    }
}

impl Debug for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "OsshError {{\n")?;
        write!(f, "Kind: {:?} => \"{}\"", self.kind, self.kind)?;
        if let Some(cause) = &self.inner {
            write!(f, "\nCaused: {:?}", cause)?;
        }
        write!(f, "\nBackTrace: \n{:?}", self.bt)?;
        write!(f, "\n}}")
    }
}

impl Display for Error {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.kind)?;
        if let Some(cause) = &self.inner {
            write!(f, "; Caused by: {}", cause)?;
        }
        Ok(())
    }
}

impl Fail for Error {
    fn name(&self) -> Option<&str> {
        Some("Osshkeys Error")
    }

    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.as_ref().map(|f| f.as_fail())
    }

    fn backtrace(&self) -> Option<&Backtrace> {
        Some(&self.bt)
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Self {
        Self::from_kind(kind)
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Self::with_failure(ErrorKind::IOError, err)
    }
}
impl From<std::fmt::Error> for Error {
    fn from(err: std::fmt::Error) -> Self {
        Self::with_failure(ErrorKind::FmtError, err)
    }
}
impl From<openssl::error::ErrorStack> for Error {
    fn from(err: openssl::error::ErrorStack) -> Self {
        Self::with_failure(ErrorKind::OpenSslError, err)
    }
}
impl From<ed25519_dalek::SignatureError> for Error {
    fn from(err: ed25519_dalek::SignatureError) -> Self {
        Self::with_failure(ErrorKind::Ed25519Error, err)
    }
}
impl From<base64::DecodeError> for Error {
    fn from(err: base64::DecodeError) -> Self {
        Self::with_failure(ErrorKind::Base64Error, err)
    }
}
impl From<block_modes::InvalidKeyIvLength> for Error {
    fn from(err: block_modes::InvalidKeyIvLength) -> Self {
        Self::with_failure(ErrorKind::InvalidKeyIvLength, err)
    }
}
impl From<nom_pem::PemParsingError> for Error {
    fn from(_err: nom_pem::PemParsingError) -> Self {
        // nom_pem::PemParsingError doesn't implement std::error::Error
        Self::from_kind(ErrorKind::InvalidPemFormat)
    }
}
impl From<std::array::TryFromSliceError> for Error {
    fn from(err: std::array::TryFromSliceError) -> Self {
        Self::with_failure(ErrorKind::InvalidLength, err)
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ErrorKind {
    OpenSslError,
    Ed25519Error,
    IOError,
    FmtError,
    Base64Error,
    InvalidArgument,
    InvalidKeyFormat,
    InvalidFormat,
    InvalidKey,
    InvalidKeySize,
    InvalidLength,
    UnsupportCurve,
    UnsupportCipher,
    IncorrectPass,
    TypeNotMatch,
    UnsupportType,
    InvalidPemFormat,
    InvalidKeyIvLength,
    Unknown,
}

impl ErrorKind {
    pub fn name(self) -> &'static str {
        use ErrorKind::*;

        match self {
            OpenSslError => "OpenSSL Error",
            Ed25519Error => "Ed25519 Error",
            IOError => "I/O Error",
            FmtError => "Formatter Error",
            Base64Error => "Base64 Error",
            InvalidArgument => "Invalid Argument",
            InvalidKeyFormat => "Invalid Key Format",
            InvalidFormat => "Invalid Format",
            InvalidKey => "Invalid Key",
            InvalidKeySize => "Invalid Key Size",
            InvalidLength => "Invalid Length",
            UnsupportCurve => "Unsupported Elliptic Curve",
            UnsupportCipher => "Unsupported Cipher",
            IncorrectPass => "Incorrect Passphrase",
            TypeNotMatch => "Key Type Not Match",
            UnsupportType => "Unsupported Key Type",
            InvalidPemFormat => "Invalid PEM Format",
            InvalidKeyIvLength => "Invalid Key/IV Length",
            Unknown => "Unknown Error",
        }
    }
}

impl Display for ErrorKind {
    fn fmt(&self, f: &mut Formatter) -> FmtResult {
        write!(f, "{}", self.name())
    }
}
