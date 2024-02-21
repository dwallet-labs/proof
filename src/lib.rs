// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

pub use range::{AggregatableRangeProof, RangeProof};
pub use transcript_protocol::TranscriptProtocol;
mod transcript_protocol;

pub mod aggregation;
pub mod range;

/// Proof error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid parameters")]
    InvalidParameters,

    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,

    #[error("aggregation error")]
    Aggregation(#[from] aggregation::Error),

    #[error("serialization/deserialization error")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid proof: did not satisfy the verification equation")]
    ProofVerification,

    #[error("group error")]
    GroupInstantiation(#[from] group::Error),

    #[error("at least one of the witnesses is out of range")]
    OutOfRange,
}

/// Proof result.
pub type Result<T> = std::result::Result<T, Error>;

impl TryInto<aggregation::Error> for Error {
    type Error = Self;

    fn try_into(self) -> std::result::Result<aggregation::Error, Self::Error> {
        match self {
            Error::Aggregation(e) => Ok(e),
            e => Err(e),
        }
    }
}
