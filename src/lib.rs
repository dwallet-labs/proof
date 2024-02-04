// Author: dWallet Labs, LTD.
// SPDX-License-Identifier: BSD-3-Clause-Clear
pub mod aggregation;
pub mod range;

/// Proof error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid parameters")]
    InvalidParameters,

    #[error("an internal error that should never have happened and signifies a bug")]
    InternalError,

    #[error("serialization/deserialization error")]
    Serialization(#[from] serde_json::Error),

    #[error("invalid proof - did not satisfy the verification equation")]
    ProofVerification,

    #[error("group error")]
    GroupInstantiation(#[from] group::Error),

    #[error("at least one of the witnesses is out of range")]
    OutOfRange,
}

/// Proof result.
pub type Result<T> = std::result::Result<T, Error>;
