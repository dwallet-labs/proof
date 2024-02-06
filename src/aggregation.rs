// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
//! Proof Aggregation Traits.
//!
//! Each state of the MPC protocol is represented by a different Rust
//! type. The state transitions consume the previous state, making it
//! a compile error to perform the steps out of order or to repeat a
//! step.

use std::collections::HashMap;
use std::fmt::Debug;

use crypto_bigint::rand_core::CryptoRngCore;
use serde::{Deserialize, Serialize};

use group::PartyID;

/// Proof aggregation error.
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(
        "this party was not selected as part of the participating parties in the current session"
    )]
    NonParticipatingParty,

    #[error("parties {:?} participated in the previous round of the session but not in the current", .0)]
    UnresponsiveParties(Vec<PartyID>),

    #[error("parties {:?} sent an invalid decommitment value", .0)]
    InvalidDecommitment(Vec<PartyID>),

    #[error("parties {:?} maliciously attempted to bypass the commitment round by sending decommitment which does not match their commitment", .0)]
    WrongDecommitment(Vec<PartyID>),

    #[error("parties {:?} decommitted on a wrong number of statements", .0)]
    WrongNumberOfDecommittedStatements(Vec<PartyID>),

    #[error("parties {:?} sent an invalid proof share value", .0)]
    InvalidProofShare(Vec<PartyID>),

    #[error("parties {:?} sent a proof share that does not pass verification", .0)]
    ProofShareVerification(Vec<PartyID>),
}

/// Proof aggregation result.
pub type Result<T> = std::result::Result<T, Error>;

/// The commitment round party of a proof aggregation protocol.
pub trait CommitmentRoundParty<Output>: Sized {
    /// Commitment error.
    type Error: Debug + TryInto<Error, Error = Self::Error>;

    /// The output of the commitment round.
    type Commitment: Serialize + for<'a> Deserialize<'a> + Clone;

    /// The round following the commitment round.
    type DecommitmentRoundParty: DecommitmentRoundParty<Output, Commitment = Self::Commitment>;

    /// The commitment round of the proof aggregation protocol.
    /// Receives `self` and not `&self`, to enforce [`Self::DecommitmentRoundParty`] can be instantiated only via a valid state transition.
    fn commit_statements_and_statement_mask(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> std::result::Result<(Self::Commitment, Self::DecommitmentRoundParty), Self::Error>;
}

/// The decommitment round party of a proof aggregation protocol.
pub trait DecommitmentRoundParty<Output>: Sized {
    /// Decommitment error.
    type Error: Debug + TryInto<Error, Error = Self::Error>;

    /// The output of the round preceding the decommitment round.
    type Commitment: Serialize + for<'a> Deserialize<'a> + Clone;
    /// The output of the decommitment round.
    type Decommitment: Serialize + for<'a> Deserialize<'a> + Clone;
    /// The round following the decommitment round.
    type ProofShareRoundParty: ProofShareRoundParty<Output, Decommitment = Self::Decommitment>;

    /// The decommitment round of the proof aggregation protocol.
    /// Receives `self` and not `&self`, to enforce [`Self::ProofShareRoundParty`] can be instantiated only via a valid state transition.
    /// Receives `commitments` the outputs of the preceding round from all parties.
    fn decommit_statements_and_statement_mask(
        self,
        commitments: HashMap<PartyID, Self::Commitment>,
        rng: &mut impl CryptoRngCore,
    ) -> std::result::Result<(Self::Decommitment, Self::ProofShareRoundParty), Self::Error>;
}

/// The proof share round party of a proof aggregation protocol.
pub trait ProofShareRoundParty<Output>: Sized {
    /// Proof share error.
    type Error: Debug + TryInto<Error, Error = Self::Error>;

    /// The output of the round preceding the proof share round.
    type Decommitment: Serialize + for<'a> Deserialize<'a> + Clone;
    /// The output of the proof share round.
    type ProofShare: Serialize + for<'a> Deserialize<'a> + Clone;
    /// The round following the proof share round.
    type ProofAggregationRoundParty: ProofAggregationRoundParty<
        Output,
        ProofShare = Self::ProofShare,
    >;

    /// The decommitment round of the proof aggregation protocol.
    /// Receives `self` and not `&self`, to enforce [`Self::ProofAggregationRoundParty`] can be instantiated only via a valid state transition.
    /// Receives `decommitments` the outputs of the preceding round from all parties.
    fn generate_proof_share(
        self,
        decommitments: HashMap<PartyID, Self::Decommitment>,
        rng: &mut impl CryptoRngCore,
    ) -> std::result::Result<(Self::ProofShare, Self::ProofAggregationRoundParty), Self::Error>;
}

/// The proof aggregation round party of a proof aggregation protocol.
pub trait ProofAggregationRoundParty<Output>: Sized {
    /// Aggregation error.
    type Error: Debug + TryInto<Error, Error = Self::Error>;

    /// The output of the round preceding the proof aggregation round.
    type ProofShare: Serialize + for<'a> Deserialize<'a> + Clone;

    /// The finalization logic of the aggregation protocol.
    /// Receives `proof_shares` the outputs of the preceding round from all parties.
    fn aggregate_proof_shares(
        self,
        proof_shares: HashMap<PartyID, Self::ProofShare>,
        rng: &mut impl CryptoRngCore,
    ) -> std::result::Result<Output, Self::Error>;
}
