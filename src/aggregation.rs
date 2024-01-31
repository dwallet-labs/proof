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
    #[error("threshold not reached: received insufficient messages")]
    ThresholdNotReached,

    #[error("parties {:?} participated in the previous round of the session but not in the current", .0)]
    UnresponsiveParties(Vec<PartyID>),

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
    type Error: Debug;

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
    type Error: Debug;

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
    type Error: Debug;

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
    type Error: Debug;

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

#[cfg(any(test, feature = "benchmarking"))]
pub(crate) mod tests {
    use std::collections::HashMap;

    use rand_core::OsRng;

    use super::*;

    #[allow(dead_code)]
    pub(crate) fn aggregates_internal<Output, P: CommitmentRoundParty<Output>>(
        commitment_round_parties: HashMap<PartyID, P>,
    ) -> Output {
        aggregates_internal_multiple(
            commitment_round_parties
                .into_iter()
                .map(|(party_id, party)| (party_id, vec![party]))
                .collect(),
        )
        .into_iter()
        .next()
        .unwrap()
    }

    #[allow(dead_code)]
    pub(crate) fn aggregates_internal_multiple<Output, P: CommitmentRoundParty<Output>>(
        commitment_round_parties: HashMap<PartyID, Vec<P>>,
    ) -> Vec<Output> {
        let batch_size = commitment_round_parties
            .iter()
            .next()
            .unwrap()
            .clone()
            .1
            .len();

        let commitments_and_decommitment_round_parties: HashMap<_, Vec<(_, _)>> =
            commitment_round_parties
                .into_iter()
                .map(|(party_id, parties)| {
                    (
                        party_id,
                        parties
                            .into_iter()
                            .map(|party| {
                                party
                                    .commit_statements_and_statement_mask(&mut OsRng)
                                    .unwrap()
                            })
                            .collect(),
                    )
                })
                .collect();

        let commitments: HashMap<_, Vec<_>> = commitments_and_decommitment_round_parties
            .iter()
            .map(|(party_id, v)| {
                (
                    *party_id,
                    v.iter().map(|(commitment, _)| commitment.clone()).collect(),
                )
            })
            .collect();

        let commitments: Vec<HashMap<_, _>> = (0..batch_size)
            .map(|i| {
                commitments
                    .iter()
                    .map(|(party_id, commitments)| (*party_id, commitments[i].clone()))
                    .collect()
            })
            .collect();

        let decommitments_and_proof_share_round_parties: HashMap<_, Vec<(_, _)>> =
            commitments_and_decommitment_round_parties
                .into_iter()
                .map(|(party_id, v)| {
                    (
                        party_id,
                        v.into_iter()
                            .enumerate()
                            .map(|(i, (_, party))| {
                                party
                                    .decommit_statements_and_statement_mask(
                                        commitments[i].clone(),
                                        &mut OsRng,
                                    )
                                    .unwrap()
                            })
                            .collect(),
                    )
                })
                .collect();

        let decommitments: HashMap<_, Vec<_>> = decommitments_and_proof_share_round_parties
            .iter()
            .map(|(party_id, v)| {
                (
                    *party_id,
                    v.iter()
                        .map(|(decommitment, _)| decommitment.clone())
                        .collect(),
                )
            })
            .collect();

        let decommitments: Vec<HashMap<_, _>> = (0..batch_size)
            .map(|i| {
                decommitments
                    .iter()
                    .map(|(party_id, decommitments)| (*party_id, decommitments[i].clone()))
                    .collect()
            })
            .collect();

        let proof_shares_and_proof_aggregation_round_parties: HashMap<_, Vec<(_, _)>> =
            decommitments_and_proof_share_round_parties
                .into_iter()
                .map(|(party_id, v)| {
                    (
                        party_id,
                        v.into_iter()
                            .enumerate()
                            .map(|(i, (_, party))| {
                                party
                                    .generate_proof_share(decommitments[i].clone(), &mut OsRng)
                                    .unwrap()
                            })
                            .collect(),
                    )
                })
                .collect();

        let proof_shares: HashMap<_, Vec<_>> = proof_shares_and_proof_aggregation_round_parties
            .iter()
            .map(|(party_id, v)| {
                (
                    *party_id,
                    v.iter()
                        .map(|(proof_share, _)| proof_share.clone())
                        .collect(),
                )
            })
            .collect();

        let proof_shares: Vec<HashMap<_, _>> = (0..batch_size)
            .map(|i| {
                proof_shares
                    .iter()
                    .map(|(party_id, proof_shares)| (*party_id, proof_shares[i].clone()))
                    .collect()
            })
            .collect();

        let (_, proof_aggregation_round_parties) = proof_shares_and_proof_aggregation_round_parties
            .into_iter()
            .next()
            .unwrap();

        let (_, proof_aggregation_round_parties): (Vec<_>, Vec<_>) =
            proof_aggregation_round_parties.into_iter().unzip();

        proof_aggregation_round_parties
            .into_iter()
            .enumerate()
            .map(|(i, proof_aggregation_round_party)| {
                proof_aggregation_round_party
                    .aggregate_proof_shares(proof_shares[i].clone(), &mut OsRng)
                    .unwrap()
            })
            .collect()
    }
}
