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

pub mod test_helpers {
    #[cfg(feature = "benchmarking")]
    use criterion::{measurement::Measurement, measurement::WallTime, BenchmarkGroup};
    use std::collections::HashMap;
    use std::process::Output;
    use std::time::Duration;

    use super::*;

    pub fn aggregates_internal<Output, P: CommitmentRoundParty<Output>>(
        commitment_round_parties: HashMap<PartyID, P>,
        rng: &mut impl CryptoRngCore,
    ) -> Output {
        aggregates_internal_multiple(
            commitment_round_parties
                .into_iter()
                .map(|(party_id, party)| (party_id, vec![party]))
                .collect(),
            rng,
        )
        .into_iter()
        .next()
        .unwrap()
    }

    pub fn aggregates_internal_multiple<Output, P: CommitmentRoundParty<Output>>(
        commitment_round_parties: HashMap<PartyID, Vec<P>>,
        rng: &mut impl CryptoRngCore,
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
                            .map(|party| party.commit_statements_and_statement_mask(rng).unwrap())
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
                                        rng,
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
                                    .generate_proof_share(decommitments[i].clone(), rng)
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
                    .aggregate_proof_shares(proof_shares[i].clone(), rng)
                    .unwrap()
            })
            .collect()
    }

    #[cfg(feature = "benchmarking")]
    pub fn benchmark_internal_multiple<Output, P: CommitmentRoundParty<Output>>(
        commitment_round_parties: HashMap<PartyID, Vec<P>>,
        g: &mut BenchmarkGroup<WallTime>,
        rng: &mut impl CryptoRngCore,
    ) -> (
        Duration,
        Duration,
        Duration,
        Duration,
        Duration,
        Vec<Output>,
    )
    where
        P: Clone,
        P::DecommitmentRoundParty: Clone,
        <P::DecommitmentRoundParty as DecommitmentRoundParty<Output>>::ProofShareRoundParty: Clone,
    {
        let measurement = WallTime;
        let pid = *commitment_round_parties.keys().next().unwrap();
        let batch_size = commitment_round_parties
            .iter()
            .next()
            .unwrap()
            .clone()
            .1
            .len();
        let mut commitment_round_time = Duration::default();
        let mut decommitment_round_time = Duration::default();
        let mut proof_share_round_time = Duration::default();

        let commitments_and_decommitment_round_parties: HashMap<_, Vec<(_, _)>> =
            commitment_round_parties
                .into_iter()
                .map(|(party_id, parties)| {
                    if party_id == pid {
                        g.bench_function(format!("commitment round"), |bench| {
                            bench.iter(|| {
                                parties.clone().into_iter().for_each(|party| {
                                    party.commit_statements_and_statement_mask(rng).unwrap();
                                })
                            })
                        });
                    }

                    let now = measurement.start();
                    let res = parties
                        .into_iter()
                        .map(|party| party.commit_statements_and_statement_mask(rng).unwrap())
                        .collect();
                    commitment_round_time = measurement.end(now);

                    (party_id, res)
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
                    if party_id == pid {
                        g.bench_function(format!("commitment round"), |bench| {
                            bench.iter(|| {
                                v.clone()
                                    .into_iter()
                                    .enumerate()
                                    .for_each(|(i, (_, party))| {
                                        party
                                            .decommit_statements_and_statement_mask(
                                                commitments[i].clone(),
                                                rng,
                                            )
                                            .unwrap();
                                    })
                            })
                        });
                    }

                    let now = measurement.start();
                    let res = v
                        .into_iter()
                        .enumerate()
                        .map(|(i, (_, party))| {
                            party
                                .decommit_statements_and_statement_mask(commitments[i].clone(), rng)
                                .unwrap()
                        })
                        .collect();
                    decommitment_round_time = measurement.end(now);

                    (party_id, res)
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
                    if party_id == pid {
                        g.bench_function(format!("commitment round"), |bench| {
                            bench.iter(|| {
                                v.clone()
                                    .into_iter()
                                    .enumerate()
                                    .for_each(|(i, (_, party))| {
                                        party
                                            .generate_proof_share(decommitments[i].clone(), rng)
                                            .unwrap();
                                    })
                            })
                        });
                    }

                    let now = measurement.start();
                    let res = v
                        .into_iter()
                        .enumerate()
                        .map(|(i, (_, party))| {
                            party
                                .generate_proof_share(decommitments[i].clone(), rng)
                                .unwrap()
                        })
                        .collect();
                    proof_share_round_time = measurement.end(now);

                    (party_id, res)
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

        let now = measurement.start();
        let output = proof_aggregation_round_parties
            .into_iter()
            .enumerate()
            .map(|(i, proof_aggregation_round_party)| {
                proof_aggregation_round_party
                    .aggregate_proof_shares(proof_shares[i].clone(), rng)
                    .unwrap()
            })
            .collect();
        let proof_aggregation_round_time = measurement.end(now);
        let total_time = measurement.add(&commitment_round_time, &decommitment_round_time);
        let total_time = measurement.add(&total_time, &proof_share_round_time);
        let total_time = measurement.add(&total_time, &proof_aggregation_round_time);

        (
            commitment_round_time,
            decommitment_round_time,
            proof_share_round_time,
            proof_aggregation_round_time,
            total_time,
            output,
        )
    }
}
