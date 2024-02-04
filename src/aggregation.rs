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

#[cfg(feature = "test_helpers")]
pub mod test_helpers {
    use super::*;
    use criterion::{measurement::Measurement, measurement::WallTime};
    use rand::seq::IteratorRandom;
    use rand_core::OsRng;
    use std::collections::HashMap;
    use std::time::Duration;

    fn commitment_round<Output, P: CommitmentRoundParty<Output>>(
        commitment_round_parties: HashMap<PartyID, P>,
    ) -> Result<(
        HashMap<PartyID, P::Commitment>,
        HashMap<PartyID, P::DecommitmentRoundParty>,
    )> {
        let commitments_and_decommitment_round_parties: HashMap<_, (_, _)> =
            commitment_round_parties
                .into_iter()
                .map(|(party_id, party)| {
                    party
                        .commit_statements_and_statement_mask(&mut OsRng)
                        .map(|res| (party_id, res))
                        .map_err(|e| e.try_into().unwrap())
                })
                .collect::<Result<_>>()?;

        Ok(commitments_and_decommitment_round_parties
            .into_iter()
            .map(|(party_id, (commitment, decommitment_round_party))| {
                ((party_id, commitment), (party_id, decommitment_round_party))
            })
            .unzip())
    }

    fn decommitment_round<Output, P: DecommitmentRoundParty<Output>>(
        commitments: HashMap<PartyID, P::Commitment>,
        decommitment_round_parties: HashMap<PartyID, P>,
    ) -> Result<(
        HashMap<PartyID, P::Decommitment>,
        HashMap<PartyID, P::ProofShareRoundParty>,
    )> {
        let decommitments_and_proof_share_round_parties: HashMap<_, (_, _)> =
            decommitment_round_parties
                .into_iter()
                .map(|(party_id, party)| {
                    party
                        .decommit_statements_and_statement_mask(commitments.clone(), &mut OsRng)
                        .map(|res| (party_id, res))
                        .map_err(|e| e.try_into().unwrap())
                })
                .collect::<Result<_>>()?;

        Ok(decommitments_and_proof_share_round_parties
            .into_iter()
            .map(|(party_id, (decommitment, proof_share_round_party))| {
                (
                    (party_id, decommitment),
                    (party_id, proof_share_round_party),
                )
            })
            .unzip())
    }

    fn proof_share_round<Output, P: ProofShareRoundParty<Output>>(
        decommitments: HashMap<PartyID, P::Decommitment>,
        proof_share_round_parties: HashMap<PartyID, P>,
    ) -> Result<(
        HashMap<PartyID, P::ProofShare>,
        HashMap<PartyID, P::ProofAggregationRoundParty>,
    )> {
        let proof_shares_and_proof_aggregation_round_parties: HashMap<_, (_, _)> =
            proof_share_round_parties
                .into_iter()
                .map(|(party_id, party)| {
                    party
                        .generate_proof_share(decommitments.clone(), &mut OsRng)
                        .map(|res| (party_id, res))
                        .map_err(|e| e.try_into().unwrap())
                })
                .collect::<Result<_>>()?;

        Ok(proof_shares_and_proof_aggregation_round_parties
            .into_iter()
            .map(|(party_id, (proof_share, proof_aggregation_round_party))| {
                (
                    (party_id, proof_share),
                    (party_id, proof_aggregation_round_party),
                )
            })
            .unzip())
    }

    pub fn unresponsive_parties_aborts_session_identifiably<
        Output,
        P: CommitmentRoundParty<Output>,
    >(
        commitment_round_parties: HashMap<PartyID, P>,
    ) where
        P::DecommitmentRoundParty: Clone,
        <P::DecommitmentRoundParty as DecommitmentRoundParty<Output>>::ProofShareRoundParty: Clone,
    {
        let (commitments, decommitment_round_parties) =
            commitment_round(commitment_round_parties).unwrap();

        let provers: Vec<_> = commitments.clone().into_keys().collect();
        let number_of_unresponsive_parties = if commitments.keys().len() == 2 { 1 } else { 2 };
        let unresponsive_parties = provers
            .clone()
            .into_iter()
            .choose_multiple(&mut OsRng, number_of_unresponsive_parties);

        let filtered_commitments = commitments
            .clone()
            .into_iter()
            .filter(|(party_id, _)| !unresponsive_parties.contains(party_id))
            .collect();

        assert!(matches!(
            decommitment_round(filtered_commitments, decommitment_round_parties.clone())
                .err()
                .unwrap(),
            Error::UnresponsiveParties(parties) if parties == unresponsive_parties
        ));

        let (decommitments, proof_share_round_parties) =
            decommitment_round(commitments, decommitment_round_parties).unwrap();

        let filtered_decommitments = decommitments
            .clone()
            .into_iter()
            .filter(|(party_id, _)| !unresponsive_parties.contains(party_id))
            .collect();

        assert!(matches!(
            proof_share_round(filtered_decommitments, proof_share_round_parties.clone())
                .err()
                .unwrap(),
            Error::UnresponsiveParties(parties) if parties == unresponsive_parties
        ));

        let (proof_shares, proof_aggregation_parties) =
            proof_share_round(decommitments, proof_share_round_parties).unwrap();

        let filtered_proof_shares: HashMap<_, _> = proof_shares
            .clone()
            .into_iter()
            .filter(|(party_id, _)| !unresponsive_parties.contains(party_id))
            .collect();

        assert!(
            proof_aggregation_parties.into_iter().all(|(party_id, proof_aggregation_round_party)| {
                let unresponsive_parties_for_party: Vec<_> = unresponsive_parties.clone().into_iter().filter(|&pid| pid != party_id).collect();

                matches!(
                    proof_aggregation_round_party.aggregate_proof_shares(filtered_proof_shares.clone(), &mut OsRng).err().unwrap().try_into().unwrap(),
                    Error::UnresponsiveParties(parties) if parties == unresponsive_parties_for_party
                )
            }
            )
        );
    }

    pub fn aggregates_internal<Output, P: CommitmentRoundParty<Output>>(
        commitment_round_parties: HashMap<PartyID, P>,
    ) -> (Duration, Duration, Duration, Duration, Duration, Output) {
        let (
            commitment_round_time,
            decommitment_round_time,
            proof_share_round_time,
            proof_aggregation_round_time,
            total_time,
            outputs,
        ) = aggregates_internal_multiple(
            commitment_round_parties
                .into_iter()
                .map(|(party_id, party)| (party_id, vec![party]))
                .collect(),
        );

        (
            commitment_round_time,
            decommitment_round_time,
            proof_share_round_time,
            proof_aggregation_round_time,
            total_time,
            outputs.into_iter().next().unwrap(),
        )
    }

    pub fn aggregates_internal_multiple<Output, P: CommitmentRoundParty<Output>>(
        commitment_round_parties: HashMap<PartyID, Vec<P>>,
    ) -> (
        Duration,
        Duration,
        Duration,
        Duration,
        Duration,
        Vec<Output>,
    ) {
        let measurement = WallTime;
        let mut commitment_round_time = Duration::default();
        let mut decommitment_round_time = Duration::default();
        let mut proof_share_round_time = Duration::default();

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
                    let now = measurement.start();
                    let res = parties
                        .into_iter()
                        .map(|party| {
                            party
                                .commit_statements_and_statement_mask(&mut OsRng)
                                .unwrap()
                        })
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
                    let now = measurement.start();
                    let res = v
                        .into_iter()
                        .enumerate()
                        .map(|(i, (_, party))| {
                            party
                                .decommit_statements_and_statement_mask(
                                    commitments[i].clone(),
                                    &mut OsRng,
                                )
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
                    let now = measurement.start();
                    let res = v
                        .into_iter()
                        .enumerate()
                        .map(|(i, (_, party))| {
                            party
                                .generate_proof_share(decommitments[i].clone(), &mut OsRng)
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
        let outputs = proof_aggregation_round_parties
            .into_iter()
            .enumerate()
            .map(|(i, proof_aggregation_round_party)| {
                proof_aggregation_round_party
                    .aggregate_proof_shares(proof_shares[i].clone(), &mut OsRng)
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
            outputs,
        )
    }
}
