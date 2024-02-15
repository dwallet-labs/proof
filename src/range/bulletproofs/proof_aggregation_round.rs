use std::collections::HashMap;
use std::collections::HashSet;

use super::COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS;
use bulletproofs::range_proof_mpc::messages::ProofShare;
use bulletproofs::range_proof_mpc::{dealer::DealerAwaitingProofShares, MPCError};
use crypto_bigint::rand_core::CryptoRngCore;
use group::{ristretto, PartyID};

use crate::aggregation::{process_incoming_messages, ProofAggregationRoundParty};
use crate::range::CommitmentScheme;
use crate::{aggregation, Error, Result};

#[cfg_attr(feature = "test_helpers", derive(Clone))]
pub struct Party<const NUM_RANGE_CLAIMS: usize> {
    pub(super) party_id: PartyID,
    pub(super) provers: HashSet<PartyID>,
    pub(super) number_of_witnesses: usize,
    pub(super) dealer_awaiting_proof_shares: DealerAwaitingProofShares,
    pub(super) individual_commitments: HashMap<PartyID, Vec<ristretto::GroupElement>>,
}

pub type Output<const NUM_RANGE_CLAIMS: usize> = (
    super::RangeProof,
    Vec<
        commitment::CommitmentSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            CommitmentScheme<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                super::RangeProof,
            >,
        >,
    >,
);

impl<const NUM_RANGE_CLAIMS: usize> ProofAggregationRoundParty<Output<NUM_RANGE_CLAIMS>>
    for Party<NUM_RANGE_CLAIMS>
{
    type Error = Error;

    type ProofShare = Vec<ProofShare>;

    fn aggregate_proof_shares(
        self,
        proof_shares: HashMap<PartyID, Self::ProofShare>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<Output<NUM_RANGE_CLAIMS>> {
        let proof_shares =
            process_incoming_messages(self.party_id, self.provers.clone(), proof_shares, false)?;

        let mut proof_shares: Vec<(_, _)> = proof_shares.into_iter().collect();

        proof_shares.sort_by_key(|(party_id, _)| *party_id);

        let proof_shares: Vec<_> = proof_shares
            .into_iter()
            .flat_map(|(_, proof_shares)| proof_shares)
            .collect();

        // TODO: should we abort identifiably in the case of decompression error?
        let bulletproofs_commitments: Vec<_> = self
            .dealer_awaiting_proof_shares
            .bit_commitments
            .iter()
            .map(|vc| vc.V_j.try_into().map_err(|_| Error::InternalError))
            .collect::<Result<Vec<_>>>()?;

        let proof = self
            .dealer_awaiting_proof_shares
            .receive_shares_with_rng(&proof_shares, rng)
            .map_err(|e| match e {
                MPCError::MalformedProofShares { bad_shares } => {
                    // TODO: verify this
                    bad_shares
                        .into_iter()
                        .map(|i| {
                            self.number_of_witnesses
                                .checked_mul(NUM_RANGE_CLAIMS)
                                .and_then(|number_of_bulletproof_parties_per_party| {
                                    i.checked_div(number_of_bulletproof_parties_per_party)
                                        .and_then(|i| i.checked_add(1))
                                        .and_then(|i| u16::try_from(i).ok())
                                })
                        })
                        .collect::<Option<Vec<_>>>()
                        .map(|malicious_parties| {
                            Error::Aggregation(aggregation::Error::ProofShareVerification(
                                malicious_parties,
                            ))
                        })
                        .unwrap_or(Error::InternalError)
                }
                _ => Error::InvalidParameters,
            })?;

        super::RangeProof::new_aggregated(
            proof,
            self.provers.len(),
            self.number_of_witnesses,
            bulletproofs_commitments.clone(),
        )
    }
}
