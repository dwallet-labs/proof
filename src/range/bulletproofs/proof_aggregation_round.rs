use std::collections::HashMap;
use std::collections::HashSet;
use std::iter;
use std::ops::Neg;

use super::{COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RANGE_CLAIM_BITS};
use bulletproofs::exp_iter;
use bulletproofs::range_proof_mpc::messages::{
    BitChallenge, BitCommitment, PolyCommitment, ProofShare,
};
use bulletproofs::range_proof_mpc::{dealer::DealerAwaitingProofShares, MPCError};
use crypto_bigint::rand_core::CryptoRngCore;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::scalar;
use curve25519_dalek::scalar::Scalar;
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
    pub(super) bit_challenge: BitChallenge,
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

        // TODO: checked next power of two?
        let padded_proof_shares_length = proof_shares.len().next_power_of_two();

        let l_vec: Vec<_> = iter::repeat(self.bit_challenge.z.neg())
            .take(RANGE_CLAIM_BITS)
            .collect();

        let mut j = proof_shares.len();
        let mut iter = proof_shares.into_iter();
        let powers_of_z: Vec<Scalar> = exp_iter(self.bit_challenge.z)
            .take(padded_proof_shares_length + 2)
            .collect();
        let powers_of_y: Vec<Scalar> = exp_iter(self.bit_challenge.y)
            .take(padded_proof_shares_length * RANGE_CLAIM_BITS)
            .collect();
        let powers_of_2: Vec<Scalar> = exp_iter(Scalar::from(2u64))
            .take(RANGE_CLAIM_BITS)
            .collect();

        let proof_shares: Vec<_> = iter::repeat_with(|| {
            if let Some(proof_share) = iter.next() {
                proof_share
            } else {
                // $$ \vec{r}_j = ((z-1) y^{n\cdot j+0}+z^{2+j}2^0,\ldots,(z-1) y^{n\cdot j+n-1}+z^{2+j}2^{n-1}) $$
                let r_vec: Vec<_> = (0..RANGE_CLAIM_BITS)
                    .map(|i| {
                        ((self.bit_challenge.z - Scalar::from(1u64))
                            * powers_of_y[j * RANGE_CLAIM_BITS + i])
                            + (powers_of_z[j + 2] * powers_of_2[i])
                    })
                    .collect();

                let t_x = r_vec
                    .clone()
                    .into_iter()
                    .zip(l_vec.clone())
                    .map(|(a, b)| a * b)
                    .reduce(|a, b| a + b)
                    .unwrap();

                let proof_share = ProofShare {
                    e_blinding: Scalar::zero(),
                    t_x_blinding: Scalar::zero(),
                    r_vec,
                    l_vec: l_vec.clone(),
                    t_x,
                };

                j += 1;
                proof_share
            }
        })
        .take(padded_proof_shares_length)
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
