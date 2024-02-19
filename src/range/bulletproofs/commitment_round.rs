// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear
use std::collections::HashSet;
use std::iter;

use super::{decommitment_round, COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS, RANGE_CLAIM_BITS};
use crate::aggregation::CommitmentRoundParty;
use crate::range::CommitmentScheme;
use crate::{aggregation, Error, Result};
use bulletproofs::{
    range_proof_mpc::{dealer::Dealer, messages::BitCommitment, party},
    BulletproofGens, PedersenGens,
};
use crypto_bigint::{rand_core::CryptoRngCore, U256, U64};
use group::PartyID;
use merlin::Transcript;

#[cfg_attr(feature = "test_helpers", derive(Clone))]
pub struct Party<const NUM_RANGE_CLAIMS: usize> {
    pub party_id: PartyID,
    // The set of parties ${P_i}$ participating in the proof aggregation protocol.
    pub(super) provers: HashSet<PartyID>,
    pub initial_transcript: Transcript,
    pub witnesses: Vec<
        commitment::MessageSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            CommitmentScheme<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                super::RangeProof,
            >,
        >,
    >,
    pub commitments_randomness: Vec<
        commitment::RandomnessSpaceGroupElement<
            COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
            CommitmentScheme<
                COMMITMENT_SCHEME_MESSAGE_SPACE_SCALAR_LIMBS,
                NUM_RANGE_CLAIMS,
                super::RangeProof,
            >,
        >,
    >,
}

impl<const NUM_RANGE_CLAIMS: usize> CommitmentRoundParty<super::Output<NUM_RANGE_CLAIMS>>
    for Party<NUM_RANGE_CLAIMS>
{
    type Error = Error;
    type Commitment = Vec<BitCommitment>;
    type DecommitmentRoundParty = decommitment_round::Party<NUM_RANGE_CLAIMS>;

    /// TODO: fix this
    /// Due to a limitation in Bulletproofs, assumes both the number of parties and the number of
    /// witnesses are powers of 2. If one needs a non-power-of-two, pad to the
    /// `next_power_of_two` by creating additional parties with zero-valued witnesses and having
    /// every party emulate those locally.
    fn commit_statements_and_statement_mask(
        self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Commitment, Self::DecommitmentRoundParty)> {
        if !self.provers.contains(&self.party_id) {
            return Err(Error::Aggregation(
                aggregation::Error::NonParticipatingParty,
            ));
        }

        let batch_size = self.witnesses.len();

        // As bulletproofs proves a single witness, flatten the witnesses vector
        // from an entry over `NUM_RANGE_CLAIMS` to a vector of individual range claims.
        let witnesses: Vec<_> = self
            .witnesses
            .into_iter()
            .flat_map(<[_; NUM_RANGE_CLAIMS]>::from)
            .collect();

        // Buletproofs think of range claims a numbers and not scalars.
        // Transition, whilst ensuring they are in range.
        let witnesses: Vec<_> = witnesses.into_iter().map(U256::from).collect();

        if witnesses
            .iter()
            .any(|witness| witness >= &(U256::ONE << RANGE_CLAIM_BITS))
        {
            return Err(Error::InvalidParameters)?;
        }

        // TODO: checked next power of two?
        let number_of_padded_witnesses = witnesses.len().next_power_of_two();
        let mut iter = witnesses.into_iter();
        let witnesses: Vec<u64> = iter::repeat_with(|| {
            iter.next()
                .map(|witness| U64::from(&witness).into())
                .unwrap_or(0u64)
        })
        .take(number_of_padded_witnesses)
        .collect();
        let number_of_witnesses = witnesses.len();

        // TODO: checked next power of two?
        let number_of_parties = self
            .provers
            .len()
            .next_power_of_two()
            .checked_mul(number_of_witnesses)
            .ok_or(Error::InternalError)?;

        let commitments_randomness: Vec<_> = self
            .commitments_randomness
            .into_iter()
            .flat_map(<[_; NUM_RANGE_CLAIMS]>::from)
            .map(curve25519_dalek::scalar::Scalar::from)
            .collect();

        let bulletproofs_generators = BulletproofGens::new(RANGE_CLAIM_BITS, number_of_parties);

        let commitment_generators = PedersenGens::default();

        let dealer_awaiting_bit_commitments = Dealer::new(
            bulletproofs_generators.clone(),
            commitment_generators,
            self.initial_transcript,
            RANGE_CLAIM_BITS,
            number_of_parties,
        )
        .map_err(|_| Error::InvalidParameters)?;

        let parties: Vec<_> = witnesses
            .into_iter()
            .zip(commitments_randomness.into_iter())
            .map(|(witness, commitment_randomness)| {
                party::Party::new(
                    bulletproofs_generators.clone(),
                    commitment_generators,
                    witness,
                    commitment_randomness,
                    RANGE_CLAIM_BITS,
                )
                .map_err(|_| Error::InvalidParameters)
            })
            .collect::<Result<Vec<_>>>()?;

        // TODO: this assumes party IDs are 1 to n right?
        let (parties_awaiting_bit_challenge, bit_commitments): (Vec<_>, Vec<_>) = parties
            .into_iter()
            .enumerate()
            .map(|(i, party): (usize, party::PartyAwaitingPosition)| {
                usize::from(self.party_id)
                    .checked_sub(1)
                    .and_then(|position| position.checked_mul(NUM_RANGE_CLAIMS))
                    .and_then(|position| position.checked_mul(batch_size))
                    .and_then(|position| position.checked_add(i))
                    .ok_or(Error::InternalError)
                    .and_then(|position| {
                        party
                            .assign_position_with_rng(position, rng)
                            .map_err(|_| Error::InvalidParameters)
                    })
            })
            .collect::<Result<Vec<(_, _)>>>()?
            .into_iter()
            .unzip();

        let decommitment_round_party = decommitment_round::Party {
            party_id: self.party_id,
            provers: self.provers,
            number_of_witnesses: batch_size,
            dealer_awaiting_bit_commitments,
            parties_awaiting_bit_challenge,
            bulletproofs_generators
        };

        Ok((bit_commitments, decommitment_round_party))
    }
}
