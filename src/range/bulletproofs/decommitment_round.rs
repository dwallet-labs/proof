use std::collections::HashSet;
use std::{collections::HashMap, marker::PhantomData};

use crate::aggregation::{process_incoming_messages, DecommitmentRoundParty};
use crate::range::bulletproofs::proof_share_round;
use crate::Error::Aggregation;
use crate::{aggregation, Error, Result};
use bulletproofs::range_proof_mpc::messages::BitCommitment;
use bulletproofs::range_proof_mpc::{
    dealer::DealerAwaitingBitCommitments, messages::PolyCommitment,
    party::PartyAwaitingBitChallenge,
};
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use group::PartyID;
use serde::{Deserialize, Serialize};

pub struct Party<const NUM_RANGE_CLAIMS: usize> {
    pub(super) party_id: PartyID,
    pub(super) provers: HashSet<PartyID>,
    pub(super) number_of_witnesses: usize,
    pub(super) dealer_awaiting_bit_commitments: DealerAwaitingBitCommitments,
    pub(super) parties_awaiting_bit_challenge: Vec<PartyAwaitingBitChallenge>,
}

impl<const NUM_RANGE_CLAIMS: usize> DecommitmentRoundParty<super::Output<NUM_RANGE_CLAIMS>>
    for Party<NUM_RANGE_CLAIMS>
{
    type Error = Error;
    type Commitment = Vec<BitCommitment>;

    type Decommitment = Vec<PolyCommitment>;

    type ProofShareRoundParty = proof_share_round::Party<NUM_RANGE_CLAIMS>;

    fn decommit_statements_and_statement_mask(
        self,
        commitments: HashMap<PartyID, Self::Commitment>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::Decommitment, Self::ProofShareRoundParty)> {
        let commitments =
            process_incoming_messages(self.party_id, self.provers.clone(), commitments)?;

        let mut bit_commitments: Vec<(_, _)> = commitments.into_iter().collect();

        bit_commitments.sort_by_key(|(party_id, _)| *party_id);

        let bit_commitments = bit_commitments
            .into_iter()
            .flat_map(|(_, bit_commitments)| bit_commitments)
            .collect();

        let (dealer_awaiting_poly_commitments, bit_challenge) = self
            .dealer_awaiting_bit_commitments
            .receive_bit_commitments(bit_commitments)
            .map_err(|_| Error::InternalError)?;

        let (parties_awaiting_poly_challenge, poly_commitments): (Vec<_>, Vec<_>) = self
            .parties_awaiting_bit_challenge
            .into_iter()
            .map(|party| party.apply_challenge_with_rng(&bit_challenge, rng))
            .unzip();

        let third_round_party = proof_share_round::Party {
            party_id: self.party_id,
            provers: self.provers,
            number_of_witnesses: self.number_of_witnesses,
            dealer_awaiting_poly_commitments,
            parties_awaiting_poly_challenge,
        };

        Ok((poly_commitments, third_round_party))
    }
}
