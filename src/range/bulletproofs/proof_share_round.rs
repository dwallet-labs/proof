use std::collections::HashSet;
use std::{collections::HashMap, marker::PhantomData};

use crate::aggregation::{process_incoming_messages, ProofShareRoundParty};
use crate::range::bulletproofs::proof_aggregation_round;
use crate::{aggregation, Error, Result};
use bulletproofs::range_proof_mpc::messages::ProofShare;
use bulletproofs::range_proof_mpc::{
    dealer::{DealerAwaitingBitCommitments, DealerAwaitingPolyCommitments},
    messages,
    messages::PolyCommitment,
    party::{PartyAwaitingBitChallenge, PartyAwaitingPolyChallenge},
};
use crypto_bigint::{rand_core::CryptoRngCore, Encoding, Uint};
use group::PartyID;
use serde::{Deserialize, Serialize};

pub struct Party<const NUM_RANGE_CLAIMS: usize> {
    pub(super) party_id: PartyID,
    pub(super) provers: HashSet<PartyID>,
    pub(super) number_of_witnesses: usize,
    pub(super) dealer_awaiting_poly_commitments: DealerAwaitingPolyCommitments,
    pub(super) parties_awaiting_poly_challenge: Vec<PartyAwaitingPolyChallenge>,
}

impl<const NUM_RANGE_CLAIMS: usize> ProofShareRoundParty<super::Output<NUM_RANGE_CLAIMS>>
    for Party<NUM_RANGE_CLAIMS>
{
    type Error = Error;

    type Decommitment = Vec<PolyCommitment>;

    type ProofShare = Vec<ProofShare>;

    type ProofAggregationRoundParty = proof_aggregation_round::Party<NUM_RANGE_CLAIMS>;

    fn generate_proof_share(
        self,
        decommitments: HashMap<PartyID, Self::Decommitment>,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::ProofShare, Self::ProofAggregationRoundParty)> {
        let decommitments =
            process_incoming_messages(self.party_id, self.provers.clone(), decommitments)?;

        let mut poly_commitments: Vec<(_, _)> = decommitments.into_iter().collect();

        poly_commitments.sort_by_key(|(party_id, _)| *party_id);

        let poly_commitments = poly_commitments
            .into_iter()
            .flat_map(|(_, poly_commitments)| poly_commitments)
            .collect();

        let (dealer_awaiting_proof_shares, poly_challenge) = self
            .dealer_awaiting_poly_commitments
            .receive_poly_commitments(poly_commitments)
            .map_err(|_| Error::InternalError)?;

        let proof_shares: Vec<_> = self
            .parties_awaiting_poly_challenge
            .into_iter()
            .map(|party| {
                party
                    .apply_challenge(&poly_challenge)
                    .map_err(bulletproofs::ProofError::from)
            })
            .collect::<std::result::Result<Vec<_>, _>>()
            .map_err(|_| Error::InternalError)?;

        let proof_aggregation_round_party = proof_aggregation_round::Party {
            party_id: self.party_id,
            provers: self.provers,
            number_of_witnesses: self.number_of_witnesses,
            dealer_awaiting_proof_shares,
        };

        Ok((proof_shares, proof_aggregation_round_party))
    }
}
