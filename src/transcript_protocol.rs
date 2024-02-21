// Author: dWallet Labs, Ltd.
// SPDX-License-Identifier: BSD-3-Clause-Clear

use crypto_bigint::{Encoding, Limb, Uint};
use merlin::Transcript;
use serde::Serialize;

/// A transcript protocol for fiat-shamir transforms of interactive to non-interactive proofs.
pub trait TranscriptProtocol {
    fn serialize_to_transcript_as_json<T: Serialize>(
        &mut self,
        label: &'static [u8],
        message: &T,
    ) -> serde_json::Result<()>;

    fn append_uint<const LIMBS: usize>(&mut self, label: &'static [u8], value: &Uint<LIMBS>)
    where
        Uint<LIMBS>: Encoding;

    fn challenge<const LIMBS: usize>(&mut self, label: &'static [u8]) -> Uint<LIMBS>;
}

impl TranscriptProtocol for Transcript {
    fn serialize_to_transcript_as_json<T: Serialize>(
        &mut self,
        label: &'static [u8],
        message: &T,
    ) -> serde_json::Result<()> {
        let serialized_message = serde_json::to_string_pretty(message)?;

        self.append_message(label, serialized_message.as_bytes());

        Ok(())
    }

    fn append_uint<const LIMBS: usize>(&mut self, label: &'static [u8], value: &Uint<LIMBS>)
    where
        Uint<LIMBS>: Encoding,
    {
        self.append_message(label, Uint::<LIMBS>::to_le_bytes(value).as_ref());
    }

    fn challenge<const LIMBS: usize>(&mut self, label: &'static [u8]) -> Uint<LIMBS> {
        let mut buf: Vec<u8> = vec![0u8; LIMBS * Limb::BYTES];
        self.challenge_bytes(label, buf.as_mut_slice());

        Uint::<LIMBS>::from_le_slice(&buf)
    }
}
