// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! AND/OR/Threshold composition of Sigma protocols, reproducing sigma-proofs'
//! `composition` module byte-for-byte for the `sigma-proofs_Shake128_P256`
//! suite. MoLE's IHAT issuer-hiding endorsement is an OR-proof: prove a valid
//! endorsement under one of N accepted anchor keys without revealing which.
//!
//! The composed protocol identifier is `SHA3-256(tag[32] || concat(branch
//! ids))` padded to 64 bytes (recursive). The OR challenge split is the
//! classic CDS: the proof carries `n-1` branch challenges and the last is
//! `c - Σ(stored)`; each branch's linear-relation transcript is checked with
//! its own challenge.
//!
//! Serialization (tagged, recursive): a node is `TAG u8 || len u32-LE || …`.
//! `Simple` commitments/responses are group elements / scalars; `Or` carries
//! per-branch nodes, and its response additionally carries the compressed
//! challenge list.

use crate::codec::{challenge_scalar, init_transcript};
use crate::linear_relation::{LinearRelation, MalformedInput};
use crate::{Point, Scalar, POINT_BYTES, SCALAR_BYTES};

const TAG_SIMPLE: u8 = 0;
#[allow(dead_code)]
const TAG_AND: u8 = 1;
const TAG_OR: u8 = 2;
#[allow(dead_code)]
const TAG_THRESHOLD: u8 = 3;

/// A byte cursor over a proof buffer.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }
    /// Bytes not yet consumed. Used to bound attacker-supplied length prefixes
    /// before allocating, so a malicious `n` can't drive an out-of-memory abort.
    fn remaining(&self) -> usize {
        self.buf.len().saturating_sub(self.pos)
    }
    fn u8(&mut self) -> Result<u8, MalformedInput> {
        let b = *self.buf.get(self.pos).ok_or(MalformedInput)?;
        self.pos += 1;
        Ok(b)
    }
    fn u32(&mut self) -> Result<usize, MalformedInput> {
        let end = self.pos + 4;
        let slice = self.buf.get(self.pos..end).ok_or(MalformedInput)?;
        self.pos = end;
        Ok(u32::from_le_bytes(slice.try_into().unwrap()) as usize)
    }
    fn point(&mut self) -> Result<Point, MalformedInput> {
        let end = self.pos + POINT_BYTES;
        let slice = self.buf.get(self.pos..end).ok_or(MalformedInput)?;
        self.pos = end;
        Point::from_bytes(&slice.try_into().unwrap()).ok_or(MalformedInput)
    }
    fn scalar(&mut self) -> Result<Scalar, MalformedInput> {
        let end = self.pos + SCALAR_BYTES;
        let slice = self.buf.get(self.pos..end).ok_or(MalformedInput)?;
        self.pos = end;
        // Wire scalars must be canonical (`< n`); a non-canonical encoding is
        // rejected rather than silently reduced, matching the reference and
        // closing scalar malleability on proof responses / branch challenges.
        Scalar::from_canonical_bytes(&slice.try_into().unwrap()).ok_or(MalformedInput)
    }
}

/// Cap on composition-tree nesting depth. MoLE's issuer-hiding statement is a
/// single OR of simple branches (depth 1); this bound stops a crafted proof of
/// deeply nested composites from exhausting the stack during parsing.
const MAX_DEPTH: usize = 8;

/// Minimum on-wire size of any composition node: a `TAG u8 || len u32-LE`
/// header with an empty body. Used to bound child counts against the buffer.
const MIN_NODE_BYTES: usize = 5;

/// Deserialized commitment tree.
enum Commitment {
    Simple(Vec<Point>),
    Composed(Vec<Commitment>),
}

/// Deserialized response tree; `Or` carries the compressed challenges too.
enum Response {
    Simple(Vec<Scalar>),
    Or(Vec<Scalar>, Vec<Response>),
}

fn parse_commitment(cur: &mut Cursor, depth: usize) -> Result<Commitment, MalformedInput> {
    if depth > MAX_DEPTH {
        return Err(MalformedInput);
    }
    match cur.u8()? {
        TAG_SIMPLE => {
            let n = cur.u32()?;
            // Each point occupies POINT_BYTES on the wire; an `n` larger than
            // the buffer could hold is malformed, so reject before allocating.
            if n > cur.remaining() / POINT_BYTES {
                return Err(MalformedInput);
            }
            let mut points = Vec::with_capacity(n);
            for _ in 0..n {
                points.push(cur.point()?);
            }
            Ok(Commitment::Simple(points))
        }
        TAG_OR | TAG_AND | TAG_THRESHOLD => {
            let n = cur.u32()?;
            if n > cur.remaining() / MIN_NODE_BYTES {
                return Err(MalformedInput);
            }
            let mut children = Vec::with_capacity(n);
            for _ in 0..n {
                children.push(parse_commitment(cur, depth + 1)?);
            }
            Ok(Commitment::Composed(children))
        }
        _ => Err(MalformedInput),
    }
}

fn parse_response(cur: &mut Cursor, depth: usize) -> Result<Response, MalformedInput> {
    if depth > MAX_DEPTH {
        return Err(MalformedInput);
    }
    match cur.u8()? {
        TAG_SIMPLE => {
            let n = cur.u32()?;
            if n > cur.remaining() / SCALAR_BYTES {
                return Err(MalformedInput);
            }
            let mut scalars = Vec::with_capacity(n);
            for _ in 0..n {
                scalars.push(cur.scalar()?);
            }
            Ok(Response::Simple(scalars))
        }
        TAG_OR | TAG_THRESHOLD => {
            let nc = cur.u32()?;
            if nc > cur.remaining() / SCALAR_BYTES {
                return Err(MalformedInput);
            }
            let mut challenges = Vec::with_capacity(nc);
            for _ in 0..nc {
                challenges.push(cur.scalar()?);
            }
            let nr = cur.u32()?;
            if nr > cur.remaining() / MIN_NODE_BYTES {
                return Err(MalformedInput);
            }
            let mut responses = Vec::with_capacity(nr);
            for _ in 0..nr {
                responses.push(parse_response(cur, depth + 1)?);
            }
            Ok(Response::Or(challenges, responses))
        }
        _ => Err(MalformedInput),
    }
}

// -- Composed protocol identifier --------------------------------------------

/// Pad a protocol identifier to the fixed 64-byte field.
fn pad64(id: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out[..id.len()].copy_from_slice(id);
    out
}

/// The composed OR protocol identifier over `n` simple branches, all in the
/// same group (so all sharing `simple_protocol_id`). Mirrors sigma-proofs:
/// each branch's id is `SHA3-256([0;32] || simple_id)` padded to 64 bytes, and
/// the OR id is `SHA3-256([2;32] || branch_id * n)` padded to 64.
fn composed_or_protocol_id(simple_protocol_id: &[u8], n: usize) -> [u8; 64] {
    let simple = pad64(simple_protocol_id);
    let mut branch_input = Vec::with_capacity(32 + 64);
    branch_input.extend_from_slice(&[0u8; 32]);
    branch_input.extend_from_slice(&simple);
    let branch_id = pad64(&crate::shake::sha3_256(&branch_input));

    let mut or_input = Vec::with_capacity(32 + n * 64);
    or_input.extend_from_slice(&[2u8; 32]);
    for _ in 0..n {
        or_input.extend_from_slice(&branch_id);
    }
    pad64(&crate::shake::sha3_256(&or_input))
}

// -- OR challenge split ------------------------------------------------------

/// The branch challenges for an OR (CDS): the proof carries `n-1` stored
/// challenges (one per branch except the last); the last branch's challenge is
/// `c - Σ(stored)`. Returns the `n` branch challenges in order.
fn or_branch_challenges(
    total: usize,
    challenge: &Scalar,
    stored: &[Scalar],
) -> Option<Vec<Scalar>> {
    if stored.len() + 1 != total {
        return None;
    }
    let mut sum = Scalar::zero();
    for s in stored {
        sum = sum.add(s);
    }
    let last = challenge.sub(&sum);
    let mut challenges: Vec<Scalar> = stored.to_vec();
    challenges.push(last);
    Some(challenges)
}

// -- Serialization (prover side) ---------------------------------------------

fn write_u32(out: &mut Vec<u8>, v: usize) {
    out.extend_from_slice(&(v as u32).to_le_bytes());
}

/// Serialize a `Simple` commitment node: `TAG_SIMPLE || len || points`.
fn serialize_simple_commitment(out: &mut Vec<u8>, points: &[Point]) {
    out.push(TAG_SIMPLE);
    write_u32(out, points.len());
    for p in points {
        out.extend_from_slice(&p.to_bytes());
    }
}

/// Serialize a `Simple` response node: `TAG_SIMPLE || len || scalars`.
fn serialize_simple_response(out: &mut Vec<u8>, scalars: &[Scalar]) {
    out.push(TAG_SIMPLE);
    write_u32(out, scalars.len());
    for s in scalars {
        out.extend_from_slice(&s.to_bytes());
    }
}

/// Produce a batchable OR proof, proving the `real_index` branch with
/// `witness` and simulating the rest (CDS). Round-trips against
/// [`verify_or_batchable`].
pub fn prove_or_batchable(
    branches: &[LinearRelation],
    real_index: usize,
    witness: &[Scalar],
    simple_protocol_id: &[u8],
    session: &[u8],
    instance: &[u8],
) -> Result<Vec<u8>, MalformedInput> {
    let n = branches.len();
    if real_index >= n || witness.len() != branches[real_index].num_scalars() {
        return Err(MalformedInput);
    }

    // Simulate every non-real branch (random challenge + response -> commitment)
    // and honestly commit the real branch with random nonces.
    let mut sim_challenges: Vec<Option<Scalar>> = (0..n).map(|_| None).collect();
    let mut responses: Vec<Vec<Scalar>> = Vec::with_capacity(n);
    let mut commitments: Vec<Vec<Point>> = Vec::with_capacity(n);
    let mut real_nonces = Vec::new();
    for (j, branch) in branches.iter().enumerate() {
        if j == real_index {
            real_nonces = (0..branch.num_scalars()).map(|_| Scalar::random()).collect();
            commitments.push(branch.evaluate(&real_nonces));
            responses.push(Vec::new()); // filled after the challenge
        } else {
            let e = Scalar::random();
            let z: Vec<Scalar> =
                (0..branch.num_scalars()).map(|_| Scalar::random()).collect();
            commitments.push(branch.simulate_commitments(&e, &z)?);
            responses.push(z);
            sim_challenges[j] = Some(e);
        }
    }

    // Serialize + absorb the OR commitment, derive the transcript challenge.
    let mut commit_bytes = Vec::new();
    commit_bytes.push(TAG_OR);
    write_u32(&mut commit_bytes, n);
    for commit in &commitments {
        serialize_simple_commitment(&mut commit_bytes, commit);
    }
    let protocol_identifier = composed_or_protocol_id(simple_protocol_id, n);
    let mut transcript = init_transcript(&protocol_identifier, session, instance);
    transcript.absorb(&commit_bytes);
    let challenge = challenge_scalar(&mut transcript);

    // Real branch challenge = c - Σ(simulated challenges); real response.
    let mut sum = Scalar::zero();
    for e in sim_challenges.iter().flatten() {
        sum = sum.add(e);
    }
    let real_challenge = challenge.sub(&sum);
    responses[real_index] = real_nonces
        .iter()
        .zip(witness)
        .map(|(nonce, w)| nonce.add(&w.mul(&real_challenge)))
        .collect();

    // Full branch-challenge list, then serialize the first n-1 as stored.
    let mut branch_challenges: Vec<Scalar> = Vec::with_capacity(n);
    for j in 0..n {
        branch_challenges.push(match &sim_challenges[j] {
            Some(e) => e.clone(),
            None => real_challenge.clone(),
        });
    }

    let mut proof = commit_bytes;
    proof.push(TAG_OR);
    write_u32(&mut proof, n - 1);
    for e in branch_challenges.iter().take(n - 1) {
        proof.extend_from_slice(&e.to_bytes());
    }
    write_u32(&mut proof, n);
    for resp in &responses {
        serialize_simple_response(&mut proof, resp);
    }
    Ok(proof)
}

// -- OR verification ---------------------------------------------------------

/// Verify a batchable OR proof: the disjunction of `branches`, over the
/// `instance` (the concatenation of the branch labels), for the given suite.
/// `simple_protocol_id` is the group's linear-relation identifier (e.g.
/// `sigma-proofs_Shake128_P256`); the composed identifier is derived from it.
/// Returns whether the proof is valid.
pub fn verify_or_batchable(
    branches: &[LinearRelation],
    simple_protocol_id: &[u8],
    session: &[u8],
    instance: &[u8],
    proof: &[u8],
) -> Result<bool, MalformedInput> {
    let protocol_identifier = composed_or_protocol_id(simple_protocol_id, branches.len());
    let mut cur = Cursor::new(proof);

    // Deserialize the commitment tree; its exact bytes are what the transcript
    // absorbed (commitment.encode() == its tagged serialization).
    let commitment_start = cur.pos;
    let commitment = parse_commitment(&mut cur, 0)?;
    let commitment_bytes = &proof[commitment_start..cur.pos];
    let response = parse_response(&mut cur, 0)?;
    if cur.pos != proof.len() {
        return Err(MalformedInput);
    }

    let (Commitment::Composed(branch_commitments), Response::Or(compressed, branch_responses)) =
        (&commitment, &response)
    else {
        return Err(MalformedInput);
    };
    if branch_commitments.len() != branches.len()
        || branch_responses.len() != branches.len()
    {
        return Err(MalformedInput);
    }

    // Derive the transcript challenge, then split it across branches.
    let mut transcript = init_transcript(&protocol_identifier, session, instance);
    transcript.absorb(commitment_bytes);
    let challenge = challenge_scalar(&mut transcript);
    let branch_challenges =
        or_branch_challenges(branches.len(), &challenge, compressed)
            .ok_or(MalformedInput)?;

    // Each branch must verify under its own challenge.
    for (((relation, commit), resp), branch_challenge) in branches
        .iter()
        .zip(branch_commitments)
        .zip(branch_responses)
        .zip(&branch_challenges)
    {
        let (Commitment::Simple(commit_points), Response::Simple(resp_scalars)) =
            (commit, resp)
        else {
            return Err(MalformedInput);
        };
        if !relation.verify_transcript(commit_points, branch_challenge, resp_scalars)? {
            return Ok(false);
        }
    }
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // Golden P-256 OR-proof vector (testdata/or_proof_p256_vector.txt), emitted
    // by sigma-rs: OR of [discrete_log (simulated), DLEQ (real)].
    const PROTOCOL_ID: &[u8] = b"sigma-proofs_Shake128_P256";
    const SESSION: &str = "6f725f70726f6f665f6578616d706c65";
    // Composed instance = discrete_log label (86 B) || DLEQ label.
    const INSTANCE: &str = "0100000001000000010000000000000000000000036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296026780c5fc70275e2c7061a0e7877bb174deadeb9887027f3fa83654158ba7f50c020000000100000001000000000000000000000003000000010000000000000002000000036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29602fb50388f29498d0a93ad25ec4c34037b9d3cc3cca4787eb6fedabe2b3003eac8028e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a3023f53a2e061a6f7306cf2ca298f96c9d7e2e162fee67d2d2228d83237856bcca4";
    const PROOF: &str = "02020000000001000000026499c0a0a83ec41edbcdb79417e9549d8e06d2b346955a57670b55bdbb93124100020000000256ea6520e0de34d9b48fc0c927d6db8add4ad028d4c71ed9618ffba33a73ffdf027320be50c10bf48a08e1d0cc532825877fd99ce0021ce385e9d2da1858652a3f0201000000c4554d1ecdf6c9248385fb5ddc81441e2eeb45e3a79ae592b1643ad9061e477a02000000000100000033545092a14c770d9de8eaf4ffcf18731010edd1e5ceb3d375f9082ecab11d920001000000d42e51f7f2eae276c730c5cd22722ca7a7c525ef95e10d7141f67aedda7659b7";
    const EXPECTED_CHALLENGE: &str = "8328bb975a8b628a6be2c5c2570869c284b217e018ad8c9ace71763deeb1e89a";

    #[test]
    fn or_transcript_challenge_matches_sigma_rs() {
        // Reproduce the transcript up to the challenge and compare to the
        // value sigma-rs derives for the same proof (isolates transcript from
        // branch verification).
        use crate::codec::{challenge_scalar, init_transcript};
        let instance = unhex(INSTANCE);
        let proof = unhex(PROOF);
        // Commitment tree bytes = leading portion up to the response tag. The
        // commitment is: TAG_OR(1) len(4) [SIMPLE(1) len(4) 33] [SIMPLE(1) len(4) 66].
        let commit_len = 1 + 4 + (1 + 4 + 33) + (1 + 4 + 66);
        let pid = composed_or_protocol_id(PROTOCOL_ID, 2);
        let mut transcript = init_transcript(&pid, &unhex(SESSION), &instance);
        transcript.absorb(&proof[..commit_len]);
        let c = challenge_scalar(&mut transcript);
        assert_eq!(hex(&c.to_bytes()), EXPECTED_CHALLENGE, "transcript challenge mismatch");
    }

    #[test]
    fn or_proof_golden_vector_verifies() {
        let instance = unhex(INSTANCE);
        // The composed instance is discrete_log label (86 B) then DLEQ label.
        let branch0 = LinearRelation::parse(&instance[..86]).unwrap();
        let branch1 = LinearRelation::parse(&instance[86..]).unwrap();
        let branches = [branch0, branch1];

        let ok = verify_or_batchable(
            &branches,
            PROTOCOL_ID,
            &unhex(SESSION),
            &instance,
            &unhex(PROOF),
        )
        .unwrap();
        assert!(ok, "OR proof golden vector must verify byte-exact");
    }

    #[test]
    fn or_prover_roundtrips_for_each_real_branch() {
        // Our OR prover must produce proofs our (byte-exact) verifier accepts,
        // regardless of which branch holds the real witness. Branch 0 is
        // discrete_log P1=x1*G (1 scalar), branch 1 is DLEQ (1 scalar).
        let instance = unhex(INSTANCE);
        let branch0 = LinearRelation::parse(&instance[..86]).unwrap();
        let branch1 = LinearRelation::parse(&instance[86..]).unwrap();
        let branches = [branch0, branch1];
        let session = unhex(SESSION);
        // Any witness for the chosen real branch works for round-trip (the
        // relation's public points are from the vector, but the prover only
        // needs a scalar; the verifier checks the equation, which holds for
        // whatever witness/nonces produce the commitment). Use the vector's
        // real witness x2 for branch 1, and an arbitrary scalar for branch 0
        // is not meaningful (P1's dlog is unknown) — so we test real=1 with x2
        // and, for real=0, we build a fresh discrete_log branch we do know.
        let x2 = Scalar::from_bytes_reduced(
            &unhex("00000000000000000000000000000000000000000000000000000000075bcd15")
                .try_into()
                .unwrap(),
        );
        let proof =
            prove_or_batchable(&branches, 1, &[x2], PROTOCOL_ID, &session, &instance).unwrap();
        assert!(
            verify_or_batchable(&branches, PROTOCOL_ID, &session, &instance, &proof).unwrap(),
            "OR prover (real branch 1) must round-trip"
        );

        // real = 0: construct a discrete_log branch whose witness we know, so
        // both branches are honest-provable; instance = both labels.
        let x0 = Scalar::from_u64(1234567);
        let g = crate::Point::mul_generator(&Scalar::from_u64(1));
        let p0 = g.mul(&x0);
        // discrete_log label: header 01000000 01000000 01000000 00000000
        // 00000000 || G || P0.
        let mut label0 = Vec::new();
        for v in [1u32, 1, 1, 0, 0] {
            label0.extend_from_slice(&v.to_le_bytes());
        }
        label0.extend_from_slice(&g.to_bytes());
        label0.extend_from_slice(&p0.to_bytes());
        let dl0 = LinearRelation::parse(&label0).unwrap();
        let mut label1 = label0.clone();
        let p1 = g.mul(&Scalar::from_u64(99));
        label1[20 + 33..20 + 66].copy_from_slice(&p1.to_bytes());
        let dl1 = LinearRelation::parse(&label1).unwrap();
        let mut composed_instance = label0.clone();
        composed_instance.extend_from_slice(&label1);
        let two = [dl0, dl1];
        let proof0 =
            prove_or_batchable(&two, 0, &[x0], PROTOCOL_ID, &session, &composed_instance)
                .unwrap();
        assert!(
            verify_or_batchable(&two, PROTOCOL_ID, &session, &composed_instance, &proof0)
                .unwrap(),
            "OR prover (real branch 0) must round-trip"
        );
    }

    #[test]
    fn or_proof_tampered_rejected() {
        let instance = unhex(INSTANCE);
        let branch0 = LinearRelation::parse(&instance[..86]).unwrap();
        let branch1 = LinearRelation::parse(&instance[86..]).unwrap();
        let branches = [branch0, branch1];
        let mut proof = unhex(PROOF);
        let last = proof.len() - 1;
        proof[last] ^= 0x01;
        let ok = verify_or_batchable(
            &branches,
            PROTOCOL_ID,
            &unhex(SESSION),
            &instance,
            &proof,
        )
        .unwrap_or(false);
        assert!(!ok);
    }

    // Real branches for the malformed-input tests below.
    fn golden_branches() -> [LinearRelation; 2] {
        let instance = unhex(INSTANCE);
        [
            LinearRelation::parse(&instance[..86]).unwrap(),
            LinearRelation::parse(&instance[86..]).unwrap(),
        ]
    }

    #[test]
    fn oversized_length_prefix_rejected() {
        // A commitment node claiming ~u32::MAX children with no body must be
        // rejected before the allocator is asked for gigabytes.
        let mut proof = Vec::new();
        proof.push(TAG_OR);
        proof.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        let branches = golden_branches();
        assert_eq!(
            verify_or_batchable(&branches, PROTOCOL_ID, &unhex(SESSION), &unhex(INSTANCE), &proof),
            Err(MalformedInput)
        );
    }

    #[test]
    fn deeply_nested_composition_rejected() {
        // A chain of composite headers deeper than MAX_DEPTH must be rejected
        // without overflowing the stack during recursive parsing.
        let mut proof = Vec::new();
        for _ in 0..(MAX_DEPTH + 2) {
            proof.push(TAG_OR);
            proof.extend_from_slice(&1u32.to_le_bytes());
        }
        let branches = golden_branches();
        assert_eq!(
            verify_or_batchable(&branches, PROTOCOL_ID, &unhex(SESSION), &unhex(INSTANCE), &proof),
            Err(MalformedInput)
        );
    }

    #[test]
    fn noncanonical_branch_scalar_rejected() {
        // Overwrite the stored branch challenge with the group order `n`
        // (non-canonical, `>= n`); parsing the response tree must reject it.
        let branches = golden_branches();
        let instance = unhex(INSTANCE);
        let mut proof = unhex(PROOF);
        // Response section layout (see prove_or_batchable):
        //   TAG_OR | len(n-1)=1 | challenge[32] | ...
        // Locate the stored challenge: it follows the commitment tree, the
        // response TAG_OR byte, and the u32 count.
        let commit_len = 1 + 4 + (1 + 4 + 33) + (1 + 4 + 66);
        let challenge_off = commit_len + 1 + 4;
        let n_bytes =
            unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        proof[challenge_off..challenge_off + SCALAR_BYTES].copy_from_slice(&n_bytes);
        assert_eq!(
            verify_or_batchable(&branches, PROTOCOL_ID, &unhex(SESSION), &instance, &proof),
            Err(MalformedInput)
        );
    }
}
