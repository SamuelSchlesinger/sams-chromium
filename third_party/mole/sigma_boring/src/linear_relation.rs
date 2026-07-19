// Copyright 2026 The Chromium Authors
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

//! Generic Schnorr proofs over a linear relation (Maurer's generalized Sigma
//! protocol), reproducing sigma-proofs' `CanonicalLinearRelation` byte-for-byte
//! for the `sigma-proofs_Shake128_P256` suite.
//!
//! A relation is a set of constraints `image_i = Σ_j scalar_j · group_k`. A
//! batchable proof is `ne` commitments (one per constraint) followed by
//! `num_scalars` responses. Verification recomputes the Fiat-Shamir challenge
//! from the transcript and checks, per constraint,
//! `Σ_j response_j · group_k == commitment_i + challenge · image_i`.

use crate::codec::{challenge_scalar, init_transcript};
use crate::{Point, Scalar, POINT_BYTES, SCALAR_BYTES};

/// One RHS term: a scalar variable index and a group-element index.
struct Term {
    scalar_index: usize,
    group_index: usize,
}

/// A parsed canonical linear relation (the statement).
pub struct LinearRelation {
    /// Per constraint: the image (LHS) group-element index and its RHS terms.
    constraints: Vec<(usize, Vec<Term>)>,
    /// The group elements referenced by index.
    group_elements: Vec<Point>,
    /// The number of distinct scalar variables.
    num_scalars: usize,
}

/// An error parsing a statement or proof.
#[derive(Debug, PartialEq, Eq)]
pub struct MalformedInput;

fn read_u32_le(buf: &mut &[u8]) -> Result<usize, MalformedInput> {
    if buf.len() < 4 {
        return Err(MalformedInput);
    }
    let v = u32::from_le_bytes(buf[..4].try_into().unwrap());
    *buf = &buf[4..];
    Ok(v as usize)
}

/// Builds a linear relation programmatically and emits its canonical label
/// (the statement), reproducing sigma-proofs' `CanonicalLinearRelation`
/// encoding. The ACT and IHAT ports construct their relations through this,
/// rather than parsing statement bytes.
///
/// Canonical group ordering: constraints are processed in order; within each,
/// its RHS term elements (in term order, first use only) are assigned the
/// next group indices, then its image element.
pub struct RelationBuilder {
    num_scalars: usize,
    /// Allocated elements by identity (allocation index) -> point.
    elements: Vec<Point>,
    /// Per constraint: (image element id, [(scalar id, element id)]).
    constraints: Vec<(usize, Vec<(usize, usize)>)>,
}

impl Default for RelationBuilder {
    fn default() -> Self {
        RelationBuilder { num_scalars: 0, elements: Vec::new(), constraints: Vec::new() }
    }
}

impl RelationBuilder {
    /// Allocate a scalar variable; returns its id.
    pub fn scalar(&mut self) -> usize {
        let id = self.num_scalars;
        self.num_scalars += 1;
        id
    }

    /// Allocate a group element with a fixed point; returns its id.
    pub fn element(&mut self, point: Point) -> usize {
        self.elements.push(point);
        self.elements.len() - 1
    }

    /// Add the constraint `image = Σ_j scalar_j · element_j`, where `image` is
    /// a fresh group element with the given point. Returns the image's id.
    pub fn constrain(&mut self, image: Point, terms: &[(usize, usize)]) -> usize {
        let image_id = self.element(image);
        self.constraints.push((image_id, terms.to_vec()));
        image_id
    }

    /// Finalize into a [`LinearRelation`] and its canonical label bytes.
    pub fn build(self) -> (LinearRelation, Vec<u8>) {
        // Assign canonical group indices in first-use order: for each
        // constraint, its term elements then its image.
        let mut group_index = vec![usize::MAX; self.elements.len()];
        let mut ordered: Vec<Point> = Vec::new();
        let assign = |id: usize, group_index: &mut Vec<usize>, ordered: &mut Vec<Point>| {
            if group_index[id] == usize::MAX {
                group_index[id] = ordered.len();
                ordered.push(self.elements[id].clone());
            }
        };
        for (image_id, terms) in &self.constraints {
            for (_, elem_id) in terms {
                assign(*elem_id, &mut group_index, &mut ordered);
            }
            assign(*image_id, &mut group_index, &mut ordered);
        }

        // Canonical constraints with resolved group indices.
        let constraints: Vec<(usize, Vec<Term>)> = self
            .constraints
            .iter()
            .map(|(image_id, terms)| {
                (
                    group_index[*image_id],
                    terms
                        .iter()
                        .map(|(s, e)| Term { scalar_index: *s, group_index: group_index[*e] })
                        .collect(),
                )
            })
            .collect();

        // Emit the label: ne, per-constraint (lhs, nterms, terms), then points.
        let mut label = Vec::new();
        label.extend_from_slice(&(constraints.len() as u32).to_le_bytes());
        for (lhs, terms) in &constraints {
            label.extend_from_slice(&(*lhs as u32).to_le_bytes());
            label.extend_from_slice(&(terms.len() as u32).to_le_bytes());
            for term in terms {
                label.extend_from_slice(&(term.scalar_index as u32).to_le_bytes());
                label.extend_from_slice(&(term.group_index as u32).to_le_bytes());
            }
        }
        for point in &ordered {
            label.extend_from_slice(&point.to_bytes());
        }

        let relation = LinearRelation {
            constraints,
            group_elements: ordered,
            num_scalars: self.num_scalars,
        };
        (relation, label)
    }
}

impl LinearRelation {
    /// Parse a relation from its canonical label encoding (the statement).
    pub fn parse(statement: &[u8]) -> Result<Self, MalformedInput> {
        let mut buf = statement;
        let ne = read_u32_le(&mut buf)?;

        // Each constraint occupies at least 8 bytes (lhs u32 + n_terms u32); an
        // `ne` larger than the buffer could hold is malformed, so reject before
        // allocating to keep an attacker's length prefix from forcing an OOM.
        if ne > buf.len() / 8 {
            return Err(MalformedInput);
        }
        let mut constraints = Vec::with_capacity(ne);
        let mut num_scalars = 0usize;
        for _ in 0..ne {
            let lhs_index = read_u32_le(&mut buf)?;
            let n_terms = read_u32_le(&mut buf)?;
            // Each term is 8 bytes (scalar u32 + group u32); bound likewise.
            if n_terms > buf.len() / 8 {
                return Err(MalformedInput);
            }
            let mut terms = Vec::with_capacity(n_terms);
            for _ in 0..n_terms {
                let scalar_index = read_u32_le(&mut buf)?;
                let group_index = read_u32_le(&mut buf)?;
                num_scalars = num_scalars.max(scalar_index + 1);
                terms.push(Term { scalar_index, group_index });
            }
            constraints.push((lhs_index, terms));
        }

        // The remainder is the group elements, each compressed (33 bytes).
        if buf.len() % POINT_BYTES != 0 {
            return Err(MalformedInput);
        }
        let mut group_elements = Vec::with_capacity(buf.len() / POINT_BYTES);
        for chunk in buf.chunks_exact(POINT_BYTES) {
            let bytes: [u8; POINT_BYTES] = chunk.try_into().unwrap();
            group_elements.push(Point::from_bytes(&bytes).ok_or(MalformedInput)?);
        }

        Ok(LinearRelation { constraints, group_elements, num_scalars })
    }

    /// The number of constraints (commitments / image points).
    pub fn num_constraints(&self) -> usize {
        self.constraints.len()
    }

    /// The number of scalar variables (witness length).
    pub fn num_scalars(&self) -> usize {
        self.num_scalars
    }

    /// Check a Sigma transcript against this relation for a supplied
    /// challenge: `Σ_j response_j · group_k == commitment_i + challenge ·
    /// image_i` for every constraint `i`. This is the per-branch check the
    /// AND/OR composition reuses (the challenge comes from the composition's
    /// challenge split, not the transcript directly).
    pub fn verify_transcript(
        &self,
        commitments: &[Point],
        challenge: &Scalar,
        responses: &[Scalar],
    ) -> Result<bool, MalformedInput> {
        if commitments.len() != self.num_constraints()
            || responses.len() != self.num_scalars
        {
            return Err(MalformedInput);
        }
        for (i, (lhs_index, terms)) in self.constraints.iter().enumerate() {
            let image = self.group_elements.get(*lhs_index).ok_or(MalformedInput)?;
            let mut lhs = Point::identity();
            for term in terms {
                let g = self
                    .group_elements
                    .get(term.group_index)
                    .ok_or(MalformedInput)?;
                lhs = lhs.add(&g.mul(&responses[term.scalar_index]));
            }
            let rhs = commitments[i].add(&image.mul(challenge));
            if !lhs.eq(&rhs) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Evaluate the relation's linear map on `scalars`, producing one group
    /// element per constraint: `out_i = Σ_j scalars_j · group_k`.
    pub(crate) fn evaluate(&self, scalars: &[Scalar]) -> Vec<Point> {
        self.constraints
            .iter()
            .map(|(_, terms)| {
                let mut acc = Point::identity();
                for term in terms {
                    let g = &self.group_elements[term.group_index];
                    acc = acc.add(&g.mul(&scalars[term.scalar_index]));
                }
                acc
            })
            .collect()
    }

    /// Produce a batchable proof of knowledge of `witness` (the Fiat-Shamir
    /// Schnorr prover): random nonces → commitments, challenge from the
    /// transcript, `response_j = nonce_j + c · witness_j`. Serialized as `ne`
    /// compressed commitments followed by `num_scalars` 32-byte responses,
    /// matching the sigma-proofs batchable layout.
    pub fn prove_batchable(
        &self,
        witness: &[Scalar],
        protocol_identifier: &[u8],
        session: &[u8],
        statement: &[u8],
    ) -> Vec<u8> {
        assert_eq!(witness.len(), self.num_scalars, "witness length mismatch");
        let nonces: Vec<Scalar> =
            (0..self.num_scalars).map(|_| Scalar::random()).collect();
        let commitments = self.evaluate(&nonces);

        let mut transcript = init_transcript(protocol_identifier, session, statement);
        for commitment in &commitments {
            transcript.absorb(&commitment.to_bytes());
        }
        let challenge = challenge_scalar(&mut transcript);

        let responses: Vec<Scalar> = nonces
            .iter()
            .zip(witness)
            .map(|(nonce, w)| nonce.add(&w.mul(&challenge)))
            .collect();

        let mut proof =
            Vec::with_capacity(commitments.len() * POINT_BYTES + witness.len() * SCALAR_BYTES);
        for commitment in &commitments {
            proof.extend_from_slice(&commitment.to_bytes());
        }
        for response in &responses {
            proof.extend_from_slice(&response.to_bytes());
        }
        proof
    }

    /// Verify a batchable proof against this relation for the given suite.
    /// `proof` is `ne` compressed commitments followed by `num_scalars`
    /// 32-byte responses.
    pub fn verify_batchable(
        &self,
        protocol_identifier: &[u8],
        session: &[u8],
        statement: &[u8],
        proof: &[u8],
    ) -> Result<bool, MalformedInput> {
        let ne = self.num_constraints();
        let expected_len = ne * POINT_BYTES + self.num_scalars * SCALAR_BYTES;
        if proof.len() != expected_len {
            return Err(MalformedInput);
        }

        // Split off the commitments (in constraint order) and responses.
        let (commitment_bytes, response_bytes) = proof.split_at(ne * POINT_BYTES);
        let commitments = commitment_bytes
            .chunks_exact(POINT_BYTES)
            .map(|c| Point::from_bytes(&c.try_into().unwrap()).ok_or(MalformedInput))
            .collect::<Result<Vec<_>, _>>()?;
        // Wire responses must be canonical (`< n`); reject non-canonical
        // encodings rather than reducing, matching the reference and closing
        // scalar malleability on the proof.
        let responses: Vec<Scalar> = response_bytes
            .chunks_exact(SCALAR_BYTES)
            .map(|c| Scalar::from_canonical_bytes(&c.try_into().unwrap()).ok_or(MalformedInput))
            .collect::<Result<Vec<_>, _>>()?;

        // Reconstruct the transcript and derive the challenge: seed + session +
        // instance, then absorb every commitment in order.
        let mut transcript = init_transcript(protocol_identifier, session, statement);
        for commitment in &commitments {
            transcript.absorb(&commitment.to_bytes());
        }
        let challenge = challenge_scalar(&mut transcript);

        // Per constraint: Σ_j response_j · group_k == commitment_i + c · image_i.
        for (i, (lhs_index, terms)) in self.constraints.iter().enumerate() {
            let image = self.group_elements.get(*lhs_index).ok_or(MalformedInput)?;
            let mut lhs = Point::identity();
            for term in terms {
                let g = self
                    .group_elements
                    .get(term.group_index)
                    .ok_or(MalformedInput)?;
                let response = responses.get(term.scalar_index).ok_or(MalformedInput)?;
                lhs = lhs.add(&g.mul(response));
            }
            let rhs = commitments[i].add(&image.mul(&challenge));
            if !lhs.eq(&rhs) {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Simulate the commitments of a transcript from the challenge and
    /// responses: `R_i = Σ_j response_j · group_k − c · image_i`.
    pub(crate) fn simulate_commitments(
        &self,
        challenge: &Scalar,
        responses: &[Scalar],
    ) -> Result<Vec<Point>, MalformedInput> {
        let neg_c = challenge.negate();
        self.constraints
            .iter()
            .map(|(lhs_index, terms)| {
                let image = self.group_elements.get(*lhs_index).ok_or(MalformedInput)?;
                let mut acc = Point::identity();
                for term in terms {
                    let g = self
                        .group_elements
                        .get(term.group_index)
                        .ok_or(MalformedInput)?;
                    let response =
                        responses.get(term.scalar_index).ok_or(MalformedInput)?;
                    acc = acc.add(&g.mul(response));
                }
                Ok(acc.add(&image.mul(&neg_c)))
            })
            .collect()
    }

    /// Verify a compact proof: `challenge` (32) followed by `num_scalars`
    /// 32-byte responses. Recomputes the commitments, re-derives the
    /// Fiat-Shamir challenge from the transcript, and checks it matches.
    pub fn verify_compact(
        &self,
        protocol_identifier: &[u8],
        session: &[u8],
        statement: &[u8],
        proof: &[u8],
    ) -> Result<bool, MalformedInput> {
        let expected_len = SCALAR_BYTES + self.num_scalars * SCALAR_BYTES;
        if proof.len() != expected_len {
            return Err(MalformedInput);
        }
        let (challenge_bytes, response_bytes) = proof.split_at(SCALAR_BYTES);
        // Compact challenge and responses are canonical on the wire; reject
        // non-canonical encodings (see verify_batchable).
        let challenge = Scalar::from_canonical_bytes(&challenge_bytes.try_into().unwrap())
            .ok_or(MalformedInput)?;
        let responses: Vec<Scalar> = response_bytes
            .chunks_exact(SCALAR_BYTES)
            .map(|c| Scalar::from_canonical_bytes(&c.try_into().unwrap()).ok_or(MalformedInput))
            .collect::<Result<Vec<_>, _>>()?;

        let commitments = self.simulate_commitments(&challenge, &responses)?;
        let mut transcript = init_transcript(protocol_identifier, session, statement);
        for commitment in &commitments {
            transcript.absorb(&commitment.to_bytes());
        }
        let recomputed = challenge_scalar(&mut transcript);
        Ok(recomputed.ct_eq(&challenge))
    }

    /// Produce a compact proof: `challenge` followed by the responses (the
    /// commitments are recomputed by the verifier).
    pub fn prove_compact(
        &self,
        witness: &[Scalar],
        protocol_identifier: &[u8],
        session: &[u8],
        statement: &[u8],
    ) -> Vec<u8> {
        assert_eq!(witness.len(), self.num_scalars, "witness length mismatch");
        let nonces: Vec<Scalar> =
            (0..self.num_scalars).map(|_| Scalar::random()).collect();
        let commitments = self.evaluate(&nonces);

        let mut transcript = init_transcript(protocol_identifier, session, statement);
        for commitment in &commitments {
            transcript.absorb(&commitment.to_bytes());
        }
        let challenge = challenge_scalar(&mut transcript);

        let mut proof = Vec::with_capacity((1 + witness.len()) * SCALAR_BYTES);
        proof.extend_from_slice(&challenge.to_bytes());
        for (nonce, w) in nonces.iter().zip(witness) {
            proof.extend_from_slice(&nonce.add(&w.mul(&challenge)).to_bytes());
        }
        proof
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROTOCOL_ID: &[u8] = b"sigma-proofs_Shake128_P256";

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    // The five official spec vectors (Statement, SessionId, Batchable Proof)
    // from sigma-proofs/tests/spec/testdata/sigma-proofs_Shake128_P256.json.
    // Every one must verify under our byte-exact reproduction.
    struct Vector {
        session_hex: &'static str,
        statement_hex: &'static str,
        batchable_hex: &'static str,
        compact_hex: &'static str,
    }

    fn vectors() -> Vec<(&'static str, Vector)> {
        vec![
            ("discrete_logarithm", Vector {
                session_hex: "64697363726574655f6c6f6761726974686d",
                statement_hex: "0100000001000000010000000000000000000000036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29602d135e66a8b8d656fa8e892501d931895ec031701a72aa550039742a8f6325336",
                batchable_hex: "031af107806a9d4f14c569d5a255904f682a7e1cc289ca70f5306d690609bf8f7231ffdce808d01c2ee9354c49c3dcbe6361cce35b81c304abd3a813909ec3c16a",
            compact_hex: "d08bc0386f6ef8b3a431d490a1b30c0ab58341043aa76e59b74493417e65a46ee9488aaa9b728b9ccd5231f1d99daae697e454d67d83522e5bc8de52324f06bd",
            }),
            ("dleq", Vector {
                session_hex: "646c6571",
                statement_hex: "020000000100000001000000000000000000000003000000010000000000000002000000036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29602e7747263366b618a771a284e6139947b17e9c3a96cb573d045db511336fea2b502d135e66a8b8d656fa8e892501d931895ec031701a72aa550039742a8f632533603c2170432aefa48cbbe91aa5be0da997e663528c96bd5652da0b71dbc44b4a157",
                batchable_hex: "031af107806a9d4f14c569d5a255904f682a7e1cc289ca70f5306d690609bf8f7202b9e055385e773efed02af727e2ac21b9dc411ede1789a3186ab779e32c3ebec3fa58b127a6ea224395244ee5a0fc4ed0e99b9e576a7d6bc132e05247bcb658a0",
            compact_hex: "8e9bd4ddb4c4cf342c4b29e9cb6447d1ed7268cbea7bd163408925c6058f1e9a32b29cb837a982782e771e90665cceaae4c2051cd2f9de70a57b5661ae9b4cf4",
            }),
            ("pedersen_commitment", Vector {
                session_hex: "706564657273656e5f636f6d6d69746d656e74",
                statement_hex: "01000000020000000200000000000000000000000100000001000000036b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c29602d135e66a8b8d656fa8e892501d931895ec031701a72aa550039742a8f6325336033f5eec2203e5d6cf13564a3884637cba8d6a835edfe1e7127ed544efa734f33c",
                batchable_hex: "022b3a82ba319b6bb06e1c0df02639fabff6644f03737a6a3129a080abbcbb994279dc23d43310f40de3d3e3a5567dfd74c5c87e7ecb8fae1e06172cfd9d4246eedadbce5fef61c99fc3cea903adfee9d8311943966a63ebc3abbe95566c2094f6",
            compact_hex: "03c2fed5978acc3cf8aaa0ca27ba0f8c594f0f30d54fd480c984c7af1627de1c15d44da987f02c4d9e0fa01f081efa719e8cc778338faa04134017481924f06dc3ee6f245c56bb20aaf97dea5380e09594b7d5d0dce38496e976d2d1a84893f5",
            }),
            ("pedersen_commitment_dleq", Vector {
                session_hex: "706564657273656e5f636f6d6d69746d656e745f646c6571",
                statement_hex: "0200000002000000020000000000000000000000010000000100000005000000020000000000000003000000010000000400000002d135e66a8b8d656fa8e892501d931895ec031701a72aa550039742a8f632533602e7747263366b618a771a284e6139947b17e9c3a96cb573d045db511336fea2b503494cd0367a7478312233f9a9645d2f3f9a68dcfe018d052325c4431b4dc4f78c032aaafb5d7a5a3dd1bad36f580cde19e8995a7a0c0cb79bc4f736b832de95320803dfcb42c94940e5ac6c5ffbabfbb9a8da0132e0db8f414d8bdd01f5ae8fa2143103052d1bd120487fa37744c6da3295f56e76be9c61a4de8a0b0c6c5de177935482",
                batchable_hex: "0384afaabfca8df99914b58ac83c1f16cc0871c95167c672b40f8b79eac10193ae021ebe92eec53b568bc65b0e6bddf3c9ca159fd493690dd28c60a12fa672e163e205ef3af821437ddfd0eb080d0e1babdff75437c1004cc6273164f0352850b73238701b45d0ee56d1be5359f5a25a81acf3f4942bb05f724a8f6713075cfe8b89",
            compact_hex: "131348247c1d6c7b66402a0c5ed4a47af55e37b44c12b7ab0103c00440f9773ddcf334188a910e111c0cf81a1ce25ac13ecdd7dbc8228a93d6f698a87af9d5f58d7b568fbb121a9f81fe2534d2f24a942a81e8daa08f48b09ea773befef5e8f0",
            }),
            ("bbs_blind_commitment_computation", Vector {
                session_hex: "6262735f626c696e645f636f6d6d69746d656e745f636f6d7075746174696f6e",
                statement_hex: "010000000400000004000000000000000000000001000000010000000200000002000000030000000300000002d135e66a8b8d656fa8e892501d931895ec031701a72aa550039742a8f632533602e7747263366b618a771a284e6139947b17e9c3a96cb573d045db511336fea2b5032aaafb5d7a5a3dd1bad36f580cde19e8995a7a0c0cb79bc4f736b832de95320803dfcb42c94940e5ac6c5ffbabfbb9a8da0132e0db8f414d8bdd01f5ae8fa21431024a243b6f8a0030941fde57d57f1a4d418d01e7f398962739fba3bbdb3adfb285",
                batchable_hex: "038b7263580bb33a66bf5b1c1d4dcadce46e89fd58c6224df2c495e4d8447ee24b3caa3feab0ebaa85847f3d2161dccbd22947cdf33ebf5ca0793e31e193b024e1f672cf51e471b286e3161e1dd18f0448cd42d3d8f30e813a6c2f2ccb6a5eb6ce4cb3bc0043639723e6aa48541a4172ab4ebd36e7f7a85aecbf1de4dcc649ff84147c4041813146e03e18d6f916a5b54633a0f68cca2153bc6d7f91bed9c6e351",
            compact_hex: "cc8e3072ee8c305b8409d01a25902d928692d4d29a56655e416afe30efbd97f8b7a3141b009229ea5ebb3e15b8771bbc1317cf125feb902e151a7d29ce254e60ad390b486329d18430e684ef46863524e8be301d21832b2a5dd070a6443070eeb292e90a3808fae2e56417693f4023387e698b2cb2d41f2ffa2551d4124da40bbb34302617a8bf67c7e0b6c73fce3697b15c1c2ef49f4991c27873f0b70a602d",
            }),
        ]
    }

    #[test]
    fn builder_reproduces_spec_statements() {
        // The builder must emit the exact canonical label for the two
        // relation shapes MoLE uses directly (discrete_log for IHAT-style,
        // DLEQ). We rebuild from the spec's own points and require the label
        // to match byte-for-byte.
        let dl = &vectors()[0].1;
        let dl_stmt = unhex(dl.statement_hex);
        let g = Point::from_bytes(&dl_stmt[20..53].try_into().unwrap()).unwrap();
        let p = Point::from_bytes(&dl_stmt[53..86].try_into().unwrap()).unwrap();
        let mut b = RelationBuilder::default();
        let x = b.scalar();
        let g_var = b.element(g);
        b.constrain(p, &[(x, g_var)]);
        let (_, label) = b.build();
        assert_eq!(hex_bytes(&label), dl.statement_hex, "discrete_log label");

        // DLEQ: P = x*G, Q = x*H. Canonical group order [G, P, H, Q].
        let dleq = &vectors()[1].1;
        let dleq_stmt = unhex(dleq.statement_hex);
        // Points are appended after the header in canonical order [G, P, H, Q].
        let hdr = dleq_stmt.len() - 4 * 33;
        let g = Point::from_bytes(&dleq_stmt[hdr..hdr + 33].try_into().unwrap()).unwrap();
        let pp = Point::from_bytes(&dleq_stmt[hdr + 33..hdr + 66].try_into().unwrap()).unwrap();
        let h = Point::from_bytes(&dleq_stmt[hdr + 66..hdr + 99].try_into().unwrap()).unwrap();
        let q = Point::from_bytes(&dleq_stmt[hdr + 99..hdr + 132].try_into().unwrap()).unwrap();
        let mut b = RelationBuilder::default();
        let x = b.scalar();
        let g_var = b.element(g);
        let h_var = b.element(h);
        b.constrain(pp, &[(x, g_var)]);
        b.constrain(q, &[(x, h_var)]);
        let (_, label) = b.build();
        assert_eq!(hex_bytes(&label), dleq.statement_hex, "dleq label");
    }

    fn hex_bytes(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn all_spec_vectors_verify_byte_exact() {
        for (name, v) in vectors() {
            let session = unhex(v.session_hex);
            let statement = unhex(v.statement_hex);
            let proof = unhex(v.batchable_hex);
            let relation = LinearRelation::parse(&statement)
                .unwrap_or_else(|_| panic!("statement must parse: {name}"));
            let ok = relation
                .verify_batchable(PROTOCOL_ID, &session, &statement, &proof)
                .unwrap_or_else(|_| panic!("proof shape must parse: {name}"));
            assert!(ok, "spec vector must verify byte-exact: {name}");
        }
    }

    // Witnesses for the five spec vectors (concatenated 32-byte scalars),
    // from the JSON's "Witness" field, in vector order.
    const WITNESSES: [&str; 5] = [
        "daca1508279cce9abb7fdefc540ec4b9bcf1b689bbcf74ea3123dbd3f5b611b0",
        "92526b41ae23f4820a911c9ba1bdc6493f68ce123871c76a6e74ec43b85494c0",
        "92526b41ae23f4820a911c9ba1bdc6493f68ce123871c76a6e74ec43b85494c0c93640008f20c1c7e267c16a7acef56ce53605f763e94cca43be52e7ad260764",
        "5be9cc0de93d47ccaf8637f1c5a9e26e92b5bc38f6265a96d64bd437ac7d597ab6116295a8d23d4cd60fb53b1ddf7177f95aee639a59dacecf37334a914bded6",
        "895007d818e8c20774be15273e5b8733e345ba359205cbcd98a046f263a7a0ce5be9cc0de93d47ccaf8637f1c5a9e26e92b5bc38f6265a96d64bd437ac7d597ab6116295a8d23d4cd60fb53b1ddf7177f95aee639a59dacecf37334a914bded6c6038561954f5b4d4052c77d8c149a74767e1c478e09dc33e7cfc801f7dfb722",
    ];

    #[test]
    fn prover_roundtrips_for_all_relations() {
        // The prover produces (randomized) proofs that our byte-exact verifier
        // accepts, for every spec relation — proving prover/verifier
        // consistency and, since the verifier matches sigma-rs, sigma-rs
        // compatibility of the prover's output.
        for ((name, v), witness_hex) in vectors().iter().zip(WITNESSES) {
            let session = unhex(v.session_hex);
            let statement = unhex(v.statement_hex);
            let witness_bytes = unhex(witness_hex);
            let relation = LinearRelation::parse(&statement).unwrap();
            let witness: Vec<Scalar> = witness_bytes
                .chunks_exact(SCALAR_BYTES)
                .map(|c| Scalar::from_bytes_reduced(&c.try_into().unwrap()))
                .collect();
            assert_eq!(witness.len(), relation.num_scalars(), "witness len {name}");

            // Two independent proofs must both verify and differ (randomized).
            let proof1 = relation.prove_batchable(&witness, PROTOCOL_ID, &session, &statement);
            let proof2 = relation.prove_batchable(&witness, PROTOCOL_ID, &session, &statement);
            assert_ne!(proof1, proof2, "proofs must be randomized: {name}");
            for proof in [&proof1, &proof2] {
                assert!(
                    relation
                        .verify_batchable(PROTOCOL_ID, &session, &statement, proof)
                        .unwrap(),
                    "prover output must verify: {name}"
                );
            }
        }
    }

    #[test]
    fn all_compact_spec_vectors_verify_byte_exact() {
        for (name, v) in vectors() {
            let session = unhex(v.session_hex);
            let statement = unhex(v.statement_hex);
            let proof = unhex(v.compact_hex);
            let relation = LinearRelation::parse(&statement).unwrap();
            assert!(
                relation
                    .verify_compact(PROTOCOL_ID, &session, &statement, &proof)
                    .unwrap(),
                "compact spec vector must verify byte-exact: {name}"
            );
        }
    }

    #[test]
    fn compact_prover_roundtrips() {
        for ((name, v), witness_hex) in vectors().iter().zip(WITNESSES) {
            let session = unhex(v.session_hex);
            let statement = unhex(v.statement_hex);
            let relation = LinearRelation::parse(&statement).unwrap();
            let witness: Vec<Scalar> = unhex(witness_hex)
                .chunks_exact(SCALAR_BYTES)
                .map(|c| Scalar::from_bytes_reduced(&c.try_into().unwrap()))
                .collect();
            let proof = relation.prove_compact(&witness, PROTOCOL_ID, &session, &statement);
            assert!(
                relation
                    .verify_compact(PROTOCOL_ID, &session, &statement, &proof)
                    .unwrap(),
                "compact prover output must verify: {name}"
            );
        }
    }

    #[test]
    fn wrong_witness_fails_verification() {
        // A proof under the wrong witness must not verify (soundness).
        let (_, v) = &vectors()[0];
        let session = unhex(v.session_hex);
        let statement = unhex(v.statement_hex);
        let relation = LinearRelation::parse(&statement).unwrap();
        let wrong = vec![Scalar::from_bytes_reduced(&[0x42u8; 32])];
        let proof = relation.prove_batchable(&wrong, PROTOCOL_ID, &session, &statement);
        assert!(!relation
            .verify_batchable(PROTOCOL_ID, &session, &statement, &proof)
            .unwrap());
    }

    #[test]
    fn tampered_proof_rejected() {
        let v = &vectors()[0].1;
        let session = unhex(v.session_hex);
        let statement = unhex(v.statement_hex);
        let mut proof = unhex(v.batchable_hex);
        // Flip a byte in the response; verification must fail.
        let last = proof.len() - 1;
        proof[last] ^= 0x01;
        let relation = LinearRelation::parse(&statement).unwrap();
        assert!(!relation
            .verify_batchable(PROTOCOL_ID, &session, &statement, &proof)
            .unwrap_or(false));
    }

    #[test]
    fn oversized_constraint_count_rejected() {
        // A near-u32::MAX constraint count with an empty body must be rejected
        // before allocating, not drive a multi-gigabyte reservation.
        let mut stmt = Vec::new();
        stmt.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        assert!(LinearRelation::parse(&stmt).is_err());

        // Likewise an oversized per-constraint term count.
        let mut stmt = Vec::new();
        stmt.extend_from_slice(&1u32.to_le_bytes()); // ne = 1
        stmt.extend_from_slice(&0u32.to_le_bytes()); // lhs index
        stmt.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // n_terms
        assert!(LinearRelation::parse(&stmt).is_err());
    }

    #[test]
    fn noncanonical_response_rejected() {
        // Replace a proof response scalar with the group order `n` (>= n, hence
        // non-canonical); the byte-exact reference rejects it, and so must we.
        let v = &vectors()[0].1;
        let session = unhex(v.session_hex);
        let statement = unhex(v.statement_hex);
        let relation = LinearRelation::parse(&statement).unwrap();
        let mut proof = unhex(v.batchable_hex);
        let resp_start = relation.num_constraints() * POINT_BYTES;
        let n_bytes =
            unhex("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
        proof[resp_start..resp_start + SCALAR_BYTES].copy_from_slice(&n_bytes);
        assert_eq!(
            relation.verify_batchable(PROTOCOL_ID, &session, &statement, &proof),
            Err(MalformedInput)
        );
    }
}
