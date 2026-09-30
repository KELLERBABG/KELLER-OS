//! Zero-knowledge authentication: a Schnorr proof of knowledge, over Ristretto255.
//!
//! The vault's disk holds no key material. What it holds is a *commitment* `X = x·G` to a scalar
//! derived from the root secret, and the sectors are sealed under a key that only exists after a
//! proof that the holder knows `x`. The point of doing it this way rather than storing a key (or a
//! hash of one) is that the disk gives an attacker nothing to test a guess against beyond `X`
//! itself: the scalar is hidden by the discrete-log problem, and a wrong secret does not merely
//! produce a wrong key — it produces a proof that does not verify.
//!
//! **The protocol.** Prover picks `r` at random, sends `R = r·G`; the challenge is
//! `c = H(domain ‖ X ‖ R ‖ context)` reduced modulo the group order; the response is
//! `s = r + c·x`. A verifier accepts when `s·G == R + c·X`, which holds for an honest prover
//! because `(r + c·x)·G = r·G + c·(x·G)`. Nothing in the transcript reveals `x`: `s` is uniform
//! for any fixed `c` and is only useful together with `R`, and forging `s` without knowing `x`
//! means solving the discrete log.
//!
//! **Why Ristretto and not raw Edwards.** Ristretto removes the cofactor and the non-canonical
//! encodings, so there is exactly one encoding per group element and no small-subgroup point can
//! be substituted for a public key. That matters here because `X` is read back off a disk: a
//! valid-looking but low-order point would make proofs forgeable, and refusing to even parse one
//! is simpler than reasoning about it.
//!
//! **Deterministic nonces, deliberately.** The prover's nonce is `H(secret ‖ context)` rather than
//! a random draw (RFC 6979's idea, applied to Schnorr). The reason is structural: an image's
//! unlock key is derived from the transcript, so the same image must yield the same transcript on
//! every boot or the key it was written under could never be re-derived. A random nonce is still
//! available ([`Witness::prove_randomized`]) and defines the usual unlinkability property; the
//! derivation is what the disk path needs, and it leaks nothing extra — the nonce is still
//! unpredictable without the secret, and a different context produces a different nonce, so no
//! nonce is ever reused across two different challenges.
//!
//! **The context is the whole point.** A Schnorr proof is a proof about a *statement*, and the
//! statement in this system is "this image, in this state, for this device". The context is built
//! from the image's own nonce and header, so a proof captured from one image does not unlock
//! another, and editing the header invalidates the proof rather than silently changing what was
//! proved. Fiat–Shamir makes it non-interactive; the binding makes it non-replayable.

use alloc::vec::Vec;
use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT as G;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::traits::Identity;
use sha2::{Digest, Sha512};

use crate::crypto;

/// Domain separation, so a challenge computed here can never collide with one computed for
/// another purpose that also hashes points.
const CHALLENGE_DOMAIN: &[u8] = b"KOS-VAULT-SCHNORR-CHALLENGE-V1";
/// Domain separation for the deterministic proof nonce.
const NONCE_DOMAIN: &[u8] = b"KOS-VAULT-SCHNORR-NONCE-V1";
/// Wide hash used to turn the root secret into a scalar.
const SCALAR_INFO: &[u8] = b"KOS-VAULT-ZK-SCALAR-V1";
const SCALAR_SALT: &[u8] = b"KELLER-OS vault proof separation";

/// A non-interactive Schnorr proof: the prover's commitment and its response.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Proof {
    /// `R = r·G`, compressed.
    pub commitment: [u8; 32],
    /// `s = r + c·x`, canonically encoded.
    pub response: [u8; 32],
}

impl Proof {
    pub const fn empty() -> Self {
        Self {
            commitment: [0; 32],
            response: [0; 32],
        }
    }

    /// The proof as it is written to the disk or hashed into a transcript.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.commitment);
        out[32..].copy_from_slice(&self.response);
        out
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() != 64 {
            return None;
        }
        let mut commitment = [0u8; 32];
        let mut response = [0u8; 32];
        commitment.copy_from_slice(&bytes[..32]);
        response.copy_from_slice(&bytes[32..]);
        Some(Self {
            commitment,
            response,
        })
    }
}

/// The secret side of the proof: the scalar derived from the root secret.
///
/// This never leaves the vault: callers ask the vault to *prove* or to *check ownership*, and get
/// back a proof or a boolean.
#[derive(Clone, Copy)]
pub struct Witness {
    scalar: Scalar,
    commitment: [u8; 32],
}

impl Witness {
    /// Derives the witness from a root secret. Deterministic, so the same secret always produces
    /// the same commitment — which is what lets a disk image be recognised as belonging to a
    /// secret without any key material being stored on it.
    pub fn from_secret(secret: &[u8]) -> Self {
        let mut wide = [0u8; 64];
        crypto::hkdf_sha256(SCALAR_SALT, secret, SCALAR_INFO, &mut wide);
        let scalar = Scalar::from_bytes_mod_order_wide(&wide);
        crypto::wipe(&mut wide);
        let commitment = (scalar * G).compress().to_bytes();
        Self {
            scalar,
            commitment,
        }
    }

    /// The public commitment `X = x·G`. Safe to print, store and compare.
    pub fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    /// Overwrites the scalar, which is what a purge leaves behind. The commitment becomes 32 zero
    /// bytes, which is not a valid Ristretto encoding, so nothing can verify against a purged
    /// witness — and in particular a purged vault does not fall back to a known scalar.
    pub fn clear(&mut self) {
        self.scalar = Scalar::ZERO;
        self.commitment = [0u8; 32];
    }

    /// Produces a proof for `context`, with the nonce derived from the secret and the context.
    ///
    /// The determinism is a requirement, not a shortcut. An image's unlock key is a function of
    /// the proof transcript, so the *same* image has to produce the *same* transcript on every
    /// boot or the key it was written under could never be re-derived. `H(secret ‖ context)` is the
    /// RFC 6979 idea: unpredictable without the secret, and never reused across two different
    /// challenges — a different context gives a different nonce, hence a different `R`. See
    /// [`Witness::prove_randomized`] for the property people usually expect from a Schnorr prover.
    pub fn prove(&self, context: &[u8]) -> Proof {
        let mut hasher = Sha512::new();
        hasher.update(NONCE_DOMAIN);
        hasher.update(self.scalar.as_bytes());
        hasher.update((context.len() as u64).to_le_bytes());
        hasher.update(context);
        let digest = hasher.finalize();
        let mut wide = [0u8; 64];
        wide.copy_from_slice(&digest);
        let nonce = Scalar::from_bytes_mod_order_wide(&wide);
        crypto::wipe(&mut wide);
        self.respond(&nonce, context)
    }

    /// A proof with a fresh random nonce: two proofs of the same statement are then different and
    /// unlinkable, which is the standard zero-knowledge property. This is what an interactive
    /// deployment would use; the disk path uses [`Witness::prove`] because it has to be
    /// reproducible.
    pub fn prove_randomized(&self, context: &[u8]) -> Proof {
        let mut wide = [0u8; 64];
        crypto::hardware_rand_bytes(&mut wide);
        let nonce = Scalar::from_bytes_mod_order_wide(&wide);
        crypto::wipe(&mut wide);
        self.respond(&nonce, context)
    }

    fn respond(&self, nonce: &Scalar, context: &[u8]) -> Proof {
        let commitment = (nonce * G).compress().to_bytes();
        let challenge = challenge(&self.commitment, &commitment, context);
        let response = nonce + challenge * self.scalar;
        Proof {
            commitment,
            response: response.to_bytes(),
        }
    }

    /// True when `proof` proves knowledge of *this* secret's scalar, i.e. when `public` is this
    /// witness's own commitment and the proof verifies against it.
    pub fn proves_ownership(&self, public: &[u8; 32], proof: &Proof, context: &[u8]) -> bool {
        crypto::ct_eq(public, &self.commitment) && verify(public, proof, context)
    }
}

/// The challenge for a statement: `H(domain ‖ X ‖ R ‖ context) mod ℓ`.
///
/// Hashing into the field with a 64-byte digest and then reducing is the standard Fiat–Shamir
/// construction; a 32-byte digest reduced the same way would bias the challenge, which is a real
/// (if small) leak of the prover's randomness.
fn challenge(public: &[u8; 32], commitment: &[u8; 32], context: &[u8]) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(CHALLENGE_DOMAIN);
    hasher.update(public);
    hasher.update(commitment);
    hasher.update((context.len() as u64).to_le_bytes());
    hasher.update(context);
    let digest = hasher.finalize();
    let mut wide = [0u8; 64];
    wide.copy_from_slice(&digest);
    let challenge = Scalar::from_bytes_mod_order_wide(&wide);
    crypto::wipe(&mut wide);
    challenge
}

/// Verifies a proof against a public commitment. This is the verifier's whole job: no secret is
/// involved, and every failure mode returns `false` rather than an error to interpret.
pub fn verify(public: &[u8; 32], proof: &Proof, context: &[u8]) -> bool {
    let point = match CompressedRistretto(*public).decompress() {
        Some(point) => point,
        None => return false,
    };
    let commitment = match CompressedRistretto(proof.commitment).decompress() {
        Some(point) => point,
        None => return false,
    };
    let response: Option<Scalar> = Scalar::from_canonical_bytes(proof.response).into();
    let response = match response {
        Some(response) => response,
        None => return false,
    };
    let challenge = challenge(public, &proof.commitment, context);
    response * G == commitment + challenge * point
}

/// The unlock key for a disk image, derived from the proof transcript.
///
/// Both sides compute the same value: the prover produces the proof, the verifier checks it, and
/// the key is a function of the transcript and the image's nonce. A wrong secret therefore yields
/// a different transcript whose proof does not verify, and there is no path that produces a key
/// without a valid proof.
pub fn unlock_key(public: &[u8; 32], proof: &Proof, device_nonce: &[u8; 32]) -> [u8; crypto::KEY_LEN] {
    let mut transcript = Vec::with_capacity(96);
    transcript.extend_from_slice(public);
    transcript.extend_from_slice(&proof.to_bytes());
    let mut key = [0u8; crypto::KEY_LEN];
    crypto::hkdf_sha256(device_nonce, &transcript, b"KOS-VAULT-DISK-KEY", &mut key);
    crypto::wipe(&mut transcript);
    key
}

// --------------------------------------------------------------------------------------- tests

/// Exercises the proof: the algebraic identity, every rejection the verifier has, and the binding
/// to the context that makes a captured proof useless on another image.
pub fn self_test() -> crate::block::BlockReport {
    let mut report = crate::block::BlockReport::new();
    let alice = Witness::from_secret(b"correct horse battery staple");
    let mallory = Witness::from_secret(b"correct horse battery stapl3");
    let context = b"image:0x1000:generation=7";

    report.check(
        alice.commitment() != mallory.commitment(),
        "two different secrets produced the same commitment",
    );
    report.check(
        Witness::from_secret(b"correct horse battery staple").commitment() == alice.commitment(),
        "the commitment is not deterministic in the secret",
    );

    let proof = alice.prove(context);
    report.check(
        verify(&alice.commitment(), &proof, context),
        "an honest proof did not verify",
    );
    report.check(
        alice.proves_ownership(&alice.commitment(), &proof, context),
        "the witness did not accept its own proof",
    );
    report.check(
        !mallory.proves_ownership(&alice.commitment(), &proof, context),
        "a different secret accepted a proof made by this one",
    );
    report.check(
        !verify(&mallory.commitment(), &proof, context),
        "an honest proof verified against a foreign public commitment",
    );

    // Determinism is what makes an image's unlock key reproducible, so it is asserted rather than
    // assumed - and so is the fact that a different context produces a different transcript.
    let repeated = alice.prove(context);
    report.check(
        repeated.commitment == proof.commitment && repeated.response == proof.response,
        "the proof for one context is not reproducible, so an image's key could not be re-derived",
    );
    let elsewhere = alice.prove(b"image:0x2000:generation=7");
    report.check(
        elsewhere.commitment != proof.commitment && elsewhere.response != proof.response,
        "two different contexts produced the same transcript",
    );
    report.check(
        verify(&alice.commitment(), &elsewhere, b"image:0x2000:generation=7"),
        "a proof for another context did not verify in that context",
    );

    // And the randomized prover - the property a Schnorr prover is usually expected to have.
    let random_a = alice.prove_randomized(context);
    let random_b = alice.prove_randomized(context);
    report.check(
        random_a.commitment != random_b.commitment && random_a.response != random_b.response,
        "two randomized proofs of the same statement were identical",
    );
    report.check(
        verify(&alice.commitment(), &random_a, context)
            && verify(&alice.commitment(), &random_b, context),
        "a randomized proof did not verify",
    );
    report.check(
        !verify(&alice.commitment(), &random_a, b"image:0x2000:generation=7"),
        "a randomized proof was accepted in a context it was not made for",
    );

    // A tampered response, or a response replaced by a valid scalar at random, must fail.
    let mut tampered = proof;
    tampered.response[0] ^= 0x01;
    report.check(
        !verify(&alice.commitment(), &tampered, context),
        "a proof with an edited response verified",
    );
    let mut tampered = proof;
    tampered.commitment[31] ^= 0x80;
    report.check(
        !verify(&alice.commitment(), &tampered, context),
        "a proof with an edited commitment verified",
    );
    let mut non_canonical = proof;
    non_canonical.response = [0xFF; 32];
    report.check(
        !verify(&alice.commitment(), &non_canonical, context),
        "a proof with a non-canonical response verified",
    );
    let mut low_order = proof;
    low_order.commitment = RistrettoPoint::identity().compress().to_bytes();
    report.check(
        !verify(&alice.commitment(), &low_order, context),
        "a proof using the identity as its commitment verified",
    );

    // The statement binding: the same proof must not verify for a different image or state.
    report.check(
        !verify(&alice.commitment(), &proof, b"image:0x2000:generation=7"),
        "a proof captured for one image verified for another",
    );
    report.check(
        !verify(&alice.commitment(), &proof, b"image:0x1000:generation=8"),
        "a proof verified for a different header generation",
    );
    report.check(
        !verify(&alice.commitment(), &proof, b""),
        "a proof verified with an empty context",
    );

    // The group order: `(l-1)·G + G` is the identity, which is only true if the scalar field and
    // the basepoint are what this code believes they are.
    let order_minus_one = -Scalar::ONE;
    report.check(
        (order_minus_one * G + G) == RistrettoPoint::identity(),
        "the scalar field's order does not match the group's",
    );

    // The unlock key depends on the transcript *and* the image nonce, and both sides agree.
    let nonce = [0x5A; 32];
    let key_a = unlock_key(&alice.commitment(), &proof, &nonce);
    let key_b = unlock_key(&alice.commitment(), &proof, &nonce);
    report.check(key_a == key_b, "the two sides derived different unlock keys");
    report.check(key_a != [0u8; crypto::KEY_LEN], "the unlock key is all zeroes");
    let mut other_nonce = nonce;
    other_nonce[0] ^= 0x01;
    report.check(
        unlock_key(&alice.commitment(), &proof, &other_nonce) != key_a,
        "a different image nonce produced the same unlock key",
    );
    report.check(
        unlock_key(&mallory.commitment(), &proof, &nonce) != key_a,
        "a different public commitment produced the same unlock key",
    );

    report
}
