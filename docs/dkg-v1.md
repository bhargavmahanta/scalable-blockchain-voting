# Distributed trustee ceremony V1

`DkgTranscriptCoordinatorV1` replaces the single-process ceremony coordinator
with a signed 5-of-9 transcript state machine.

## Enforced now

- exactly nine independent trustee signing keys;
- national-election, constituency, and ceremony binding;
- two signed rounds per qualified trustee;
- round-two linkage to the trustee's round-one hash;
- objective equivocation evidence from two conflicting signed messages;
- permanent disqualification of an equivocating trustee;
- successful completion with any five qualified trustees;
- refusal with four or fewer survivors;
- a canonical transcript hash binding the qualified/disqualified sets,
  contribution hashes, evidence, election public key, and trustee keyset; and
- no private shares, plaintext shares, signatures, or network metadata in the
  public transcript.

Trustee services should expose authenticated operations for contribution
submission, complaint/evidence retrieval, transcript retrieval, and aggregate
decryption-share generation. Private shares remain in trustee-controlled HSM or
encrypted storage and never pass through the coordinator.

## Cryptographic readiness boundary

The coordinator treats each Pedersen commitment and encrypted share bundle as a
digest. The next implementation must verify, inside an audited BabyJubJub DKG
engine:

1. commitments use two independently generated subgroup generators;
2. every encrypted share opens against the dealer's coefficient commitments;
3. authenticated encryption binds sender, recipient, ceremony, and round;
4. complaints reveal only the disputed opening;
5. the group public key and each qualified public share are reconstructed from
   accepted contributions; and
6. produced private shares generate the existing public DLEQ decryption-share
   format.

Until that engine and independent review are complete, this milestone provides
authenticated transcript/accountability infrastructure, not a completed
Pedersen DKG security claim.
