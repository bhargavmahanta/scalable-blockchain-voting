# Constituency sharding V4

Each constituency deploys its own immutable `ElectionConfigV4`,
`BatchCommitmentV4`, and `TallyVerifierV4`. Ingestion, proof workers, storage,
nullifier state, encrypted aggregation, and settlement therefore scale
horizontally instead of sharing one national bottleneck.

`NationalElectionIndexV4` provides the national audit layer:

1. a multisig registers the expected constituency deployments;
2. a timelock freezes the complete roster;
3. anyone records a constituency only after its proof-gated tally is published;
4. anyone accumulates recorded tallies in the frozen registration order; and
5. anyone finalizes the national index once every constituency is included.

The fixed order makes the accumulator deterministic even when constituencies
finish at different times. Each leaf binds the national and constituency IDs,
contract addresses, result, artifact, tally public inputs, and accepted ballot
count. The national index contains no individual vote or identity data.

This removes shared-chain application contention, but the 10,000/s sustained,
50,000/s burst, multi-provider storage, and 960-million projection targets
still require the dedicated distributed load and availability test milestone.
