import { buildModule } from "@nomicfoundation/hardhat-ignition/modules";
import type { Address, Hex } from "viem";

/// Production-only V4 deployment.
///
/// This module intentionally has no zero-address defaults and deploys none of
/// the V2/V3 trusted registration, direct-vote, trusted-batch, dealer, or mock
/// verifier contracts. Governance must configure the referenced append-only
/// verifier registry before deploying an election.
export default buildModule("ProductionV4", (m) => {
  const nationalElectionId = m.getParameter<Hex>("nationalElectionId");
  const constituencyId = m.getParameter<Hex>("constituencyId");
  const eligibilityRoot = m.getParameter<Hex>("eligibilityRoot");
  const eligibilityRootVersion = m.getParameter<bigint>(
    "eligibilityRootVersion",
  );
  const candidateProfile = m.getParameter<number>("candidateProfile");
  const candidateListHash = m.getParameter<Hex>("candidateListHash");
  const trusteeKeysetHash = m.getParameter<Hex>("trusteeKeysetHash");
  const dkgTranscriptHash = m.getParameter<Hex>("dkgTranscriptHash");
  const eligibilityVerifierVersion = m.getParameter<number>(
    "eligibilityVerifierVersion",
  );
  const batchVerifierVersion = m.getParameter<number>("batchVerifierVersion");
  const tallyVerifierVersion = m.getParameter<number>("tallyVerifierVersion");
  const votingStartsAt = m.getParameter<bigint>("votingStartsAt");
  const votingEndsAt = m.getParameter<bigint>("votingEndsAt");
  const settlementEndsAt = m.getParameter<bigint>("settlementEndsAt");
  const verifierRegistryAddress = m.getParameter<Address>(
    "verifierRegistryAddress",
  );
  const bondToken = m.getParameter<Address>("bondToken");
  const batcherBond = m.getParameter<bigint>("batcherBond");
  const challengerBond = m.getParameter<bigint>("challengerBond");
  const challengePeriod = m.getParameter<bigint>("challengePeriod");
  const fraudVerifierVersion = m.getParameter<number>(
    "fraudVerifierVersion",
  );

  const verifierRegistry = m.contractAt(
    "VerifierRegistryV4",
    verifierRegistryAddress,
  );
  const electionConfig = m.contract("ElectionConfigV4", [
    {
      nationalElectionId,
      constituencyId,
      eligibilityRoot,
      eligibilityRootVersion,
      candidateProfile,
      candidateListHash,
      trusteeKeysetHash,
      dkgTranscriptHash,
      eligibilityVerifierVersion,
      batchVerifierVersion,
      tallyVerifierVersion,
      votingStartsAt,
      votingEndsAt,
      settlementEndsAt,
    },
    verifierRegistry,
  ]);
  const batchCommitment = m.contract("BatchCommitmentV4", [
    electionConfig,
    bondToken,
    batcherBond,
    challengerBond,
    challengePeriod,
    fraudVerifierVersion,
  ]);
  const tallyVerifier = m.contract("TallyVerifierV4", [
    electionConfig,
    batchCommitment,
  ]);

  return {
    verifierRegistry,
    electionConfig,
    batchCommitment,
    tallyVerifier,
  };
});
