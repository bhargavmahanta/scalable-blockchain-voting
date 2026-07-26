package main

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

var bytes32Pattern = regexp.MustCompile(`^0x[0-9a-fA-F]{64}$`)

type BatchManifestV4 struct {
	SchemaVersion               uint32   `json:"schemaVersion"`
	NationalElectionID          string   `json:"nationalElectionId"`
	ConstituencyID              string   `json:"constituencyId"`
	EligibilityRoot             string   `json:"eligibilityRoot"`
	EligibilityRootVersion      uint64   `json:"eligibilityRootVersion"`
	CandidateProfile            uint8    `json:"candidateProfile"`
	PackageRoot                 string   `json:"packageRoot"`
	PreviousNullifierRoot       string   `json:"previousNullifierRoot"`
	NullifierRoot               string   `json:"nullifierRoot"`
	ManifestDigest              string   `json:"manifestDigest"`
	AggregateCiphertextDigest   string   `json:"aggregateCiphertextDigest"`
	AvailabilityCertificateHash string   `json:"availabilityCertificateHash"`
	BallotCount                 uint64   `json:"ballotCount"`
	BallotVerifierVersion       uint32   `json:"ballotVerifierVersion"`
	BatchVerifierVersion        uint32   `json:"batchVerifierVersion"`
	PackageDigests              []string `json:"packageDigests"`
}

func (manifest BatchManifestV4) Validate() error {
	if manifest.SchemaVersion != 4 {
		return fmt.Errorf("schemaVersion must be 4")
	}
	if manifest.CandidateProfile != 4 && manifest.CandidateProfile != 16 {
		return fmt.Errorf("candidateProfile must be 4 or 16")
	}
	if manifest.BallotCount < 32 || manifest.BallotCount > 256 {
		return fmt.Errorf("ballotCount must be between 32 and 256")
	}
	if uint64(len(manifest.PackageDigests)) != manifest.BallotCount {
		return fmt.Errorf("packageDigests length must equal ballotCount")
	}
	if manifest.EligibilityRootVersion == 0 ||
		manifest.BallotVerifierVersion == 0 ||
		manifest.BatchVerifierVersion == 0 {
		return errors.New("root and verifier versions must be non-zero")
	}
	if strings.EqualFold(
		manifest.PreviousNullifierRoot,
		manifest.NullifierRoot,
	) {
		return errors.New("nullifier state transition must change the root")
	}
	fields := map[string]string{
		"nationalElectionId":          manifest.NationalElectionID,
		"constituencyId":              manifest.ConstituencyID,
		"eligibilityRoot":             manifest.EligibilityRoot,
		"packageRoot":                 manifest.PackageRoot,
		"previousNullifierRoot":       manifest.PreviousNullifierRoot,
		"nullifierRoot":               manifest.NullifierRoot,
		"manifestDigest":              manifest.ManifestDigest,
		"aggregateCiphertextDigest":   manifest.AggregateCiphertextDigest,
		"availabilityCertificateHash": manifest.AvailabilityCertificateHash,
	}
	for label, value := range fields {
		if !bytes32Pattern.MatchString(value) {
			return fmt.Errorf("%s must be bytes32", label)
		}
	}
	seen := make(map[string]struct{}, len(manifest.PackageDigests))
	for index, digest := range manifest.PackageDigests {
		if !bytes32Pattern.MatchString(digest) {
			return fmt.Errorf("packageDigests[%d] must be bytes32", index)
		}
		normalizedDigest := strings.ToLower(digest)
		if _, duplicate := seen[normalizedDigest]; duplicate {
			return fmt.Errorf("packageDigests[%d] is duplicated", index)
		}
		seen[normalizedDigest] = struct{}{}
	}
	return nil
}

type BatchProofArtifactV4 struct {
	SchemaVersion         uint32 `json:"schemaVersion"`
	JobID                 string `json:"jobId"`
	ManifestDigest        string `json:"manifestDigest"`
	BatchPublicInputsHash string `json:"batchPublicInputsHash"`
	ProofSystem           string `json:"proofSystem"`
	Proof                 string `json:"proof"`
	RecursivelyProved     bool   `json:"recursivelyProved"`
	LeafProofCount        uint64 `json:"leafProofCount"`
	BatchVerifierVersion  uint32 `json:"batchVerifierVersion"`
	CanonicalDigest       string `json:"canonicalDigest"`
}

type JobState string

const (
	JobQueued    JobState = "queued"
	JobProving   JobState = "proving"
	JobSucceeded JobState = "succeeded"
	JobFailed    JobState = "failed"
)

type ProofJob struct {
	ID       string                `json:"id"`
	State    JobState              `json:"state"`
	Error    string                `json:"error,omitempty"`
	Manifest BatchManifestV4       `json:"manifest"`
	Artifact *BatchProofArtifactV4 `json:"artifact,omitempty"`
}
