package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testHash = "0x1111111111111111111111111111111111111111111111111111111111111111"

type successfulEngine struct{}

func (successfulEngine) Prove(
	_ context.Context,
	manifest BatchManifestV4,
) (*BatchProofArtifactV4, error) {
	return &BatchProofArtifactV4{
		SchemaVersion:         4,
		ManifestDigest:        manifest.ManifestDigest,
		ProofSystem:           "recursive-groth16-bn254",
		Proof:                 "0x1234",
		RecursivelyProved:     true,
		LeafProofCount:        manifest.BallotCount,
		BatchVerifierVersion:  manifest.BatchVerifierVersion,
		BatchPublicInputsHash: testHash,
		CanonicalDigest:       testHash,
	}, nil
}

func validManifest() BatchManifestV4 {
	digests := make([]string, 32)
	for index := range digests {
		digest := []byte(testHash)
		digest[len(digest)-2] = "0123456789abcdef"[index/16]
		digest[len(digest)-1] = "0123456789abcdef"[index%16]
		digests[index] = string(digest)
	}
	return BatchManifestV4{
		SchemaVersion:               4,
		NationalElectionID:          testHash,
		ConstituencyID:              testHash,
		EligibilityRoot:             testHash,
		EligibilityRootVersion:      1,
		CandidateProfile:            4,
		PackageRoot:                 testHash,
		PreviousNullifierRoot:       testHash,
		NullifierRoot:               "0x2222222222222222222222222222222222222222222222222222222222222222",
		ManifestDigest:              testHash,
		AggregateCiphertextDigest:   testHash,
		AvailabilityCertificateHash: testHash,
		BallotCount:                 32,
		BallotVerifierVersion:       1,
		BatchVerifierVersion:        1,
		PackageDigests:              digests,
	}
}

func TestManifestValidation(t *testing.T) {
	manifest := validManifest()
	if err := manifest.Validate(); err != nil {
		t.Fatalf("valid manifest rejected: %v", err)
	}
	manifest.BallotCount = 31
	if err := manifest.Validate(); err == nil {
		t.Fatal("undersized leaf batch was accepted")
	}
}

func TestProofAPI(t *testing.T) {
	server := NewProofServer(successfulEngine{}, 1)
	body, err := json.Marshal(validManifest())
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPost, "/v1/manifests", bytes.NewReader(body))
	response := httptest.NewRecorder()
	server.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("submit returned %d: %s", response.Code, response.Body.String())
	}
	var submitted ProofJob
	if err := json.Unmarshal(response.Body.Bytes(), &submitted); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		request = httptest.NewRequest(http.MethodGet, "/v1/jobs/"+submitted.ID, nil)
		response = httptest.NewRecorder()
		server.ServeHTTP(response, request)
		var job ProofJob
		if err := json.Unmarshal(response.Body.Bytes(), &job); err != nil {
			t.Fatal(err)
		}
		if job.State == JobSucceeded {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("proof job did not complete")
}

func TestUnavailableEngineFailsClosed(t *testing.T) {
	server := NewProofServer(UnavailableEngine{}, 1)
	manifest := validManifest()
	server.jobs["job"] = &ProofJob{ID: "job", State: JobQueued, Manifest: manifest}
	server.queue <- "job"
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		server.mutex.RLock()
		job := *server.jobs["job"]
		server.mutex.RUnlock()
		if job.State == JobFailed {
			if !strings.Contains(job.Error, "no proof was produced") {
				t.Fatalf("unexpected failure: %s", job.Error)
			}
			if job.Artifact != nil {
				t.Fatal("fail-closed engine emitted an artifact")
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("unavailable engine did not fail")
}
