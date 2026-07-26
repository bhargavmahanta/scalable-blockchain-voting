package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

var ErrRecursiveEngineUnavailable = errors.New(
	"recursive BN254 Groth16 engine is unavailable; no proof was produced",
)

type RecursiveEngine interface {
	Prove(context.Context, BatchManifestV4) (*BatchProofArtifactV4, error)
}

type UnavailableEngine struct{}

func (UnavailableEngine) Prove(
	context.Context,
	BatchManifestV4,
) (*BatchProofArtifactV4, error) {
	return nil, ErrRecursiveEngineUnavailable
}

type ProofServer struct {
	engine RecursiveEngine
	jobs   map[string]*ProofJob
	queue  chan string
	mutex  sync.RWMutex
}

func NewProofServer(engine RecursiveEngine, workers int) *ProofServer {
	if engine == nil {
		engine = UnavailableEngine{}
	}
	if workers < 1 {
		workers = 1
	}
	server := &ProofServer{
		engine: engine,
		jobs:   make(map[string]*ProofJob),
		queue:  make(chan string, workers*4),
	}
	for index := 0; index < workers; index++ {
		go server.worker()
	}
	return server
}

func (server *ProofServer) ServeHTTP(
	response http.ResponseWriter,
	request *http.Request,
) {
	response.Header().Set("content-type", "application/json")
	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/v1/manifests":
		server.submit(response, request)
	case request.Method == http.MethodGet &&
		strings.HasPrefix(request.URL.Path, "/v1/jobs/"):
		server.readJob(response, strings.TrimPrefix(request.URL.Path, "/v1/jobs/"))
	case request.Method == http.MethodGet &&
		strings.HasPrefix(request.URL.Path, "/v1/artifacts/"):
		server.readArtifact(
			response,
			strings.TrimPrefix(request.URL.Path, "/v1/artifacts/"),
		)
	case request.Method == http.MethodGet && request.URL.Path == "/healthz":
		writeJSON(response, http.StatusOK, map[string]string{
			"status":         "ok",
			"proofReadiness": "engine-dependent",
		})
	default:
		writeJSON(response, http.StatusNotFound, map[string]string{
			"error": "route not found",
		})
	}
}

func (server *ProofServer) submit(
	response http.ResponseWriter,
	request *http.Request,
) {
	body := http.MaxBytesReader(response, request.Body, 4<<20)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var manifest BatchManifestV4
	if err := decoder.Decode(&manifest); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{
			"error": fmt.Sprintf("invalid manifest: %v", err),
		})
		return
	}
	if err := manifest.Validate(); err != nil {
		writeJSON(response, http.StatusUnprocessableEntity, map[string]string{
			"error": err.Error(),
		})
		return
	}
	if err := ensureEOF(decoder); err != nil {
		writeJSON(response, http.StatusBadRequest, map[string]string{
			"error": err.Error(),
		})
		return
	}

	idBytes := sha256.Sum256([]byte(
		manifest.ManifestDigest + ":" +
			manifest.NationalElectionID + ":" +
			manifest.ConstituencyID,
	))
	id := hex.EncodeToString(idBytes[:])
	server.mutex.Lock()
	if existing, exists := server.jobs[id]; exists {
		snapshot := *existing
		server.mutex.Unlock()
		writeJSON(response, http.StatusOK, snapshot)
		return
	}
	job := &ProofJob{ID: id, State: JobQueued, Manifest: manifest}
	server.jobs[id] = job
	snapshot := *job
	server.mutex.Unlock()
	server.queue <- id
	writeJSON(response, http.StatusAccepted, snapshot)
}

func (server *ProofServer) readJob(
	response http.ResponseWriter,
	id string,
) {
	server.mutex.RLock()
	job, found := server.jobs[id]
	var snapshot ProofJob
	if found {
		snapshot = *job
	}
	server.mutex.RUnlock()
	if !found {
		writeJSON(response, http.StatusNotFound, map[string]string{
			"error": "job not found",
		})
		return
	}
	writeJSON(response, http.StatusOK, snapshot)
}

func (server *ProofServer) readArtifact(
	response http.ResponseWriter,
	id string,
) {
	server.mutex.RLock()
	job, found := server.jobs[id]
	var state JobState
	var artifact *BatchProofArtifactV4
	if found {
		state = job.State
		if job.Artifact != nil {
			artifactCopy := *job.Artifact
			artifact = &artifactCopy
		}
	}
	server.mutex.RUnlock()
	if !found {
		writeJSON(response, http.StatusNotFound, map[string]string{
			"error": "job not found",
		})
		return
	}
	if state != JobSucceeded || artifact == nil {
		writeJSON(response, http.StatusConflict, map[string]string{
			"error": "proof artifact is not available",
			"state": string(state),
		})
		return
	}
	writeJSON(response, http.StatusOK, artifact)
}

func (server *ProofServer) worker() {
	for id := range server.queue {
		server.mutex.Lock()
		job := server.jobs[id]
		job.State = JobProving
		server.mutex.Unlock()

		contextWithTimeout, cancel := context.WithTimeout(
			context.Background(),
			30*time.Minute,
		)
		artifact, err := server.engine.Prove(contextWithTimeout, job.Manifest)
		cancel()

		server.mutex.Lock()
		if err != nil {
			job.State = JobFailed
			job.Error = err.Error()
			job.Artifact = nil
		} else if artifact == nil || !artifact.RecursivelyProved {
			job.State = JobFailed
			job.Error = "engine returned no recursively proved artifact"
			job.Artifact = nil
		} else {
			job.State = JobSucceeded
			job.Artifact = artifact
		}
		server.mutex.Unlock()
	}
}

func ensureEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return errors.New("manifest must contain exactly one JSON object")
	}
	return nil
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}
