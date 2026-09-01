//
// Copyright 2024 The GUAC Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package mockosv

// This package mocks the OSV querybatch API (api.osv.dev/v1/querybatch).
// Usage: create a MockOSV, set responses per purl, then use GetTransport()
// to build an *http.Client that redirects OSV requests to the mock server.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
)

// batchRequest mirrors the OSV querybatch request format.
type batchRequest struct {
	Queries []struct {
		Package struct {
			PURL string `json:"purl"`
		} `json:"package"`
	} `json:"queries"`
}

// minimalVuln is the minimal vuln object returned by querybatch.
type minimalVuln struct {
	ID       string `json:"id"`
	Modified string `json:"modified,omitempty"`
}

// batchResult holds vulns for a single query.
type batchResult struct {
	Vulns []minimalVuln `json:"vulns,omitempty"`
}

// batchResponse mirrors the OSV querybatch response format.
type batchResponse struct {
	Results []batchResult `json:"results"`
}

// MockOSV intercepts requests to api.osv.dev and returns pre-configured responses.
type MockOSV struct {
	server    *httptest.Server
	responses map[string][]byte // purl -> raw querybatch single-result JSON
}

// NewMockOSV creates a mock OSV server ready to serve querybatch requests.
func NewMockOSV() *MockOSV {
	mock := &MockOSV{
		responses: make(map[string][]byte),
	}
	mock.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mock.handleQueryBatch(w, r)
	}))
	return mock
}

// SetResponse configures the full querybatch response to return for a given purl.
// responseJSON should be a complete querybatch response ({"results":[{"vulns":[...]}]}).
func (m *MockOSV) SetResponse(purl string, responseJSON []byte) {
	m.responses[purl] = responseJSON
}

// Close shuts down the test server.
func (m *MockOSV) Close() {
	m.server.Close()
}

// GetTransport returns a RoundTripper that redirects api.osv.dev to this mock.
func (m *MockOSV) GetTransport() http.RoundTripper {
	return &mockTransport{
		original:      http.DefaultTransport,
		testServerURL: m.server.URL,
	}
}

type mockTransport struct {
	original      http.RoundTripper
	testServerURL string
}

func (t *mockTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Host, "api.osv.dev") {
		req.URL.Scheme = "http"
		req.URL.Host = strings.TrimPrefix(t.testServerURL, "http://")
	}
	return t.original.RoundTrip(req)
}

func (m *MockOSV) handleQueryBatch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || !strings.Contains(r.URL.Path, "querybatch") {
		http.Error(w, "Not found", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read request", http.StatusInternalServerError)
		return
	}
	defer r.Body.Close()

	var req batchRequest
	if err := json.Unmarshal(body, &req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"code":    3,
			"message": "Invalid query.",
		})
		return
	}

	// For each query, look up the purl in our configured responses.
	// If we have a full response for a single-purl request, parse and return it.
	// Otherwise, build the response per-purl.
	if len(req.Queries) == 1 {
		purl := req.Queries[0].Package.PURL
		if purl == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    3,
				"message": "Invalid query.",
			})
			return
		}
		if respData, ok := m.responses[purl]; ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respData)
			return
		}
	}

	// Multi-purl batch: build combined response
	resp := batchResponse{Results: make([]batchResult, len(req.Queries))}
	for i, q := range req.Queries {
		purl := q.Package.PURL
		if purl == "" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"code":    3,
				"message": "Invalid query.",
			})
			return
		}
		if respData, ok := m.responses[purl]; ok {
			var singleResp batchResponse
			if err := json.Unmarshal(respData, &singleResp); err == nil && len(singleResp.Results) > 0 {
				resp.Results[i] = singleResp.Results[0]
			}
		}
		// If no response configured, leave empty (no vulns)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}
