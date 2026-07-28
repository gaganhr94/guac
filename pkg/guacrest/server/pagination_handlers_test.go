//
// Copyright 2026 The GUAC Authors.
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

package server_test

import (
	"context"
	"testing"

	. "github.com/guacsec/guac/internal/testing/graphqlClients"
	_ "github.com/guacsec/guac/pkg/assembler/backends/keyvalue"
	gen "github.com/guacsec/guac/pkg/guacrest/generated"
	"github.com/guacsec/guac/pkg/guacrest/pagination"
	"github.com/guacsec/guac/pkg/guacrest/server"
	"github.com/guacsec/guac/pkg/logging"
)

// depGraph returns a GuacData fixture with a chain of `n` packages, each one
// linked to the next via an SBOM-included edge. Returns the root purl. The
// transitive deps from the root are pkgs[1..n-1] — so n-1 deps.
func depGraph(n int) (GuacData, string) {
	pkgs := make([]string, n)
	for i := range n {
		pkgs[i] = "pkg:guac/p" + string(rune('a'+i))
	}
	sboms := make([]HasSbom, 0, n-1)
	for i := range n - 1 {
		sboms = append(sboms, HasSbom{
			Subject:          pkgs[i],
			IncludedSoftware: []string{pkgs[i+1]},
		})
	}
	return GuacData{
		Packages: pkgs,
		HasSboms: sboms,
	}, pkgs[0]
}

// Test_GetPackageDeps_Pagination verifies pagination on a PurlList-shaped
// endpoint: nil spec falls through to the default page size (results that fit
// in one page have no NextCursor), an explicit smaller PageSize returns a
// cursor that follows through to the remaining items, and an invalid cursor
// is reported as 400.
func Test_GetPackageDeps_Pagination(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	data, root := depGraph(5) // root + 4 transitive deps; 4 < DefaultPageSize=40
	wantTotal := 4

	t.Run("nil spec uses default page size; small list returns no cursor", func(t *testing.T) {
		gqlClient := SetupTest(t)
		Ingest(ctx, t, gqlClient, data)
		api := server.NewDefaultServer(gqlClient)

		res, err := api.GetPackageDeps(ctx, gen.GetPackageDepsRequestObject{Purl: root})
		if err != nil {
			t.Fatalf("GetPackageDeps returned err: %v", err)
		}
		ok, success := res.(gen.GetPackageDeps200JSONResponse)
		if !success {
			t.Fatalf("expected 200, got %T: %v", res, res)
		}
		if len(ok.PurlList) != wantTotal {
			t.Errorf("PurlList len = %d, want %d (full list)", len(ok.PurlList), wantTotal)
		}
		if ok.PaginationInfo.NextCursor != nil {
			t.Errorf("NextCursor = %q, want nil when full list fits in default page", *ok.PaginationInfo.NextCursor)
		}
		if ok.PaginationInfo.TotalCount == nil || *ok.PaginationInfo.TotalCount != wantTotal {
			t.Errorf("TotalCount = %v, want %d", ok.PaginationInfo.TotalCount, wantTotal)
		}
	})

	t.Run("explicit page size returns page and cursor", func(t *testing.T) {
		gqlClient := SetupTest(t)
		Ingest(ctx, t, gqlClient, data)
		api := server.NewDefaultServer(gqlClient)

		spec := &gen.PaginationSpec{PageSize: pagination.PointerOf(2)}
		res, err := api.GetPackageDeps(ctx, gen.GetPackageDepsRequestObject{
			Purl:   root,
			Params: gen.GetPackageDepsParams{PaginationSpec: spec},
		})
		if err != nil {
			t.Fatalf("GetPackageDeps returned err: %v", err)
		}
		ok := res.(gen.GetPackageDeps200JSONResponse)
		if len(ok.PurlList) != 2 {
			t.Errorf("page 1 len = %d, want 2", len(ok.PurlList))
		}
		if ok.PaginationInfo.NextCursor == nil {
			t.Fatal("NextCursor is nil, want non-nil to continue paging")
		}

		nextSpec := &gen.PaginationSpec{
			PageSize: pagination.PointerOf(2),
			Cursor:   ok.PaginationInfo.NextCursor,
		}
		res2, err := api.GetPackageDeps(ctx, gen.GetPackageDepsRequestObject{
			Purl:   root,
			Params: gen.GetPackageDepsParams{PaginationSpec: nextSpec},
		})
		if err != nil {
			t.Fatalf("GetPackageDeps page 2 returned err: %v", err)
		}
		ok2 := res2.(gen.GetPackageDeps200JSONResponse)
		if len(ok2.PurlList) != 2 {
			t.Errorf("page 2 len = %d, want 2", len(ok2.PurlList))
		}
		if ok2.PaginationInfo.NextCursor != nil {
			t.Errorf("page 2 NextCursor = %q, want nil at end of list", *ok2.PaginationInfo.NextCursor)
		}

		// pages should not overlap
		seen := map[string]struct{}{}
		for _, p := range ok.PurlList {
			seen[p] = struct{}{}
		}
		for _, p := range ok2.PurlList {
			if _, dup := seen[p]; dup {
				t.Errorf("purl %q appears in both pages", p)
			}
		}
	})

	t.Run("invalid cursor returns 400", func(t *testing.T) {
		gqlClient := SetupTest(t)
		Ingest(ctx, t, gqlClient, data)
		api := server.NewDefaultServer(gqlClient)

		spec := &gen.PaginationSpec{Cursor: pagination.PointerOf("not-a-real-cursor")}
		res, err := api.GetPackageDeps(ctx, gen.GetPackageDepsRequestObject{
			Purl:   root,
			Params: gen.GetPackageDepsParams{PaginationSpec: spec},
		})
		if err != nil {
			t.Fatalf("GetPackageDeps returned err: %v", err)
		}
		if _, ok := res.(gen.GetPackageDeps400JSONResponse); !ok {
			t.Fatalf("expected 400, got %T: %v", res, res)
		}
	})
}

// Test_GetPackageVulns_Pagination covers the VulnerabilityList-shaped endpoint.
// The response shape changes in this PR from a bare array to an object that
// wraps the list along with PaginationInfo, mirroring the existing PurlList
// shape.
func Test_GetPackageVulns_Pagination(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	pkg := "pkg:guac/foo"
	vulnIDs := []string{"osv/CVE-2024-0001", "osv/CVE-2024-0002", "osv/CVE-2024-0003"}
	certs := make([]CertifyVuln, 0, len(vulnIDs))
	for _, v := range vulnIDs {
		certs = append(certs, CertifyVuln{Package: pkg, Vulnerability: v, Metadata: vulnScanMeta()})
	}
	data := GuacData{
		Packages:        []string{pkg},
		Vulnerabilities: vulnIDs,
		CertifyVulns:    certs,
	}

	t.Run("nil spec uses default page size; small list returns no cursor", func(t *testing.T) {
		gqlClient := SetupTest(t)
		Ingest(ctx, t, gqlClient, data)
		api := server.NewDefaultServer(gqlClient)

		res, err := api.GetPackageVulns(ctx, gen.GetPackageVulnsRequestObject{Purl: pkg})
		if err != nil {
			t.Fatalf("GetPackageVulns returned err: %v", err)
		}
		ok := res.(gen.GetPackageVulns200JSONResponse)
		if len(ok.VulnerabilityList) != len(vulnIDs) {
			t.Errorf("VulnerabilityList len = %d, want %d", len(ok.VulnerabilityList), len(vulnIDs))
		}
		if ok.PaginationInfo.NextCursor != nil {
			t.Errorf("NextCursor = %q, want nil", *ok.PaginationInfo.NextCursor)
		}
	})

	t.Run("explicit page size returns page and cursor", func(t *testing.T) {
		gqlClient := SetupTest(t)
		Ingest(ctx, t, gqlClient, data)
		api := server.NewDefaultServer(gqlClient)

		spec := &gen.PaginationSpec{PageSize: pagination.PointerOf(2)}
		res, err := api.GetPackageVulns(ctx, gen.GetPackageVulnsRequestObject{
			Purl:   pkg,
			Params: gen.GetPackageVulnsParams{PaginationSpec: spec},
		})
		if err != nil {
			t.Fatalf("GetPackageVulns returned err: %v", err)
		}
		ok := res.(gen.GetPackageVulns200JSONResponse)
		if len(ok.VulnerabilityList) != 2 {
			t.Errorf("page 1 len = %d, want 2", len(ok.VulnerabilityList))
		}
		if ok.PaginationInfo.NextCursor == nil {
			t.Fatal("NextCursor is nil, want non-nil")
		}
	})
}

// Test_AnalyzeDependencies_Pagination covers the third response shape —
// PackageNameList — produced by /analysis/dependencies. The fixture uses three
// distinct dependency packages because findDependentsOfDependencies emits one
// PackageName per *depPkg* (the dependency side of an edge).
func Test_AnalyzeDependencies_Pagination(t *testing.T) {
	ctx := logging.WithLogger(context.Background())

	dependent := "pkg:guac/dependent"
	depPkgs := []string{"pkg:guac/r1", "pkg:guac/r2", "pkg:guac/r3"}
	includedDeps := make([]IsDependency, 0, len(depPkgs))
	for _, dp := range depPkgs {
		includedDeps = append(includedDeps, IsDependency{DependentPkg: dependent, DependencyPkg: dp})
	}
	data := GuacData{
		Packages: append([]string{dependent}, depPkgs...),
		HasSboms: []HasSbom{{
			Subject:                dependent,
			IncludedIsDependencies: includedDeps,
		}},
	}

	t.Run("nil spec uses default page size; small list returns no cursor", func(t *testing.T) {
		gqlClient := SetupTest(t)
		Ingest(ctx, t, gqlClient, data)
		api := server.NewDefaultServer(gqlClient)

		res, err := api.AnalyzeDependencies(ctx, gen.AnalyzeDependenciesRequestObject{
			Params: gen.AnalyzeDependenciesParams{Sort: gen.Frequency},
		})
		if err != nil {
			t.Fatalf("AnalyzeDependencies returned err: %v", err)
		}
		ok, success := res.(gen.AnalyzeDependencies200JSONResponse)
		if !success {
			t.Fatalf("expected 200, got %T: %v", res, res)
		}
		if len(ok.PackageNameList) == 0 {
			t.Fatalf("PackageNameList is empty; expected at least one package")
		}
		if ok.PaginationInfo.NextCursor != nil {
			t.Errorf("NextCursor = %q, want nil when paginationSpec is nil", *ok.PaginationInfo.NextCursor)
		}
	})

	t.Run("explicit page size returns page and cursor", func(t *testing.T) {
		gqlClient := SetupTest(t)
		Ingest(ctx, t, gqlClient, data)
		api := server.NewDefaultServer(gqlClient)

		spec := &gen.PaginationSpec{PageSize: pagination.PointerOf(1)}
		res, err := api.AnalyzeDependencies(ctx, gen.AnalyzeDependenciesRequestObject{
			Params: gen.AnalyzeDependenciesParams{
				Sort:           gen.Frequency,
				PaginationSpec: spec,
			},
		})
		if err != nil {
			t.Fatalf("AnalyzeDependencies returned err: %v", err)
		}
		ok := res.(gen.AnalyzeDependencies200JSONResponse)
		if len(ok.PackageNameList) != 1 {
			t.Errorf("page 1 len = %d, want 1", len(ok.PackageNameList))
		}
		if ok.PaginationInfo.NextCursor == nil {
			t.Fatal("NextCursor is nil, want non-nil")
		}
	})
}

// Test_PaginationParam_Accepted is a smoke test that the remaining three
// endpoints accept paginationSpec without erroring. The full
// page-cursor-follow contract is covered by the two tests above.
func Test_PaginationParam_Accepted(t *testing.T) {
	ctx := logging.WithLogger(context.Background())
	spec := &gen.PaginationSpec{PageSize: pagination.PointerOf(10)}

	t.Run("GetPackagePurls", func(t *testing.T) {
		gqlClient := SetupTest(t)
		Ingest(ctx, t, gqlClient, GuacData{Packages: []string{"pkg:guac/foo@1.0", "pkg:guac/foo@2.0"}})
		api := server.NewDefaultServer(gqlClient)
		res, err := api.GetPackagePurls(ctx, gen.GetPackagePurlsRequestObject{
			Purl:   "pkg:guac/foo",
			Params: gen.GetPackagePurlsParams{PaginationSpec: spec},
		})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if _, ok := res.(gen.GetPackagePurls200JSONResponse); !ok {
			t.Fatalf("expected 200, got %T: %v", res, res)
		}
	})

	t.Run("GetArtifactDeps", func(t *testing.T) {
		gqlClient := SetupTest(t)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages:      []string{"pkg:guac/foo"},
			Artifacts:     []string{"sha-xyz"},
			IsOccurrences: []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-xyz"}},
		})
		api := server.NewDefaultServer(gqlClient)
		res, err := api.GetArtifactDeps(ctx, gen.GetArtifactDepsRequestObject{
			Digest: "sha-xyz",
			Params: gen.GetArtifactDepsParams{PaginationSpec: spec},
		})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if _, ok := res.(gen.GetArtifactDeps200JSONResponse); !ok {
			t.Fatalf("expected 200, got %T: %v", res, res)
		}
	})

	t.Run("GetArtifactVulns", func(t *testing.T) {
		gqlClient := SetupTest(t)
		Ingest(ctx, t, gqlClient, GuacData{
			Packages:        []string{"pkg:guac/foo"},
			Artifacts:       []string{"sha-xyz"},
			Vulnerabilities: []string{"osv/CVE-2024-0001"},
			IsOccurrences:   []IsOccurrence{{Subject: "pkg:guac/foo", Artifact: "sha-xyz"}},
			CertifyVulns:    []CertifyVuln{{Package: "pkg:guac/foo", Vulnerability: "osv/CVE-2024-0001", Metadata: vulnScanMeta()}},
		})
		api := server.NewDefaultServer(gqlClient)
		res, err := api.GetArtifactVulns(ctx, gen.GetArtifactVulnsRequestObject{
			Digest: "sha-xyz",
			Params: gen.GetArtifactVulnsParams{PaginationSpec: spec},
		})
		if err != nil {
			t.Fatalf("err: %v", err)
		}
		if _, ok := res.(gen.GetArtifactVulns200JSONResponse); !ok {
			t.Fatalf("expected 200, got %T: %v", res, res)
		}
	})
}
