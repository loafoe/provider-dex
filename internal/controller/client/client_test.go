/*
Copyright 2026 Andy Lo-A-Foe.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package client

import (
	"context"
	"testing"

	"github.com/dexidp/dex/api/v2"
	"github.com/google/go-cmp/cmp"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/crossplane/crossplane-runtime/v2/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	"github.com/crossplane/crossplane-runtime/v2/pkg/test"

	v1 "github.com/crossplane/provider-dex/apis/oauth/v1"
	dexclient "github.com/crossplane/provider-dex/internal/clients/dex"
)

// Unlike many Kubernetes projects Crossplane does not use third party testing
// libraries, per the common Go test review comments. Crossplane encourages the
// use of table driven unit tests. The tests of the crossplane-runtime project
// are representative of the testing style Crossplane encourages.
//
// https://github.com/golang/go/wiki/TestComments
// https://github.com/crossplane/crossplane/blob/master/CONTRIBUTING.md#contributing-code

func TestObserve(t *testing.T) {
	type fields struct {
		dex  *dexclient.Client
		kube client.Client
	}

	type args struct {
		ctx context.Context
		mg  resource.Managed
	}

	type want struct {
		o   managed.ExternalObservation
		err error
	}

	cases := map[string]struct {
		reason string
		fields fields
		args   args
		want   want
	}{
		// TODO: Add test cases.
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := external{dex: tc.fields.dex, kube: tc.fields.kube}
			got, err := e.Observe(tc.args.ctx, tc.args.mg)
			if diff := cmp.Diff(tc.want.err, err, test.EquateErrors()); diff != "" {
				t.Errorf("\n%s\ne.Observe(...): -want error, +got error:\n%s\n", tc.reason, diff)
			}
			if diff := cmp.Diff(tc.want.o, got); diff != "" {
				t.Errorf("\n%s\ne.Observe(...): -want, +got:\n%s\n", tc.reason, diff)
			}
		})
	}
}

func TestIsClientUpToDate(t *testing.T) {
	type args struct {
		spec     v1.ClientParameters
		existing *api.ClientInfo
	}

	cases := map[string]struct {
		reason string
		args   args
		want   bool
	}{
		"EverythingMatches": {
			reason: "A client with no SSO sharing configured is up to date.",
			args: args{
				spec:     v1.ClientParameters{Name: "example", RedirectURIs: []string{"http://localhost/callback"}},
				existing: &api.ClientInfo{Id: "example", Name: "example", RedirectUris: []string{"http://localhost/callback"}},
			},
			want: true,
		},
		"SSOSharedWithMatches": {
			reason: "A client whose ssoSharedWith matches the observed value is up to date.",
			args: args{
				spec: v1.ClientParameters{
					Name:          "example",
					RedirectURIs:  []string{"http://localhost/callback"},
					SSOSharedWith: []string{"other-client"},
				},
				existing: &api.ClientInfo{
					Id:            "example",
					Name:          "example",
					RedirectUris:  []string{"http://localhost/callback"},
					SsoSharedWith: []string{"other-client"},
				},
			},
			want: true,
		},
		"SSOSharedWithDrift": {
			reason: "A client whose ssoSharedWith differs from the observed value is not up to date.",
			args: args{
				spec: v1.ClientParameters{
					Name:          "example",
					RedirectURIs:  []string{"http://localhost/callback"},
					SSOSharedWith: []string{"other-client"},
				},
				existing: &api.ClientInfo{
					Id:            "example",
					Name:          "example",
					RedirectUris:  []string{"http://localhost/callback"},
					SsoSharedWith: []string{"yet-another-client"},
				},
			},
			want: false,
		},
		"SSOSharedWithUnmanaged": {
			reason: "A client with no ssoSharedWith in the spec is up to date even when the server has one, because the API cannot clear it.",
			args: args{
				spec: v1.ClientParameters{Name: "example", RedirectURIs: []string{"http://localhost/callback"}},
				existing: &api.ClientInfo{
					Id:            "example",
					Name:          "example",
					RedirectUris:  []string{"http://localhost/callback"},
					SsoSharedWith: []string{"other-client"},
				},
			},
			want: true,
		},
		"SSOSharedWithEmptySpec": {
			reason: "An explicitly empty ssoSharedWith does not report drift, because the API cannot express it.",
			args: args{
				spec: v1.ClientParameters{
					Name:          "example",
					RedirectURIs:  []string{"http://localhost/callback"},
					SSOSharedWith: []string{},
				},
				existing: &api.ClientInfo{
					Id:            "example",
					Name:          "example",
					RedirectUris:  []string{"http://localhost/callback"},
					SsoSharedWith: []string{"other-client"},
				},
			},
			want: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := isClientUpToDate(tc.args.spec, tc.args.existing)
			if diff := cmp.Diff(tc.want, got); diff != "" {
				t.Errorf("\n%s\nisClientUpToDate(...): -want, +got:\n%s\n", tc.reason, diff)
			}
		})
	}
}
