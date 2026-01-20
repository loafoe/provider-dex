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

package v1

import (
	"reflect"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	xpv1 "github.com/crossplane/crossplane-runtime/v2/apis/common/v1"
	xpv2 "github.com/crossplane/crossplane-runtime/v2/apis/common/v2"
)

// ClientParameters are the configurable fields of a Dex OAuth2 Client.
type ClientParameters struct {
	// ID is the OAuth2 client ID. If not specified, the metadata.name will be used.
	// +optional
	ID string `json:"id,omitempty"`

	// Secret is the OAuth2 client secret. If not specified, one will be generated.
	// For public clients, this should be left empty.
	// +optional
	Secret string `json:"secret,omitempty"`

	// SecretRef is a reference to a secret containing the client secret.
	// Takes precedence over Secret if both are specified.
	// +optional
	SecretRef *xpv1.SecretKeySelector `json:"secretRef,omitempty"`

	// RedirectURIs is a list of allowed redirect URIs for the client.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinItems=1
	RedirectURIs []string `json:"redirectURIs"`

	// TrustedPeers is a list of client IDs that are allowed to exchange tokens
	// on behalf of this client.
	// +optional
	TrustedPeers []string `json:"trustedPeers,omitempty"`

	// Public indicates whether this is a public client (e.g., a native app or SPA).
	// Public clients do not have a secret.
	// +optional
	Public bool `json:"public,omitempty"`

	// Name is a human-readable name for the client.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// LogoURL is the URL to the client's logo.
	// +optional
	LogoURL string `json:"logoURL,omitempty"`
}

// ClientObservation are the observable fields of a Dex OAuth2 Client.
type ClientObservation struct {
	// ID is the actual client ID in Dex.
	ID string `json:"id,omitempty"`

	// Name is the client name.
	Name string `json:"name,omitempty"`

	// Public indicates whether this is a public client.
	Public bool `json:"public,omitempty"`

	// RedirectURIs is the list of redirect URIs configured for this client.
	RedirectURIs []string `json:"redirectURIs,omitempty"`
}

// A ClientSpec defines the desired state of a Client.
type ClientSpec struct {
	xpv2.ManagedResourceSpec `json:",inline"`
	ForProvider              ClientParameters `json:"forProvider"`
}

// A ClientStatus represents the observed state of a Client.
type ClientStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          ClientObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A Client is a Dex OAuth2 client managed resource.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="CLIENT-ID",type="string",JSONPath=".status.atProvider.id"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,dex}
type Client struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ClientSpec   `json:"spec"`
	Status ClientStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClientList contains a list of Client
type ClientList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Client `json:"items"`
}

// Client type metadata.
var (
	ClientKind             = reflect.TypeOf(Client{}).Name()
	ClientGroupKind        = schema.GroupKind{Group: Group, Kind: ClientKind}.String()
	ClientKindAPIVersion   = ClientKind + "." + SchemeGroupVersion.String()
	ClientGroupVersionKind = SchemeGroupVersion.WithKind(ClientKind)
)

func init() {
	SchemeBuilder.Register(&Client{}, &ClientList{})
}
