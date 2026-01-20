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

// DiscoveryParameters are the configurable fields of a Discovery resource.
// Since Discovery is observe-only, there are no configurable parameters.
type DiscoveryParameters struct{}

// DiscoveryObservation contains the OIDC discovery information from Dex.
type DiscoveryObservation struct {
	// Issuer is the OIDC issuer URL.
	Issuer string `json:"issuer,omitempty"`

	// AuthorizationEndpoint is the URL of the authorization endpoint.
	AuthorizationEndpoint string `json:"authorizationEndpoint,omitempty"`

	// TokenEndpoint is the URL of the token endpoint.
	TokenEndpoint string `json:"tokenEndpoint,omitempty"`

	// JWKSURI is the URL of the JSON Web Key Set.
	JWKSURI string `json:"jwksUri,omitempty"`

	// UserinfoEndpoint is the URL of the userinfo endpoint.
	UserinfoEndpoint string `json:"userinfoEndpoint,omitempty"`

	// DeviceAuthorizationEndpoint is the URL of the device authorization endpoint.
	DeviceAuthorizationEndpoint string `json:"deviceAuthorizationEndpoint,omitempty"`

	// IntrospectionEndpoint is the URL of the token introspection endpoint.
	IntrospectionEndpoint string `json:"introspectionEndpoint,omitempty"`

	// GrantTypesSupported is the list of supported grant types.
	GrantTypesSupported []string `json:"grantTypesSupported,omitempty"`

	// ResponseTypesSupported is the list of supported response types.
	ResponseTypesSupported []string `json:"responseTypesSupported,omitempty"`

	// SubjectTypesSupported is the list of supported subject types.
	SubjectTypesSupported []string `json:"subjectTypesSupported,omitempty"`

	// IDTokenSigningAlgValuesSupported is the list of supported ID token signing algorithms.
	IDTokenSigningAlgValuesSupported []string `json:"idTokenSigningAlgValuesSupported,omitempty"`

	// CodeChallengeMethodsSupported is the list of supported PKCE code challenge methods.
	CodeChallengeMethodsSupported []string `json:"codeChallengeMethodsSupported,omitempty"`

	// ScopesSupported is the list of supported scopes.
	ScopesSupported []string `json:"scopesSupported,omitempty"`

	// TokenEndpointAuthMethodsSupported is the list of supported token endpoint auth methods.
	TokenEndpointAuthMethodsSupported []string `json:"tokenEndpointAuthMethodsSupported,omitempty"`

	// ClaimsSupported is the list of supported claims.
	ClaimsSupported []string `json:"claimsSupported,omitempty"`
}

// A DiscoverySpec defines the desired state of a Discovery resource.
type DiscoverySpec struct {
	xpv2.ManagedResourceSpec `json:",inline"`
	ForProvider              DiscoveryParameters `json:"forProvider"`
}

// A DiscoveryStatus represents the observed state of a Discovery resource.
type DiscoveryStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          DiscoveryObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A Discovery is an observe-only resource that fetches OIDC discovery information from Dex.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="ISSUER",type="string",JSONPath=".status.atProvider.issuer"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,dex}
type Discovery struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   DiscoverySpec   `json:"spec"`
	Status DiscoveryStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// DiscoveryList contains a list of Discovery
type DiscoveryList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Discovery `json:"items"`
}

// Discovery type metadata.
var (
	DiscoveryKind             = reflect.TypeOf(Discovery{}).Name()
	DiscoveryGroupKind        = schema.GroupKind{Group: Group, Kind: DiscoveryKind}.String()
	DiscoveryKindAPIVersion   = DiscoveryKind + "." + SchemeGroupVersion.String()
	DiscoveryGroupVersionKind = SchemeGroupVersion.WithKind(DiscoveryKind)
)

func init() {
	SchemeBuilder.Register(&Discovery{}, &DiscoveryList{})
}
