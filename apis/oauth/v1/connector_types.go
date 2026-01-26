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

// ConnectorParameters are the configurable fields of a Dex Connector.
type ConnectorParameters struct {
	// ID is the connector ID. If not specified, the metadata.name will be used.
	// +optional
	ID string `json:"id,omitempty"`

	// Type is the connector type (e.g., "oidc", "ldap", "github").
	// +kubebuilder:validation:Required
	Type string `json:"type"`

	// Name is the connector name.
	// +kubebuilder:validation:Required
	Name string `json:"name"`

	// ConfigSecretRef corresponds to the secret key that contains the raw, byte-encoded configuration JSON.
	// The configuration is specific to the connector type.
	// +optional
	ConfigSecretRef *xpv1.SecretKeySelector `json:"configSecretRef,omitempty"`
}

// ConnectorObservation are the observable fields of a Dex Connector.
type ConnectorObservation struct {
	// ID is the actual connector ID in Dex.
	ID string `json:"id,omitempty"`
}

// A ConnectorSpec defines the desired state of a Connector.
type ConnectorSpec struct {
	xpv2.ManagedResourceSpec `json:",inline"`
	ForProvider              ConnectorParameters `json:"forProvider"`
}

// A ConnectorStatus represents the observed state of a Connector.
type ConnectorStatus struct {
	xpv1.ResourceStatus `json:",inline"`
	AtProvider          ConnectorObservation `json:"atProvider,omitempty"`
}

// +kubebuilder:object:root=true

// A Connector is a Dex Connector managed resource.
// +kubebuilder:printcolumn:name="READY",type="string",JSONPath=".status.conditions[?(@.type=='Ready')].status"
// +kubebuilder:printcolumn:name="SYNCED",type="string",JSONPath=".status.conditions[?(@.type=='Synced')].status"
// +kubebuilder:printcolumn:name="CONNECTOR-ID",type="string",JSONPath=".status.atProvider.id"
// +kubebuilder:printcolumn:name="TYPE",type="string",JSONPath=".spec.forProvider.type"
// +kubebuilder:printcolumn:name="AGE",type="date",JSONPath=".metadata.creationTimestamp"
// +kubebuilder:subresource:status
// +kubebuilder:resource:scope=Namespaced,categories={crossplane,managed,dex}
type Connector struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ConnectorSpec   `json:"spec"`
	Status ConnectorStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ConnectorList contains a list of Connector
type ConnectorList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []Connector `json:"items"`
}

// Connector type metadata.
var (
	ConnectorKind             = reflect.TypeOf(Connector{}).Name()
	ConnectorGroupKind        = schema.GroupKind{Group: Group, Kind: ConnectorKind}.String()
	ConnectorKindAPIVersion   = ConnectorKind + "." + SchemeGroupVersion.String()
	ConnectorGroupVersionKind = SchemeGroupVersion.WithKind(ConnectorKind)
)

func init() {
	SchemeBuilder.Register(&Connector{}, &ConnectorList{})
}
