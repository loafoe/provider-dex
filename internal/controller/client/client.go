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
	"crypto/rand"
	"encoding/hex"
	"reflect"
	"strings"

	"github.com/dexidp/dex/api/v2"
	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/v2/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/v2/pkg/controller"
	"github.com/crossplane/crossplane-runtime/v2/pkg/event"
	"github.com/crossplane/crossplane-runtime/v2/pkg/feature"
	"github.com/crossplane/crossplane-runtime/v2/pkg/meta"
	"github.com/crossplane/crossplane-runtime/v2/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/v2/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	"github.com/crossplane/crossplane-runtime/v2/pkg/statemetrics"

	v1 "github.com/crossplane/provider-dex/apis/oauth/v1"
	apisv1alpha1 "github.com/crossplane/provider-dex/apis/v1alpha1"
	dexclient "github.com/crossplane/provider-dex/internal/clients/dex"
)

const (
	errNotClient    = "managed resource is not a Client custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCPC       = "cannot get ClusterProviderConfig"
	errGetTLSCreds  = "cannot get TLS credentials"

	errNewClient = "cannot create new Dex client"
	errObserve   = "cannot observe client"
	errCreate    = "cannot create client"
	errUpdate    = "cannot update client"
	errDelete    = "cannot delete client"
	errGetSecret = "cannot get secret"
	errGenSecret = "cannot generate secret"
)

// SetupGated adds a controller that reconciles Client managed resources with safe-start support.
func SetupGated(mgr ctrl.Manager, o controller.Options) error {
	o.Gate.Register(func() {
		if err := Setup(mgr, o); err != nil {
			panic(errors.Wrap(err, "cannot setup Client controller"))
		}
	}, v1.ClientGroupVersionKind)
	return nil
}

func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1.ClientGroupKind)

	opts := []managed.ReconcilerOption{
		managed.WithExternalConnector(&connector{
			kube:  mgr.GetClient(),
			usage: resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1alpha1.ProviderConfigUsage{}),
		}),
		managed.WithLogger(o.Logger.WithValues("controller", name)),
		managed.WithPollInterval(o.PollInterval),
		managed.WithRecorder(event.NewAPIRecorder(mgr.GetEventRecorderFor(name))),
	}

	if o.Features.Enabled(feature.EnableBetaManagementPolicies) {
		opts = append(opts, managed.WithManagementPolicies())
	}

	if o.Features.Enabled(feature.EnableAlphaChangeLogs) {
		opts = append(opts, managed.WithChangeLogger(o.ChangeLogOptions.ChangeLogger))
	}

	if o.MetricOptions != nil {
		opts = append(opts, managed.WithMetricRecorder(o.MetricOptions.MRMetrics))
	}

	if o.MetricOptions != nil && o.MetricOptions.MRStateMetrics != nil {
		stateMetricsRecorder := statemetrics.NewMRStateRecorder(
			mgr.GetClient(), o.Logger, o.MetricOptions.MRStateMetrics, &v1.ClientList{}, o.MetricOptions.PollStateMetricInterval,
		)
		if err := mgr.Add(stateMetricsRecorder); err != nil {
			return errors.Wrap(err, "cannot register MR state metrics recorder for kind v1alpha1.ClientList")
		}
	}

	r := managed.NewReconciler(mgr, resource.ManagedKind(v1.ClientGroupVersionKind), opts...)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1.Client{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

// A connector is expected to produce an ExternalClient when its Connect method
// is called.
type connector struct {
	kube  client.Client
	usage *resource.ProviderConfigUsageTracker
}

// Connect produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the TLS credentials specified by the ProviderConfig.
// 4. Using the credentials to form a Dex gRPC client.
//
//nolint:gocyclo // Complexity is due to handling multiple ProviderConfig types and TLS setup; logic is linear and readable
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1.Client)
	if !ok {
		return nil, errors.New(errNotClient)
	}

	if err := c.usage.Track(ctx, cr); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	// Get ProviderConfigRef
	m := mg.(resource.ModernManaged)
	ref := m.GetProviderConfigReference()

	var spec apisv1alpha1.ProviderConfigSpec

	switch ref.Kind {
	case "ProviderConfig":
		pc := &apisv1alpha1.ProviderConfig{}
		if err := c.kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: m.GetNamespace()}, pc); err != nil {
			return nil, errors.Wrap(err, errGetPC)
		}
		spec = pc.Spec
	case "ClusterProviderConfig":
		cpc := &apisv1alpha1.ClusterProviderConfig{}
		if err := c.kube.Get(ctx, types.NamespacedName{Name: ref.Name}, cpc); err != nil {
			return nil, errors.Wrap(err, errGetCPC)
		}
		spec = cpc.Spec
	default:
		return nil, errors.Errorf("unsupported provider config kind: %s", ref.Kind)
	}

	// Build Dex client config
	cfg := dexclient.Config{
		Endpoint: spec.Endpoint,
	}

	// Extract TLS credentials if configured
	if spec.TLS != nil {
		cfg.InsecureSkipVerify = spec.TLS.InsecureSkipVerify

		if spec.TLS.CACert != nil {
			caCert, err := c.extractSecretData(ctx, spec.TLS.CACert)
			if err != nil {
				return nil, errors.Wrap(err, errGetTLSCreds)
			}
			cfg.CACert = caCert
		}

		if spec.TLS.ClientCert != nil {
			clientCert, err := c.extractSecretData(ctx, spec.TLS.ClientCert)
			if err != nil {
				return nil, errors.Wrap(err, errGetTLSCreds)
			}
			cfg.ClientCert = clientCert
		}

		if spec.TLS.ClientKey != nil {
			clientKey, err := c.extractSecretData(ctx, spec.TLS.ClientKey)
			if err != nil {
				return nil, errors.Wrap(err, errGetTLSCreds)
			}
			cfg.ClientKey = clientKey
		}
	}

	dex, err := dexclient.NewClient(cfg)
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}

	return &external{dex: dex, kube: c.kube}, nil
}

// extractSecretData extracts data from a secret using the given selector.
func (c *connector) extractSecretData(ctx context.Context, sel *xpv1.SecretKeySelector) ([]byte, error) {
	secret := &corev1.Secret{}
	if err := c.kube.Get(ctx, types.NamespacedName{
		Name:      sel.Name,
		Namespace: sel.Namespace,
	}, secret); err != nil {
		return nil, errors.Wrap(err, errGetSecret)
	}

	data, ok := secret.Data[sel.Key]
	if !ok {
		return nil, errors.Errorf("secret %s/%s does not contain key %s", sel.Namespace, sel.Name, sel.Key)
	}

	return data, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	dex  *dexclient.Client
	kube client.Client
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1.Client)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotClient)
	}

	// Get the client ID - use spec.forProvider.id or metadata.name
	clientID := cr.Spec.ForProvider.ID
	if clientID == "" {
		clientID = cr.GetName()
	}

	// Check if client exists in Dex
	existing, err := c.dex.GetClient(ctx, clientID)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, errObserve)
	}

	if existing == nil {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}

	// Update status with observed values
	cr.Status.AtProvider = v1.ClientObservation{
		ID:           existing.GetId(),
		Name:         existing.GetName(),
		Public:       existing.GetPublic(),
		RedirectURIs: existing.GetRedirectUris(),
	}

	// Check if the resource is up to date
	upToDate := isClientUpToDate(cr.Spec.ForProvider, existing)

	if upToDate {
		cr.Status.SetConditions(xpv1.Available())
	}

	return managed.ExternalObservation{
		ResourceExists:    true,
		ResourceUpToDate:  upToDate,
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

//nolint:gocyclo // Complexity is due to handling secret retrieval, generation, and connection details; logic is straightforward
func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1.Client)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotClient)
	}

	cr.Status.SetConditions(xpv1.Creating())

	// Get the client ID - use spec.forProvider.id or metadata.name
	clientID := cr.Spec.ForProvider.ID
	if clientID == "" {
		clientID = cr.GetName()
	}

	// Get or generate client secret
	clientSecret := cr.Spec.ForProvider.Secret
	if clientSecret == "" && cr.Spec.ForProvider.SecretRef != nil {
		secretData, err := c.extractSecretData(ctx, cr.Spec.ForProvider.SecretRef)
		if err != nil {
			return managed.ExternalCreation{}, errors.Wrap(err, errGetSecret)
		}
		clientSecret = string(secretData)
	}
	if clientSecret == "" && !cr.Spec.ForProvider.Public {
		generated, err := generateSecret(32)
		if err != nil {
			return managed.ExternalCreation{}, errors.Wrap(err, errGenSecret)
		}
		clientSecret = generated
	}

	// Build Dex client
	dexClient := &api.Client{
		Id:           clientID,
		Secret:       clientSecret,
		RedirectUris: cr.Spec.ForProvider.RedirectURIs,
		TrustedPeers: cr.Spec.ForProvider.TrustedPeers,
		Public:       cr.Spec.ForProvider.Public,
		Name:         cr.Spec.ForProvider.Name,
		LogoUrl:      cr.Spec.ForProvider.LogoURL,
	}

	created, err := c.dex.CreateClient(ctx, dexClient)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, errCreate)
	}

	// Set external name to the client ID
	meta.SetExternalName(cr, created.GetId())

	// Return connection details including the secret from Dex response
	connDetails := managed.ConnectionDetails{
		"clientId": []byte(created.GetId()),
	}
	if created.GetSecret() != "" {
		connDetails["clientSecret"] = []byte(created.GetSecret())
	}

	return managed.ExternalCreation{
		ConnectionDetails: connDetails,
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1.Client)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotClient)
	}

	// Get the client ID
	clientID := cr.Spec.ForProvider.ID
	if clientID == "" {
		clientID = cr.GetName()
	}

	err := c.dex.UpdateClient(
		ctx,
		clientID,
		cr.Spec.ForProvider.RedirectURIs,
		cr.Spec.ForProvider.TrustedPeers,
		cr.Spec.ForProvider.Name,
		cr.Spec.ForProvider.LogoURL,
	)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, errUpdate)
	}

	return managed.ExternalUpdate{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) (managed.ExternalDelete, error) {
	cr, ok := mg.(*v1.Client)
	if !ok {
		return managed.ExternalDelete{}, errors.New(errNotClient)
	}

	cr.Status.SetConditions(xpv1.Deleting())

	// Get the client ID
	clientID := cr.Spec.ForProvider.ID
	if clientID == "" {
		clientID = cr.GetName()
	}

	err := c.dex.DeleteClient(ctx, clientID)
	if err != nil {
		// Ignore "not found" errors - the client is already gone
		if strings.Contains(err.Error(), "not found") {
			return managed.ExternalDelete{}, nil
		}
		return managed.ExternalDelete{}, errors.Wrap(err, errDelete)
	}

	return managed.ExternalDelete{}, nil
}

func (c *external) Disconnect(ctx context.Context) error {
	if c.dex != nil {
		return c.dex.Close()
	}
	return nil
}

// extractSecretData extracts data from a secret using the given selector.
func (c *external) extractSecretData(ctx context.Context, sel *xpv1.SecretKeySelector) ([]byte, error) {
	secret := &corev1.Secret{}
	if err := c.kube.Get(ctx, types.NamespacedName{
		Name:      sel.Name,
		Namespace: sel.Namespace,
	}, secret); err != nil {
		return nil, err
	}

	data, ok := secret.Data[sel.Key]
	if !ok {
		return nil, errors.Errorf("secret %s/%s does not contain key %s", sel.Namespace, sel.Name, sel.Key)
	}

	return data, nil
}

// generateSecret generates a random hex-encoded secret of the given length.
func generateSecret(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// isClientUpToDate checks if the Dex client matches the desired spec.
// Note: Uses ClientInfo since ListClients returns ClientInfo (without secret).
func isClientUpToDate(spec v1.ClientParameters, existing *api.ClientInfo) bool {
	if spec.Name != existing.GetName() {
		return false
	}
	if spec.LogoURL != existing.GetLogoUrl() {
		return false
	}
	if spec.Public != existing.GetPublic() {
		return false
	}
	if !reflect.DeepEqual(spec.RedirectURIs, existing.GetRedirectUris()) {
		return false
	}
	if !reflect.DeepEqual(spec.TrustedPeers, existing.GetTrustedPeers()) {
		return false
	}
	return true
}
