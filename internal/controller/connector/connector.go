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

package connector

import (
	"bytes"
	"context"
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
	errNotConnector = "managed resource is not a Connector custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCPC       = "cannot get ClusterProviderConfig"
	errGetTLSCreds  = "cannot get TLS credentials"

	errNewClient = "cannot create new Dex client"
	errObserve   = "cannot observe connector"
	errCreate    = "cannot create connector"
	errUpdate    = "cannot update connector"
	errDelete    = "cannot delete connector"
	errGetSecret = "cannot get secret"
)

// SetupGated adds a controller that reconciles Connector managed resources with safe-start support.
func SetupGated(mgr ctrl.Manager, o controller.Options) error {
	o.Gate.Register(func() {
		if err := Setup(mgr, o); err != nil {
			panic(errors.Wrap(err, "cannot setup Connector controller"))
		}
	}, v1.ConnectorGroupVersionKind)
	return nil
}

func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1.ConnectorGroupKind)

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
			mgr.GetClient(), o.Logger, o.MetricOptions.MRStateMetrics, &v1.ConnectorList{}, o.MetricOptions.PollStateMetricInterval,
		)
		if err := mgr.Add(stateMetricsRecorder); err != nil {
			return errors.Wrap(err, "cannot register MR state metrics recorder for kind v1.ConnectorList")
		}
	}

	r := managed.NewReconciler(mgr, resource.ManagedKind(v1.ConnectorGroupVersionKind), opts...)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1.Connector{}).
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
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1.Connector)
	if !ok {
		return nil, errors.New(errNotConnector)
	}

	if err := c.usage.Track(ctx, cr); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	spec, err := c.getProviderConfigSpec(ctx, mg)
	if err != nil {
		return nil, err
	}

	cfg, err := c.getDexClientConfig(ctx, spec)
	if err != nil {
		return nil, err
	}

	dex, err := dexclient.NewClient(cfg)
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}

	return &external{dex: dex, kube: c.kube}, nil
}

func (c *connector) getProviderConfigSpec(ctx context.Context, mg resource.Managed) (apisv1alpha1.ProviderConfigSpec, error) {
	m := mg.(resource.ModernManaged)
	ref := m.GetProviderConfigReference()

	var spec apisv1alpha1.ProviderConfigSpec

	switch ref.Kind {
	case "ProviderConfig":
		pc := &apisv1alpha1.ProviderConfig{}
		if err := c.kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: m.GetNamespace()}, pc); err != nil {
			return spec, errors.Wrap(err, errGetPC)
		}
		spec = pc.Spec
	case "ClusterProviderConfig":
		cpc := &apisv1alpha1.ClusterProviderConfig{}
		if err := c.kube.Get(ctx, types.NamespacedName{Name: ref.Name}, cpc); err != nil {
			return spec, errors.Wrap(err, errGetCPC)
		}
		spec = cpc.Spec
	default:
		return spec, errors.Errorf("unsupported provider config kind: %s", ref.Kind)
	}
	return spec, nil
}

func (c *connector) getDexClientConfig(ctx context.Context, spec apisv1alpha1.ProviderConfigSpec) (dexclient.Config, error) {
	cfg := dexclient.Config{
		Endpoint: spec.Endpoint,
	}

	// Extract TLS credentials if configured
	if spec.TLS != nil {
		cfg.InsecureSkipVerify = spec.TLS.InsecureSkipVerify

		if spec.TLS.CACert != nil {
			caCert, err := c.extractSecretData(ctx, spec.TLS.CACert)
			if err != nil {
				return cfg, errors.Wrap(err, errGetTLSCreds)
			}
			cfg.CACert = caCert
		}

		if spec.TLS.ClientCert != nil {
			clientCert, err := c.extractSecretData(ctx, spec.TLS.ClientCert)
			if err != nil {
				return cfg, errors.Wrap(err, errGetTLSCreds)
			}
			cfg.ClientCert = clientCert
		}

		if spec.TLS.ClientKey != nil {
			clientKey, err := c.extractSecretData(ctx, spec.TLS.ClientKey)
			if err != nil {
				return cfg, errors.Wrap(err, errGetTLSCreds)
			}
			cfg.ClientKey = clientKey
		}
	}
	return cfg, nil
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
	cr, ok := mg.(*v1.Connector)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotConnector)
	}

	// Get the connector ID - use spec.forProvider.id or metadata.name
	connectorID := cr.Spec.ForProvider.ID
	if connectorID == "" {
		connectorID = cr.GetName()
	}

	// Check if connector exists in Dex
	existing, err := c.dex.GetConnector(ctx, connectorID)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, errObserve)
	}

	if existing == nil {
		return managed.ExternalObservation{
			ResourceExists: false,
		}, nil
	}

	// Update status with observed values
	cr.Status.AtProvider = v1.ConnectorObservation{
		ID: existing.GetId(),
	}

	// Check if the resource is up to date
	// We need to fetch the local config first
	config, err := c.connectorConfig(ctx, cr)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, errGetSecret)
	}

	// If config is fetched, use it to check up-to-date status
	upToDate := isConnectorUpToDate(cr.Spec.ForProvider, config, existing)

	if upToDate {
		cr.Status.SetConditions(xpv1.Available())
	}

	return managed.ExternalObservation{
		ResourceExists:    true,
		ResourceUpToDate:  upToDate,
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	cr, ok := mg.(*v1.Connector)
	if !ok {
		return managed.ExternalCreation{}, errors.New(errNotConnector)
	}

	cr.Status.SetConditions(xpv1.Creating())

	// Get the connector ID
	connectorID := cr.Spec.ForProvider.ID
	if connectorID == "" {
		connectorID = cr.GetName()
	}

	// Get configuration
	config, err := c.connectorConfig(ctx, cr)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, errGetSecret)
	}

	// Build Dex connector
	dexConnector := &api.Connector{
		Id:     connectorID,
		Type:   cr.Spec.ForProvider.Type,
		Name:   cr.Spec.ForProvider.Name,
		Config: config,
	}

	_, err = c.dex.CreateConnector(ctx, dexConnector)
	if err != nil {
		return managed.ExternalCreation{}, errors.Wrap(err, errCreate)
	}

	// Set external name to the connector ID
	meta.SetExternalName(cr, connectorID)

	return managed.ExternalCreation{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	cr, ok := mg.(*v1.Connector)
	if !ok {
		return managed.ExternalUpdate{}, errors.New(errNotConnector)
	}

	// Get the connector ID
	connectorID := cr.Spec.ForProvider.ID
	if connectorID == "" {
		connectorID = cr.GetName()
	}

	// Get configuration
	config, err := c.connectorConfig(ctx, cr)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, errGetSecret)
	}

	err = c.dex.UpdateConnector(
		ctx,
		connectorID,
		cr.Spec.ForProvider.Type,
		cr.Spec.ForProvider.Name,
		config,
	)
	if err != nil {
		return managed.ExternalUpdate{}, errors.Wrap(err, errUpdate)
	}

	return managed.ExternalUpdate{
		ConnectionDetails: managed.ConnectionDetails{},
	}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) (managed.ExternalDelete, error) {
	cr, ok := mg.(*v1.Connector)
	if !ok {
		return managed.ExternalDelete{}, errors.New(errNotConnector)
	}

	cr.Status.SetConditions(xpv1.Deleting())

	// Get the connector ID
	connectorID := cr.Spec.ForProvider.ID
	if connectorID == "" {
		connectorID = cr.GetName()
	}

	err := c.dex.DeleteConnector(ctx, connectorID)
	if err != nil {
		// Ignore "not found" errors - the connector is already gone
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

// connectorConfig retrieves the connector configuration from the secret referenced in the spec.
func (c *external) connectorConfig(ctx context.Context, cr *v1.Connector) ([]byte, error) {
	if cr.Spec.ForProvider.ConfigSecretRef != nil {
		secret := &corev1.Secret{}
		if err := c.kube.Get(ctx, types.NamespacedName{
			Name:      cr.Spec.ForProvider.ConfigSecretRef.Name,
			Namespace: cr.Spec.ForProvider.ConfigSecretRef.Namespace,
		}, secret); err != nil {
			return nil, err
		}

		data, ok := secret.Data[cr.Spec.ForProvider.ConfigSecretRef.Key]
		if !ok {
			return nil, errors.Errorf("secret %s/%s does not contain key %s",
				cr.Spec.ForProvider.ConfigSecretRef.Namespace,
				cr.Spec.ForProvider.ConfigSecretRef.Name,
				cr.Spec.ForProvider.ConfigSecretRef.Key)
		}
		return data, nil
	}
	// TODO: Support inline config if we add it to parameters
	return nil, nil // No config
}

// isConnectorUpToDate checks if the Dex connector matches the desired spec.
func isConnectorUpToDate(spec v1.ConnectorParameters, config []byte, existing *api.Connector) bool {
	if spec.Name != existing.GetName() {
		return false
	}
	if spec.Type != existing.GetType() {
		return false
	}
	// Determine if config changed.
	// This is tricky because existing.GetConfig() might be formatted differently.
	// For now, we do a byte comparison which implies the user must ensure consistent formatting.
	// Or we could JSON decode both and compare.
	// Let's stick to byte comparison for simplicity as per common Crossplane pattern,
	// but strictly speaking, JSON equivalence is better.
	if !bytes.Equal(config, existing.GetConfig()) {
		return false
	}

	return true
}
