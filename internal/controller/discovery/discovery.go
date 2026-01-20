/*
Copyright 2025 The Crossplane Authors.

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

package discovery

import (
	"context"

	"github.com/pkg/errors"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	xpv1 "github.com/crossplane/crossplane-runtime/v2/apis/common/v1"
	"github.com/crossplane/crossplane-runtime/v2/pkg/controller"
	"github.com/crossplane/crossplane-runtime/v2/pkg/event"
	"github.com/crossplane/crossplane-runtime/v2/pkg/feature"
	"github.com/crossplane/crossplane-runtime/v2/pkg/ratelimiter"
	"github.com/crossplane/crossplane-runtime/v2/pkg/reconciler/managed"
	"github.com/crossplane/crossplane-runtime/v2/pkg/resource"
	"github.com/crossplane/crossplane-runtime/v2/pkg/statemetrics"

	v1 "github.com/crossplane/provider-dex/apis/oauth/v1"
	apisv1 "github.com/crossplane/provider-dex/apis/v1alpha1"
	dexclient "github.com/crossplane/provider-dex/internal/clients/dex"
)

const (
	errNotDiscovery = "managed resource is not a Discovery custom resource"
	errTrackPCUsage = "cannot track ProviderConfig usage"
	errGetPC        = "cannot get ProviderConfig"
	errGetCPC       = "cannot get ClusterProviderConfig"
	errGetTLSCreds  = "cannot get TLS credentials"

	errNewClient = "cannot create new Dex client"
	errObserve   = "cannot observe discovery"
)

// SetupGated adds a controller that reconciles Discovery managed resources with safe-start support.
func SetupGated(mgr ctrl.Manager, o controller.Options) error {
	o.Gate.Register(func() {
		if err := Setup(mgr, o); err != nil {
			panic(errors.Wrap(err, "cannot setup Discovery controller"))
		}
	}, v1.DiscoveryGroupVersionKind)
	return nil
}

func Setup(mgr ctrl.Manager, o controller.Options) error {
	name := managed.ControllerName(v1.DiscoveryGroupKind)

	opts := []managed.ReconcilerOption{
		managed.WithExternalConnector(&connector{
			kube:  mgr.GetClient(),
			usage: resource.NewProviderConfigUsageTracker(mgr.GetClient(), &apisv1.ProviderConfigUsage{}),
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
			mgr.GetClient(), o.Logger, o.MetricOptions.MRStateMetrics, &v1.DiscoveryList{}, o.MetricOptions.PollStateMetricInterval,
		)
		if err := mgr.Add(stateMetricsRecorder); err != nil {
			return errors.Wrap(err, "cannot register MR state metrics recorder for kind v1.DiscoveryList")
		}
	}

	r := managed.NewReconciler(mgr, resource.ManagedKind(v1.DiscoveryGroupVersionKind), opts...)

	return ctrl.NewControllerManagedBy(mgr).
		Named(name).
		WithOptions(o.ForControllerRuntime()).
		WithEventFilter(resource.DesiredStateChanged()).
		For(&v1.Discovery{}).
		Complete(ratelimiter.NewReconciler(name, r, o.GlobalRateLimiter))
}

// A connector is expected to produce an ExternalClient when its Connect method
// is called.
type connector struct {
	kube  client.Client
	usage *resource.ProviderConfigUsageTracker
}

// Connect typically produces an ExternalClient by:
// 1. Tracking that the managed resource is using a ProviderConfig.
// 2. Getting the managed resource's ProviderConfig.
// 3. Getting the credentials specified by the ProviderConfig.
// 4. Using the credentials to form a client.
func (c *connector) Connect(ctx context.Context, mg resource.Managed) (managed.ExternalClient, error) {
	cr, ok := mg.(*v1.Discovery)
	if !ok {
		return nil, errors.New(errNotDiscovery)
	}

	if err := c.usage.Track(ctx, cr); err != nil {
		return nil, errors.Wrap(err, errTrackPCUsage)
	}

	// Get ProviderConfigRef
	m := mg.(resource.ModernManaged)
	ref := m.GetProviderConfigReference()

	var spec apisv1.ProviderConfigSpec

	switch ref.Kind {
	case "ProviderConfig":
		pc := &apisv1.ProviderConfig{}
		if err := c.kube.Get(ctx, types.NamespacedName{Name: ref.Name, Namespace: m.GetNamespace()}, pc); err != nil {
			return nil, errors.Wrap(err, errGetPC)
		}
		spec = pc.Spec
	case "ClusterProviderConfig":
		fallthrough
	default:
		cpc := &apisv1.ClusterProviderConfig{}
		if err := c.kube.Get(ctx, types.NamespacedName{Name: ref.Name}, cpc); err != nil {
			return nil, errors.Wrap(err, errGetCPC)
		}
		spec = cpc.Spec
	}

	// Build Dex client config
	cfg := dexclient.Config{
		Endpoint: spec.Endpoint,
	}

	// Get TLS credentials if configured
	if spec.TLS != nil {
		tlsCreds, err := c.getTLSCredentials(ctx, spec.TLS)
		if err != nil {
			return nil, errors.Wrap(err, errGetTLSCreds)
		}
		cfg.CACert = tlsCreds.caCert
		cfg.ClientCert = tlsCreds.clientCert
		cfg.ClientKey = tlsCreds.clientKey
	}

	// Create Dex client
	dex, err := dexclient.NewClient(cfg)
	if err != nil {
		return nil, errors.Wrap(err, errNewClient)
	}

	return &external{
		dex:  dex,
		kube: c.kube,
	}, nil
}

type tlsCredentials struct {
	caCert     []byte
	clientCert []byte
	clientKey  []byte
}

func (c *connector) getTLSCredentials(ctx context.Context, tls *apisv1.TLSConfig) (*tlsCredentials, error) {
	creds := &tlsCredentials{}

	// Get CA certificate
	if tls.CACert != nil {
		data, err := c.getSecretData(ctx, tls.CACert)
		if err != nil {
			return nil, errors.Wrap(err, "cannot get CA certificate")
		}
		creds.caCert = data
	}

	// Get client certificate
	if tls.ClientCert != nil {
		data, err := c.getSecretData(ctx, tls.ClientCert)
		if err != nil {
			return nil, errors.Wrap(err, "cannot get client certificate")
		}
		creds.clientCert = data
	}

	// Get client key
	if tls.ClientKey != nil {
		data, err := c.getSecretData(ctx, tls.ClientKey)
		if err != nil {
			return nil, errors.Wrap(err, "cannot get client key")
		}
		creds.clientKey = data
	}

	return creds, nil
}

func (c *connector) getSecretData(ctx context.Context, ref *xpv1.SecretKeySelector) ([]byte, error) {
	secret := &corev1.Secret{}
	if err := c.kube.Get(ctx, types.NamespacedName{
		Namespace: ref.Namespace,
		Name:      ref.Name,
	}, secret); err != nil {
		return nil, err
	}

	data, ok := secret.Data[ref.Key]
	if !ok {
		return nil, errors.Errorf("secret %s/%s does not contain key %s", ref.Namespace, ref.Name, ref.Key)
	}

	return data, nil
}

// An ExternalClient observes, then either creates, updates, or deletes an
// external resource to ensure it reflects the managed resource's desired state.
type external struct {
	dex  *dexclient.Client
	kube client.Client
}

func (c *external) Disconnect(ctx context.Context) error {
	return c.dex.Close()
}

func (c *external) Observe(ctx context.Context, mg resource.Managed) (managed.ExternalObservation, error) {
	cr, ok := mg.(*v1.Discovery)
	if !ok {
		return managed.ExternalObservation{}, errors.New(errNotDiscovery)
	}

	// Get discovery information from Dex
	discovery, err := c.dex.GetDiscovery(ctx)
	if err != nil {
		return managed.ExternalObservation{}, errors.Wrap(err, errObserve)
	}

	// Update status with observed values
	cr.Status.AtProvider = v1.DiscoveryObservation{
		Issuer:                            discovery.Issuer,
		AuthorizationEndpoint:             discovery.AuthorizationEndpoint,
		TokenEndpoint:                     discovery.TokenEndpoint,
		JWKSURI:                           discovery.JwksUri,
		UserinfoEndpoint:                  discovery.UserinfoEndpoint,
		DeviceAuthorizationEndpoint:       discovery.DeviceAuthorizationEndpoint,
		IntrospectionEndpoint:             discovery.IntrospectionEndpoint,
		GrantTypesSupported:               discovery.GrantTypesSupported,
		ResponseTypesSupported:            discovery.ResponseTypesSupported,
		SubjectTypesSupported:             discovery.SubjectTypesSupported,
		IDTokenSigningAlgValuesSupported:  discovery.IdTokenSigningAlgValuesSupported,
		CodeChallengeMethodsSupported:     discovery.CodeChallengeMethodsSupported,
		ScopesSupported:                   discovery.ScopesSupported,
		TokenEndpointAuthMethodsSupported: discovery.TokenEndpointAuthMethodsSupported,
		ClaimsSupported:                   discovery.ClaimsSupported,
	}

	cr.Status.SetConditions(xpv1.Available())

	return managed.ExternalObservation{
		ResourceExists:   true,
		ResourceUpToDate: true,
	}, nil
}

func (c *external) Create(ctx context.Context, mg resource.Managed) (managed.ExternalCreation, error) {
	// Discovery is observe-only, no creation needed
	return managed.ExternalCreation{}, nil
}

func (c *external) Update(ctx context.Context, mg resource.Managed) (managed.ExternalUpdate, error) {
	// Discovery is observe-only, no updates needed
	return managed.ExternalUpdate{}, nil
}

func (c *external) Delete(ctx context.Context, mg resource.Managed) (managed.ExternalDelete, error) {
	// Discovery is observe-only, no deletion needed
	return managed.ExternalDelete{}, nil
}
