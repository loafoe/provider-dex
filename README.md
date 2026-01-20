# provider-dex

`provider-dex` is a [Crossplane](https://crossplane.io/) Provider for managing
[Dex](https://dexidp.io/) OAuth2/OIDC resources via the Dex gRPC API.

## Features

- Manage Dex OAuth2 clients as Kubernetes resources
- Observe OIDC discovery information from Dex
- Support for both namespace-scoped `ProviderConfig` and cluster-scoped `ClusterProviderConfig`
- TLS/mTLS authentication support for secure gRPC connections
- Automatic client secret generation with connection secret support

## Requirements

- Dex must be configured with gRPC API enabled
- Dex must use a storage backend that supports `ListClients` (sqlite, postgres, mysql)
  - The Kubernetes storage backend does **not** support the gRPC API for client management

## Resources

### Client

The `Client` resource manages OAuth2 clients in Dex.

```yaml
apiVersion: oauth.dex.crossplane.io/v1alpha1
kind: Client
metadata:
  name: my-app
  namespace: default
spec:
  forProvider:
    id: my-app
    name: "My Application"
    redirectURIs:
      - "https://my-app.example.com/callback"
    public: false
  providerConfigRef:
    name: dex-config
    kind: ClusterProviderConfig
  writeConnectionSecretToRef:
    name: my-app-credentials
```

#### Spec Fields

| Field | Type | Description |
|-------|------|-------------|
| `forProvider.id` | string | OAuth2 client ID (defaults to resource name) |
| `forProvider.name` | string | Human-readable client name |
| `forProvider.redirectURIs` | []string | Allowed redirect URIs |
| `forProvider.trustedPeers` | []string | Client IDs that can exchange tokens |
| `forProvider.public` | bool | Public client (no secret required) |
| `forProvider.logoURL` | string | URL to client logo |
| `forProvider.secret` | string | Client secret (auto-generated if not set) |
| `forProvider.secretRef` | SecretKeySelector | Reference to existing secret |

#### Connection Secret

When `writeConnectionSecretToRef` is specified, the provider writes:
- `clientId` - The OAuth2 client ID
- `clientSecret` - The generated or provided client secret

### Discovery

The `Discovery` resource is an **observe-only** resource that fetches OIDC discovery information from Dex.

```yaml
apiVersion: oauth.dex.crossplane.io/v1alpha1
kind: Discovery
metadata:
  name: dex-discovery
  namespace: default
spec:
  forProvider: {}
  providerConfigRef:
    name: dex-config
    kind: ClusterProviderConfig
  managementPolicies:
    - Observe
```

#### Observed Fields

The discovery information is available in `status.atProvider`:

| Field | Description |
|-------|-------------|
| `issuer` | OIDC issuer URL |
| `authorizationEndpoint` | Authorization endpoint URL |
| `tokenEndpoint` | Token endpoint URL |
| `jwksUri` | JSON Web Key Set URL |
| `userinfoEndpoint` | Userinfo endpoint URL |
| `deviceAuthorizationEndpoint` | Device authorization endpoint URL |
| `introspectionEndpoint` | Token introspection endpoint URL |
| `grantTypesSupported` | Supported grant types |
| `responseTypesSupported` | Supported response types |
| `subjectTypesSupported` | Supported subject types |
| `idTokenSigningAlgValuesSupported` | Supported ID token signing algorithms |
| `codeChallengeMethodsSupported` | Supported PKCE code challenge methods |
| `scopesSupported` | Supported scopes |
| `tokenEndpointAuthMethodsSupported` | Supported token endpoint auth methods |
| `claimsSupported` | Supported claims |

### ProviderConfig / ClusterProviderConfig

Configure the connection to Dex gRPC API:

```yaml
apiVersion: dex.crossplane.io/v1alpha1
kind: ClusterProviderConfig
metadata:
  name: dex-config
spec:
  endpoint: "dex.iam-dex.svc.cluster.local:5557"
  # Optional TLS configuration
  tls:
    caSecretRef:
      name: dex-ca
      namespace: iam-dex
      key: ca.crt
    clientCertSecretRef:
      name: dex-client-cert
      namespace: iam-dex
      key: tls.crt
    clientKeySecretRef:
      name: dex-client-cert
      namespace: iam-dex
      key: tls.key
```

## Developing

1. Run `make reviewable` to run code generation, linters, and tests.
2. Run `make build` to build the provider.

Refer to Crossplane's [CONTRIBUTING.md] file for more information on how the
Crossplane community prefers to work. The [Provider Development][provider-dev]
guide may also be of use.

[CONTRIBUTING.md]: https://github.com/crossplane/crossplane/blob/master/CONTRIBUTING.md
[provider-dev]: https://github.com/crossplane/crossplane/blob/master/contributing/guide-provider-development.md
