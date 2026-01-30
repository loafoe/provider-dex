# Dex Provider

`provider-dex` is a Crossplane provider that enables the management of [Dex](https://dexidp.io/) resources using Kubernetes Custom Resources. It allows you to provision and manage Dex connectors, OAuth2 clients, and other configuration declaratively.

## Overview

This provider allows platform teams to embed Dex identity management into their control planes, managing authentication configuration alongside infrastructure and application deployments.

## Prerequisites

For the provider to manage connectors via gRPC, your Dex deployment must be configured with the following environment variable:

```bash
DEX_API_CONNECTORS_CRUD=true
```
 
## Installation

Install the provider by applying the following `Provider` manifest to your Crossplane cluster:

```yaml
apiVersion: pkg.crossplane.io/v1
kind: Provider
metadata:
  name: provider-dex
spec:
  package: xpkg.upbound.io/loafoe/provider-dex:v1.10.0
```

## Configuration

1. **Create a Secret** containing the necessary credentials (e.g., mTLS certificates or API tokens) to communicate with the Dex gRPC API.
2. **Apply a `ProviderConfig`** to configure the connection:

```yaml
apiVersion: dex.crossplane.io/v1beta1
kind: ProviderConfig
metadata:
  name: default
spec:
  credentials:
    source: Secret
    secretRef:
      namespace: crossplane-system
      name: dex-creds
      key: credentials
    # Address of the Dex gRPC API
    address: dex.auth.svc.cluster.local:5557
 
## License

This project is licensed under the Apache 2.0 License.
