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

package dex

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"github.com/dexidp/dex/api/v2"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Config holds the configuration for connecting to a Dex gRPC server.
type Config struct {
	// Endpoint is the Dex gRPC API endpoint (e.g., "dex:5557").
	Endpoint string

	// CACert is the CA certificate PEM data for verifying the server.
	CACert []byte

	// ClientCert is the client certificate PEM data for mTLS.
	ClientCert []byte

	// ClientKey is the client private key PEM data for mTLS.
	ClientKey []byte

	// InsecureSkipVerify skips TLS verification (not recommended for production).
	InsecureSkipVerify bool
}

// Client wraps the Dex gRPC client.
type Client struct {
	conn *grpc.ClientConn
	dex  api.DexClient
}

// NewClient creates a new Dex gRPC client with the given configuration.
func NewClient(cfg Config) (*Client, error) {
	var opts []grpc.DialOption

	// If no TLS config is provided, use insecure connection
	if cfg.CACert == nil && cfg.ClientCert == nil && !cfg.InsecureSkipVerify {
		opts = append(opts, grpc.WithTransportCredentials(insecure.NewCredentials()))
	} else {
		tlsConfig, err := buildTLSConfig(cfg)
		if err != nil {
			return nil, errors.Wrap(err, "failed to build TLS config")
		}
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)))
	}

	conn, err := grpc.NewClient(cfg.Endpoint, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to dial Dex gRPC server")
	}

	return &Client{
		conn: conn,
		dex:  api.NewDexClient(conn),
	}, nil
}

func buildTLSConfig(cfg Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	// Add CA certificate if provided
	if len(cfg.CACert) > 0 {
		cPool := x509.NewCertPool()
		if !cPool.AppendCertsFromPEM(cfg.CACert) {
			return nil, fmt.Errorf("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = cPool
	}

	// Add client certificate if provided (for mTLS)
	if len(cfg.ClientCert) > 0 && len(cfg.ClientKey) > 0 {
		clientCert, err := tls.X509KeyPair(cfg.ClientCert, cfg.ClientKey)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load client certificate")
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	}

	return tlsConfig, nil
}

// Close closes the gRPC connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// CreateClient creates a new OAuth2 client in Dex.
func (c *Client) CreateClient(ctx context.Context, client *api.Client) (*api.Client, error) {
	req := &api.CreateClientReq{
		Client: client,
	}

	resp, err := c.dex.CreateClient(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create client")
	}

	if resp.AlreadyExists {
		return nil, fmt.Errorf("client with ID %q already exists", client.Id)
	}

	return resp.Client, nil
}

// GetClient retrieves an OAuth2 client from Dex by ID.
// Note: Dex API returns ClientInfo (without secret) from ListClients.
// Returns an error if ListClients is not implemented by the storage backend.
func (c *Client) GetClient(ctx context.Context, id string) (*api.ClientInfo, error) {
	resp, err := c.dex.ListClients(ctx, &api.ListClientReq{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to list clients")
	}

	for _, client := range resp.Clients {
		if client.Id == id {
			return client, nil
		}
	}

	return nil, nil // Client not found
}

// UpdateClient updates an existing OAuth2 client in Dex.
func (c *Client) UpdateClient(ctx context.Context, id string, redirectURIs, trustedPeers []string, name, logoURL string) error {
	req := &api.UpdateClientReq{
		Id:           id,
		RedirectUris: redirectURIs,
		TrustedPeers: trustedPeers,
		Name:         name,
		LogoUrl:      logoURL,
	}

	resp, err := c.dex.UpdateClient(ctx, req)
	if err != nil {
		return errors.Wrap(err, "failed to update client")
	}

	if resp.NotFound {
		return fmt.Errorf("client with ID %q not found", id)
	}

	return nil
}

// DeleteClient deletes an OAuth2 client from Dex.
func (c *Client) DeleteClient(ctx context.Context, id string) error {
	req := &api.DeleteClientReq{
		Id: id,
	}

	resp, err := c.dex.DeleteClient(ctx, req)
	if err != nil {
		return errors.Wrap(err, "failed to delete client")
	}

	if resp.NotFound {
		return fmt.Errorf("client with ID %q not found", id)
	}

	return nil
}

// ListClients lists all OAuth2 clients in Dex.
// Note: Returns ClientInfo (without secret) for security reasons.
func (c *Client) ListClients(ctx context.Context) ([]*api.ClientInfo, error) {
	resp, err := c.dex.ListClients(ctx, &api.ListClientReq{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to list clients")
	}

	return resp.Clients, nil
}
