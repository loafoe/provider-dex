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

package dex

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/dexidp/dex/api/v2"
	"github.com/pkg/errors"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/resolver"
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

// cacheKey returns a unique key for caching the client connection.
// It includes the endpoint and a hash of the TLS configuration to ensure
// different TLS configs for the same endpoint get separate connections.
func (c Config) cacheKey() string {
	h := sha256.New()
	h.Write([]byte(c.Endpoint))
	h.Write(c.CACert)
	h.Write(c.ClientCert)
	h.Write(c.ClientKey)
	if c.InsecureSkipVerify {
		h.Write([]byte("insecure"))
	}
	return c.Endpoint + "-" + hex.EncodeToString(h.Sum(nil))[:16]
}

// Client wraps the Dex gRPC client.
type Client struct {
	conn *grpc.ClientConn
	dex  api.DexClient
}

// clientCache provides connection reuse across reconciliation loops.
// This avoids repeated DNS lookups and connection establishment overhead.
type clientCache struct {
	mu      sync.RWMutex
	clients map[string]*Client // keyed by endpoint
}

var (
	cache     = &clientCache{clients: make(map[string]*Client)}
	cacheOnce sync.Once
)

func getCache() *clientCache {
	cacheOnce.Do(func() {
		cache = &clientCache{clients: make(map[string]*Client)}
	})
	return cache
}

func (c *clientCache) get(endpoint string) (*Client, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	client, ok := c.clients[endpoint]
	return client, ok
}

func (c *clientCache) set(endpoint string, client *Client) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.clients[endpoint] = client
}

// defaultServiceConfig defines retry and load balancing policy for the gRPC client.
// This helps handle transient DNS resolution failures and connection issues.
const defaultServiceConfig = `{
	"loadBalancingConfig": [{"round_robin": {}}],
	"methodConfig": [{
		"name": [{"service": ""}],
		"waitForReady": true,
		"retryPolicy": {
			"maxAttempts": 5,
			"initialBackoff": "0.1s",
			"maxBackoff": "5s",
			"backoffMultiplier": 2.0,
			"retryableStatusCodes": ["UNAVAILABLE", "UNKNOWN"]
		}
	}]
}`

// NewClient creates a new Dex gRPC client with the given configuration.
// Connections are cached and reused across calls to avoid repeated DNS lookups.
func NewClient(cfg Config) (*Client, error) {
	// Register our custom DNS resolver with retry logic
	registerRetryingResolver()

	// Check cache first - reuse existing connection if available
	// Cache key includes TLS config hash to handle different certs for same endpoint
	cacheKey := cfg.cacheKey()
	c := getCache()
	if client, ok := c.get(cacheKey); ok {
		// Verify connection is still usable
		if client.conn.GetState() != connectivity.Shutdown {
			return client, nil
		}
		// Connection is dead, will create a new one
	}

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

	// Add default service config for retry policy and load balancing
	// Add keepalive parameters to detect and recover from dead connections
	opts = append(opts,
		grpc.WithDefaultServiceConfig(defaultServiceConfig),
		grpc.WithKeepaliveParams(keepalive.ClientParameters{
			Time:                10 * time.Second,
			Timeout:             3 * time.Second,
			PermitWithoutStream: true,
		}))

	// Ensure endpoint has proper DNS scheme for reliable resolution
	endpoint := ensureDNSScheme(cfg.Endpoint)

	conn, err := grpc.NewClient(endpoint, opts...)
	if err != nil {
		return nil, errors.Wrap(err, "failed to dial Dex gRPC server")
	}

	client := &Client{
		conn: conn,
		dex:  api.NewDexClient(conn),
	}

	// Cache the client for reuse
	c.set(cacheKey, client)

	return client, nil
}

// ensureDNSScheme adds the dnsretry:/// scheme prefix if no scheme is present.
// This uses our custom resolver with retry logic for DNS resolution failures.
func ensureDNSScheme(endpoint string) string {
	// If already has a scheme (e.g., dns:///, passthrough:///, unix:), return as-is
	if strings.Contains(endpoint, "://") {
		return endpoint
	}
	// Add dnsretry:/// scheme to use our custom resolver with retry logic
	return "dnsretry:///" + endpoint
}

// retryingResolverBuilder wraps the default DNS resolver with retry logic
// to handle transient "produced zero addresses" errors.
type retryingResolverBuilder struct {
	scheme string
}

var (
	resolverOnce     sync.Once
	resolverInstance *retryingResolverBuilder
)

// registerRetryingResolver registers the custom resolver once.
// Uses scheme "dnsretry" to avoid conflict with gRPC's built-in "dns" resolver.
func registerRetryingResolver() {
	resolverOnce.Do(func() {
		resolverInstance = &retryingResolverBuilder{scheme: "dnsretry"}
		resolver.Register(resolverInstance)
	})
}

func (b *retryingResolverBuilder) Build(target resolver.Target, cc resolver.ClientConn, opts resolver.BuildOptions) (resolver.Resolver, error) {
	host, port, err := parseTarget(target.Endpoint())
	if err != nil {
		return nil, err
	}

	r := &retryingResolver{
		host:      host,
		port:      port,
		cc:        cc,
		stopCh:    make(chan struct{}),
		reresolve: make(chan struct{}, 1),
	}

	go r.watcher()
	return r, nil
}

func (b *retryingResolverBuilder) Scheme() string {
	return b.scheme
}

type retryingResolver struct {
	host      string
	port      string
	cc        resolver.ClientConn
	stopCh    chan struct{}
	reresolve chan struct{}
}

func (r *retryingResolver) ResolveNow(resolver.ResolveNowOptions) {
	select {
	case r.reresolve <- struct{}{}:
	default:
	}
}

func (r *retryingResolver) Close() {
	close(r.stopCh)
}

func (r *retryingResolver) watcher() {
	// Initial resolution with retry
	r.resolveWithRetry()

	// Re-resolve periodically and on demand
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.resolveWithRetry()
		case <-r.reresolve:
			r.resolveWithRetry()
		}
	}
}

func (r *retryingResolver) resolveWithRetry() {
	const maxRetries = 5
	backoff := 100 * time.Millisecond

	for i := 0; i < maxRetries; i++ {
		addrs, err := r.resolve()
		if err != nil {
			// Wait before retry
			select {
			case <-r.stopCh:
				return
			case <-time.After(backoff):
				backoff *= 2
				if backoff > 5*time.Second {
					backoff = 5 * time.Second
				}
				continue
			}
		}

		if len(addrs) > 0 {
			_ = r.cc.UpdateState(resolver.State{Addresses: addrs})
			return
		}

		// Zero addresses - retry with backoff
		select {
		case <-r.stopCh:
			return
		case <-time.After(backoff):
			backoff *= 2
			if backoff > 5*time.Second {
				backoff = 5 * time.Second
			}
		}
	}

	// After all retries, report empty state (will trigger UNAVAILABLE)
	_ = r.cc.UpdateState(resolver.State{})
}

func (r *retryingResolver) resolve() ([]resolver.Address, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Use lookupWithSearchDomains which handles Kubernetes DNS search domain
	// issues more reliably than relying on the OS resolver's ndots behavior.
	addrs, err := r.lookupWithSearchDomains(ctx, r.host)
	if err != nil {
		// Check if this is a "no such host" error - might be transient with search domains
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			// Return nil to trigger retry logic - search domain iteration may succeed on retry
			return nil, nil
		}
		return nil, err
	}

	// Filter out any empty or invalid addresses
	var resolverAddrs []resolver.Address
	for _, addr := range addrs {
		if addr != "" {
			resolverAddrs = append(resolverAddrs, resolver.Address{Addr: net.JoinHostPort(addr, r.port)})
		}
	}
	return resolverAddrs, nil
}

// lookupWithSearchDomains tries to resolve the hostname, and if it fails,
// attempts resolution with common Kubernetes search domain suffixes.
// This handles cases where ndots settings cause inconsistent DNS behavior.
func (r *retryingResolver) lookupWithSearchDomains(ctx context.Context, host string) ([]string, error) {
	customResolver := &net.Resolver{PreferGo: false}

	// First try the hostname as-is
	addrs, err := customResolver.LookupHost(ctx, host)
	if err == nil && len(addrs) > 0 {
		return addrs, nil
	}

	// If hostname already has dots or ends with a dot (FQDN), don't try search domains
	if strings.Contains(host, ".") {
		return addrs, err
	}

	// Try common Kubernetes search domain patterns
	// These are derived from typical /etc/resolv.conf search entries
	searchSuffixes := []string{
		".svc.cluster.local",
		".cluster.local",
	}

	for _, suffix := range searchSuffixes {
		fqdn := host + suffix
		addrs, err = customResolver.LookupHost(ctx, fqdn)
		if err == nil && len(addrs) > 0 {
			return addrs, nil
		}
	}

	return nil, err
}

func parseTarget(endpoint string) (host, port string, err error) {
	host, port, err = net.SplitHostPort(endpoint)
	if err != nil {
		// No port specified, assume endpoint is just the host
		host = endpoint
		port = "443" // default gRPC port
		err = nil
	}
	return
}

func buildTLSConfig(cfg Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		InsecureSkipVerify: cfg.InsecureSkipVerify, //nolint:gosec // User-controlled option for dev/test environments with self-signed certs
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

// Close is a no-op for cached connections.
// Connections are managed by the client cache and reused across reconciliation loops.
// The connection will be automatically cleaned up when the process exits.
func (c *Client) Close() error {
	// Do not close cached connections - they are reused across reconciles.
	// The gRPC connection handles reconnection internally.
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

	if resp.GetAlreadyExists() {
		return nil, fmt.Errorf("client with ID %q already exists", client.GetId())
	}

	return resp.GetClient(), nil
}

// GetClient retrieves an OAuth2 client from Dex by ID.
// Note: Dex API returns ClientInfo (without secret) from ListClients.
// Returns an error if ListClients is not implemented by the storage backend.
func (c *Client) GetClient(ctx context.Context, id string) (*api.ClientInfo, error) {
	resp, err := c.dex.ListClients(ctx, &api.ListClientReq{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to list clients")
	}

	for _, client := range resp.GetClients() {
		if client.GetId() == id {
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

	if resp.GetNotFound() {
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

	if resp.GetNotFound() {
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

	return resp.GetClients(), nil
}

// GetDiscovery retrieves OIDC discovery information from Dex.
func (c *Client) GetDiscovery(ctx context.Context) (*api.DiscoveryResp, error) {
	resp, err := c.dex.GetDiscovery(ctx, &api.DiscoveryReq{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to get discovery")
	}

	return resp, nil
}

// CreateConnector creates a new connector in Dex.
func (c *Client) CreateConnector(ctx context.Context, connector *api.Connector) (*api.Connector, error) {
	req := &api.CreateConnectorReq{
		Connector: connector,
	}

	resp, err := c.dex.CreateConnector(ctx, req)
	if err != nil {
		return nil, errors.Wrap(err, "failed to create connector")
	}

	if resp.GetAlreadyExists() {
		return nil, fmt.Errorf("connector with ID %q already exists", connector.GetId())
	}

	return connector, nil
}

// GetConnector retrieves a connector from Dex by ID.
// Returns an error if ListConnectors is not implemented by the storage backend.
func (c *Client) GetConnector(ctx context.Context, id string) (*api.Connector, error) {
	resp, err := c.dex.ListConnectors(ctx, &api.ListConnectorReq{})
	if err != nil {
		return nil, errors.Wrap(err, "failed to list connectors")
	}

	for _, connector := range resp.GetConnectors() {
		if connector.GetId() == id {
			return connector, nil
		}
	}

	return nil, nil // Connector not found
}

// UpdateConnector updates an existing connector in Dex.
func (c *Client) UpdateConnector(ctx context.Context, id, newType, newName string, newConfig []byte) error {
	req := &api.UpdateConnectorReq{
		Id:        id,
		NewType:   newType,
		NewName:   newName,
		NewConfig: newConfig,
	}

	resp, err := c.dex.UpdateConnector(ctx, req)
	if err != nil {
		return errors.Wrap(err, "failed to update connector")
	}

	if resp.GetNotFound() {
		return fmt.Errorf("connector with ID %q not found", id)
	}

	return nil
}

// DeleteConnector deletes a connector from Dex.
func (c *Client) DeleteConnector(ctx context.Context, id string) error {
	req := &api.DeleteConnectorReq{
		Id: id,
	}

	resp, err := c.dex.DeleteConnector(ctx, req)
	if err != nil {
		return errors.Wrap(err, "failed to delete connector")
	}

	if resp.GetNotFound() {
		return fmt.Errorf("connector with ID %q not found", id)
	}

	return nil
}
