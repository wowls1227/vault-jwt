package keycloakjwt

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type tokenResponse struct {
	AccessToken      string `json:"access_token"`
	ExpiresIn        int    `json:"expires_in"`
	RefreshToken     string `json:"refresh_token"`
	RefreshExpiresIn int    `json:"refresh_expires_in"`
	TokenType        string `json:"token_type"`
	Scope            string `json:"scope"`
}

type keycloakClient struct {
	cfg  *keycloakConfig
	http *http.Client
}

func newKeycloakClient(cfg *keycloakConfig) (*keycloakClient, error) {
	var transport http.RoundTripper = http.DefaultTransport

	if cfg.CACert != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(cfg.CACert)) {
			return nil, fmt.Errorf("failed to parse ca_cert")
		}
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = &tls.Config{RootCAs: pool}
		transport = t
	}

	return &keycloakClient{
		cfg:  cfg,
		http: &http.Client{Transport: transport, Timeout: 30 * time.Second},
	}, nil
}

// CreateUser creates a new Keycloak user and returns the user ID.
func (c *keycloakClient) CreateUser(ctx context.Context, username string) (string, error) {
	adminToken, err := c.getAdminToken(ctx)
	if err != nil {
		return "", err
	}

	body, _ := json.Marshal(map[string]interface{}{
		"username":        username,
		"enabled":         true,
		"email":           username + "@vault.internal",
		"firstName":       "vault",
		"lastName":        username,
		"requiredActions": []string{},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.adminUsersURL(), bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("create user request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated {
		b, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("create user returned %d: %s", resp.StatusCode, b)
	}

	// Keycloak returns the user URL in the Location header: .../users/{id}
	location := resp.Header.Get("Location")
	parts := strings.Split(location, "/")
	if len(parts) == 0 {
		return "", fmt.Errorf("no Location header in create user response")
	}
	return parts[len(parts)-1], nil
}

// SetPassword sets the password and clears any required actions for a Keycloak user.
func (c *keycloakClient) SetPassword(ctx context.Context, userID, password string) error {
	adminToken, err := c.getAdminToken(ctx)
	if err != nil {
		return err
	}

	// Clear required actions so the account is fully usable immediately.
	if err := c.clearRequiredActions(ctx, adminToken, userID); err != nil {
		return err
	}

	body, _ := json.Marshal(map[string]interface{}{
		"type":      "password",
		"value":     password,
		"temporary": false,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.cfg.adminUserPasswordURL(userID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("set password request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("set password returned %d: %s", resp.StatusCode, b)
	}
	return nil
}

func (c *keycloakClient) clearRequiredActions(ctx context.Context, adminToken, userID string) error {
	body, _ := json.Marshal(map[string]interface{}{
		"requiredActions": []string{},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, c.cfg.adminUserURL(userID), bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("clear required actions request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("clear required actions returned %d: %s", resp.StatusCode, b)
	}
	return nil
}

// DeleteUser deletes a Keycloak user, which immediately terminates all their sessions.
func (c *keycloakClient) DeleteUser(ctx context.Context, userID string) error {
	adminToken, err := c.getAdminToken(ctx)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, c.cfg.adminUserURL(userID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+adminToken)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("delete user request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusNoContent {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("delete user returned %d: %s", resp.StatusCode, b)
	}
	return nil
}

// IssueToken issues a JWT for a user via password grant.
func (c *keycloakClient) IssueToken(ctx context.Context, username, password, scopes string) (*tokenResponse, error) {
	params := url.Values{
		"client_id":     {c.cfg.ClientID},
		"client_secret": {c.cfg.ClientSecret},
		"grant_type":    {"password"},
		"username":      {username},
		"password":      {password},
	}
	if scopes != "" {
		params.Set("scope", scopes)
	}
	return c.doTokenRequest(ctx, params)
}

func (c *keycloakClient) getAdminToken(ctx context.Context) (string, error) {
	params := url.Values{
		"client_id":     {c.cfg.AdminClientID},
		"client_secret": {c.cfg.AdminClientSecret},
		"grant_type":    {"client_credentials"},
	}
	tr, err := c.doTokenRequest(ctx, params)
	if err != nil {
		return "", fmt.Errorf("get admin token: %w", err)
	}
	return tr.AccessToken, nil
}

func (c *keycloakClient) doTokenRequest(ctx context.Context, params url.Values) (*tokenResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.tokenURL(),
		strings.NewReader(params.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("keycloak token request: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("keycloak returned %d: %s", resp.StatusCode, body)
	}

	var tr tokenResponse
	if err := json.Unmarshal(body, &tr); err != nil {
		return nil, fmt.Errorf("decode token response: %w", err)
	}
	return &tr, nil
}
