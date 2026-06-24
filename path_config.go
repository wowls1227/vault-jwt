package keycloakjwt

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type keycloakConfig struct {
	BaseURL           string `json:"base_url"`
	Realm             string `json:"realm"`
	ClientID          string `json:"client_id"`
	ClientSecret      string `json:"client_secret"`
	CACert            string `json:"ca_cert"`
	AdminClientID     string `json:"admin_client_id"`
	AdminClientSecret string `json:"admin_client_secret"`
}

func (c *keycloakConfig) tokenURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", c.BaseURL, c.Realm)
}

func (c *keycloakConfig) logoutURL() string {
	return fmt.Sprintf("%s/realms/%s/protocol/openid-connect/logout", c.BaseURL, c.Realm)
}

func (c *keycloakConfig) adminUsersURL() string {
	return fmt.Sprintf("%s/admin/realms/%s/users", c.BaseURL, c.Realm)
}

func (c *keycloakConfig) adminUserURL(userID string) string {
	return fmt.Sprintf("%s/admin/realms/%s/users/%s", c.BaseURL, c.Realm, userID)
}

func (c *keycloakConfig) adminUserPasswordURL(userID string) string {
	return fmt.Sprintf("%s/admin/realms/%s/users/%s/reset-password", c.BaseURL, c.Realm, userID)
}

func pathConfig(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "config",
			Fields: map[string]*framework.FieldSchema{
				"base_url": {
					Type:        framework.TypeString,
					Description: "Keycloak base URL, e.g. https://keycloak.example.com",
				},
				"realm": {
					Type:        framework.TypeString,
					Description: "Keycloak realm name",
				},
				"client_id": {
					Type:        framework.TypeString,
					Description: "OAuth2 client ID (must have Direct Access Grants enabled)",
				},
				"client_secret": {
					Type:         framework.TypeString,
					Description:  "OAuth2 client secret",
					DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
				},
				"ca_cert": {
					Type:        framework.TypeString,
					Description: "PEM-encoded CA certificate for self-signed Keycloak TLS (optional)",
				},
				"admin_client_id": {
					Type:        framework.TypeString,
					Description: "Client ID with manage-users realm role for Admin API",
				},
				"admin_client_secret": {
					Type:         framework.TypeString,
					Description:  "Client secret for admin_client_id",
					DisplayAttrs: &framework.DisplayAttributes{Sensitive: true},
				},
			},
			ExistenceCheck: b.configExists,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.configWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.configWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.configRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.configDelete},
			},
			HelpSynopsis: "Configure Keycloak connection settings.",
		},
	}
}

func (b *backend) configExists(ctx context.Context, req *logical.Request, _ *framework.FieldData) (bool, error) {
	cfg, err := getConfig(ctx, req.Storage)
	return cfg != nil, err
}

func (b *backend) configWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	cfg := &keycloakConfig{
		BaseURL:           d.Get("base_url").(string),
		Realm:             d.Get("realm").(string),
		ClientID:          d.Get("client_id").(string),
		ClientSecret:      d.Get("client_secret").(string),
		CACert:            d.Get("ca_cert").(string),
		AdminClientID:     d.Get("admin_client_id").(string),
		AdminClientSecret: d.Get("admin_client_secret").(string),
	}
	if cfg.BaseURL == "" || cfg.Realm == "" || cfg.ClientID == "" {
		return logical.ErrorResponse("base_url, realm, and client_id are required"), nil
	}
	if cfg.AdminClientID == "" || cfg.AdminClientSecret == "" {
		return logical.ErrorResponse("admin_client_id and admin_client_secret are required"), nil
	}
	entry, err := logical.StorageEntryJSON("config", cfg)
	if err != nil {
		return nil, err
	}
	return nil, req.Storage.Put(ctx, entry)
}

func (b *backend) configRead(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"base_url":        cfg.BaseURL,
			"realm":           cfg.Realm,
			"client_id":       cfg.ClientID,
			"admin_client_id": cfg.AdminClientID,
		},
	}, nil
}

func (b *backend) configDelete(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	return nil, req.Storage.Delete(ctx, "config")
}

func getConfig(ctx context.Context, s logical.Storage) (*keycloakConfig, error) {
	entry, err := s.Get(ctx, "config")
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var cfg keycloakConfig
	if err := entry.DecodeJSON(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
