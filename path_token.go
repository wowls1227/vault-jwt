package keycloakjwt

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const secretTypeToken = "keycloak_jwt"

func pathToken(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "token/" + framework.GenericNameRegex("role"),
			Fields: map[string]*framework.FieldSchema{
				"role": {
					Type:        framework.TypeString,
					Description: "Name of the role to issue a token for",
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{Callback: b.tokenRead},
			},
			HelpSynopsis: "Issue a Keycloak JWT for the given role. Creates a dedicated Keycloak user per lease.",
		},
	}
}

func secretToken(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: secretTypeToken,
		Fields: map[string]*framework.FieldSchema{
			"access_token": {Type: framework.TypeString},
			"token_type":   {Type: framework.TypeString},
			"scope":        {Type: framework.TypeString},
			"expires_in":   {Type: framework.TypeInt},
			"username":     {Type: framework.TypeString},
		},
		Renew:  b.tokenRenew,
		Revoke: b.tokenRevoke,
	}
}

func (b *backend) tokenRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("role").(string)

	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return logical.ErrorResponse("backend not configured — run vault write <mount>/config"), nil
	}

	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("role %q not found", roleName)), nil
	}

	kc, err := newKeycloakClient(cfg)
	if err != nil {
		return nil, err
	}

	username := "vault-" + randomSuffix()
	password, err := randomPassword()
	if err != nil {
		return nil, fmt.Errorf("generate password: %w", err)
	}

	userID, err := kc.CreateUser(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	if err := kc.SetPassword(ctx, userID, password); err != nil {
		// Clean up on failure
		_ = kc.DeleteUser(ctx, userID)
		return nil, fmt.Errorf("set password: %w", err)
	}

	tr, err := kc.IssueToken(ctx, username, password, role.Scopes)
	if err != nil {
		_ = kc.DeleteUser(ctx, userID)
		return nil, fmt.Errorf("issue token: %w", err)
	}

	ttl, _, err := framework.CalculateTTL(b.System(), 0, role.TTL, 0, role.MaxTTL, 0, time.Time{})
	if err != nil {
		_ = kc.DeleteUser(ctx, userID)
		return nil, err
	}
	if tr.ExpiresIn > 0 {
		if kTTL := time.Duration(tr.ExpiresIn) * time.Second; kTTL < ttl || ttl == 0 {
			ttl = kTTL
		}
	}

	resp := b.Secret(secretTypeToken).Response(
		map[string]interface{}{
			"access_token": tr.AccessToken,
			"token_type":   tr.TokenType,
			"scope":        tr.Scope,
			"expires_in":   tr.ExpiresIn,
			"username":     username,
		},
		map[string]interface{}{
			"user_id":  userID,
			"username": username,
			"password": password,
			"role":     roleName,
		},
	)
	resp.Secret.TTL = ttl
	resp.Secret.MaxTTL = role.MaxTTL

	return resp, nil
}

func (b *backend) tokenRenew(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, fmt.Errorf("backend not configured")
	}

	roleName, _ := req.Secret.InternalData["role"].(string)
	role, err := getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("role %q no longer exists", roleName)
	}

	username, _ := req.Secret.InternalData["username"].(string)
	password, _ := req.Secret.InternalData["password"].(string)
	if username == "" || password == "" {
		return nil, fmt.Errorf("internal data missing username or password")
	}

	kc, err := newKeycloakClient(cfg)
	if err != nil {
		return nil, err
	}

	tr, err := kc.IssueToken(ctx, username, password, role.Scopes)
	if err != nil {
		return nil, fmt.Errorf("re-issue token on renew: %w", err)
	}

	ttl, _, err := framework.CalculateTTL(b.System(), req.Secret.Increment, role.TTL, 0, role.MaxTTL, 0, req.Secret.IssueTime)
	if err != nil {
		return nil, err
	}
	if tr.ExpiresIn > 0 {
		if kTTL := time.Duration(tr.ExpiresIn) * time.Second; kTTL < ttl || ttl == 0 {
			ttl = kTTL
		}
	}

	newSecret := *req.Secret
	newSecret.TTL = ttl

	return &logical.Response{Secret: &newSecret}, nil
}

func (b *backend) tokenRevoke(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	cfg, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if cfg == nil {
		return nil, nil
	}

	userID, _ := req.Secret.InternalData["user_id"].(string)
	if userID == "" {
		return nil, nil
	}

	kc, err := newKeycloakClient(cfg)
	if err != nil {
		return nil, err
	}

	if err := kc.DeleteUser(ctx, userID); err != nil {
		return nil, fmt.Errorf("delete user: %w", err)
	}

	return nil, nil
}

func randomSuffix() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func randomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
