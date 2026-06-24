package keycloakjwt

import (
	"context"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	backendHelp = `
The Keycloak JWT secrets engine issues and manages Keycloak JWT tokens.
Tokens are tied to Vault leases — when a lease expires or is revoked,
the corresponding Keycloak token is revoked as well.
`
)

type backend struct {
	*framework.Backend
}

func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := &backend{}
	b.Backend = &framework.Backend{
		Help:        strings.TrimSpace(backendHelp),
		BackendType: logical.TypeLogical,
		Paths: framework.PathAppend(
			pathConfig(b),
			pathRoles(b),
			pathToken(b),
		),
		Secrets: []*framework.Secret{
			secretToken(b),
		},
	}
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}
