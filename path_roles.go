package keycloakjwt

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

type roleEntry struct {
	Scopes string        `json:"scopes"`
	TTL    time.Duration `json:"ttl"`
	MaxTTL time.Duration `json:"max_ttl"`
}

func pathRoles(b *backend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/" + framework.GenericNameRegex("name"),
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
				},
				"scopes": {
					Type:        framework.TypeString,
					Description: "Space-separated OAuth2 scopes to request",
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease TTL",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum lease TTL",
				},
			},
			ExistenceCheck: b.roleExists,
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.CreateOperation: &framework.PathOperation{Callback: b.roleWrite},
				logical.UpdateOperation: &framework.PathOperation{Callback: b.roleWrite},
				logical.ReadOperation:   &framework.PathOperation{Callback: b.roleRead},
				logical.DeleteOperation: &framework.PathOperation{Callback: b.roleDelete},
				logical.ListOperation:   &framework.PathOperation{Callback: b.roleList},
			},
			HelpSynopsis: "Manage roles for Keycloak JWT issuance.",
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{Callback: b.roleList},
			},
			HelpSynopsis: "List existing roles.",
		},
	}
}

func (b *backend) roleWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role := &roleEntry{
		Scopes: d.Get("scopes").(string),
		TTL:    time.Duration(d.Get("ttl").(int)) * time.Second,
		MaxTTL: time.Duration(d.Get("max_ttl").(int)) * time.Second,
	}
	entry, err := logical.StorageEntryJSON("roles/"+name, role)
	if err != nil {
		return nil, err
	}
	return nil, req.Storage.Put(ctx, entry)
}

func (b *backend) roleRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	role, err := getRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, nil
	}
	return &logical.Response{
		Data: map[string]interface{}{
			"scopes":  role.Scopes,
			"ttl":     role.TTL.Seconds(),
			"max_ttl": role.MaxTTL.Seconds(),
		},
	}, nil
}

func (b *backend) roleDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	return nil, req.Storage.Delete(ctx, "roles/"+name)
}

func (b *backend) roleList(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	keys, err := req.Storage.List(ctx, "roles/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(keys), nil
}

func (b *backend) roleExists(ctx context.Context, req *logical.Request, d *framework.FieldData) (bool, error) {
	name := d.Get("name").(string)
	role, err := getRole(ctx, req.Storage, name)
	return role != nil, err
}

func getRole(ctx context.Context, s logical.Storage, name string) (*roleEntry, error) {
	entry, err := s.Get(ctx, "roles/"+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}
	var role roleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, fmt.Errorf("error decoding role %q: %w", name, err)
	}
	return &role, nil
}
