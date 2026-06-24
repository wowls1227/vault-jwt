package keycloakjwt

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/logical"
)

type fakeKeycloak struct {
	users        map[string]string // userID → username
	deletedUsers []string
	issuedCount  int
}

func newFakeKeycloak(t *testing.T) (*httptest.Server, *fakeKeycloak) {
	t.Helper()
	fk := &fakeKeycloak{users: map[string]string{}}
	userCounter := 0

	mux := http.NewServeMux()

	// Admin: create user
	mux.HandleFunc("/admin/realms/test/users", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var body map[string]interface{}
		json.NewDecoder(r.Body).Decode(&body)
		username, _ := body["username"].(string)
		userCounter++
		userID := fmt.Sprintf("user-%d", userCounter)
		fk.users[userID] = username
		w.Header().Set("Location", "/admin/realms/test/users/"+userID)
		w.WriteHeader(http.StatusCreated)
	})

	// Admin: update user / set password / delete user
	mux.HandleFunc("/admin/realms/test/users/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(r.URL.Path, "/")
		userID := parts[len(parts)-1]

		if strings.HasSuffix(r.URL.Path, "/reset-password") {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		switch r.Method {
		case http.MethodPut: // clearRequiredActions
			w.WriteHeader(http.StatusNoContent)
		case http.MethodDelete:
			fk.deletedUsers = append(fk.deletedUsers, userID)
			delete(fk.users, userID)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	})

	// Admin: token (client_credentials for admin)
	// Token: password grant for vault users
	mux.HandleFunc("/realms/test/protocol/openid-connect/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		fk.issuedCount++
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResponse{
			AccessToken:      "access-token-" + fmt.Sprintf("%d", fk.issuedCount),
			ExpiresIn:        3600,
			RefreshToken:     "refresh-token",
			RefreshExpiresIn: 7200,
			TokenType:        "Bearer",
			Scope:            "openid",
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, fk
}


func testBackend(t *testing.T) (logical.Backend, logical.Storage) {
	t.Helper()
	storage := &logical.InmemStorage{}
	config := &logical.BackendConfig{
		StorageView: storage,
		System:      logical.TestSystemView(),
		Logger:      hclog.NewNullLogger(),
	}
	b, err := Factory(context.Background(), config)
	if err != nil {
		t.Fatalf("factory: %v", err)
	}
	return b, storage
}

func writeConfig(t *testing.T, b logical.Backend, s logical.Storage, baseURL string) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Storage:   s,
		Data: map[string]interface{}{
			"base_url":            baseURL,
			"realm":               "test",
			"client_id":           "vault-client",
			"client_secret":       "supersecret",
			"admin_client_id":     "vault-admin",
			"admin_client_secret": "adminsecret",
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("config write: err=%v resp=%v", err, resp)
	}
}

func writeRole(t *testing.T, b logical.Backend, s logical.Storage, name string, ttl time.Duration) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + name,
		Storage:   s,
		Data: map[string]interface{}{
			"scopes": "openid",
			"ttl":    int(ttl.Seconds()),
		},
	})
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("role write: err=%v resp=%v", err, resp)
	}
}

func TestTokenIssue(t *testing.T) {
	srv, fk := newFakeKeycloak(t)
	b, s := testBackend(t)
	writeConfig(t, b, s, srv.URL)
	writeRole(t, b, s, "myrole", 5*time.Minute)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/myrole",
		Storage:   s,
	})
	if err != nil || resp.IsError() {
		t.Fatalf("token read: err=%v resp=%v", err, resp)
	}

	// 유저가 생성됐는지 확인
	if len(fk.users) != 1 {
		t.Errorf("expected 1 user created, got %d", len(fk.users))
	}
	// username이 vault- prefix인지 확인
	for _, username := range fk.users {
		if !strings.HasPrefix(username, "vault-") {
			t.Errorf("expected username to start with vault-, got %s", username)
		}
	}
	// refresh_token 미노출 확인
	if _, ok := resp.Data["refresh_token"]; ok {
		t.Error("refresh_token must not be exposed in response data")
	}
	// username 노출 확인
	if resp.Data["username"] == "" {
		t.Error("expected username in response data")
	}
}

func TestTokenRevoke(t *testing.T) {
	srv, fk := newFakeKeycloak(t)
	b, s := testBackend(t)
	writeConfig(t, b, s, srv.URL)
	writeRole(t, b, s, "r", 5*time.Minute)

	issueResp, _ := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/r",
		Storage:   s,
	})

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Secret:    issueResp.Secret,
		Storage:   s,
	}); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// 유저가 삭제됐는지 확인
	if len(fk.deletedUsers) == 0 {
		t.Error("expected Keycloak user to be deleted on revoke")
	}
	if len(fk.users) != 0 {
		t.Error("expected no remaining users after revoke")
	}
}

func TestTokenRevoke_Independent(t *testing.T) {
	srv, fk := newFakeKeycloak(t)
	b, s := testBackend(t)
	writeConfig(t, b, s, srv.URL)
	writeRole(t, b, s, "r", 5*time.Minute)

	resp1, _ := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/r",
		Storage:   s,
	})
	resp2, _ := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/r",
		Storage:   s,
	})

	// lease-1만 revoke
	b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RevokeOperation,
		Secret:    resp1.Secret,
		Storage:   s,
	})

	// lease-2의 유저는 살아있어야 함
	if len(fk.users) != 1 {
		t.Errorf("expected 1 remaining user after revoking one lease, got %d", len(fk.users))
	}
	remainingUser := fk.users[resp2.Secret.InternalData["user_id"].(string)]
	if remainingUser == "" {
		t.Error("lease-2 user should still exist")
	}
}

func TestTokenRenew(t *testing.T) {
	srv, fk := newFakeKeycloak(t)
	b, s := testBackend(t)
	writeConfig(t, b, s, srv.URL)
	writeRole(t, b, s, "r", 5*time.Minute)

	issueResp, _ := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/r",
		Storage:   s,
	})
	userCountBefore := len(fk.users)

	if _, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RenewOperation,
		Secret:    issueResp.Secret,
		Storage:   s,
	}); err != nil {
		t.Fatalf("renew: %v", err)
	}

	// renew 시 새 유저가 생성되면 안 됨
	if len(fk.users) != userCountBefore {
		t.Error("renew must not create a new user")
	}
}

func TestMissingConfig(t *testing.T) {
	b, s := testBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/any-role",
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Error("expected error response when config is missing")
	}
}

func TestRoleNotFound(t *testing.T) {
	srv, _ := newFakeKeycloak(t)
	b, s := testBackend(t)
	writeConfig(t, b, s, srv.URL)

	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "token/nonexistent",
		Storage:   s,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !resp.IsError() {
		t.Error("expected error for unknown role")
	}
}
