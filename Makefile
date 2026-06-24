BINARY     = vault-plugin-secrets-keycloak-jwt
CMD        = ./cmd/$(BINARY)
PLUGIN_DIR ?= $(abspath ./tmp/vault-plugins)

VAULT_ADDR  ?= http://127.0.0.1:8300
VAULT_TOKEN ?= root

export VAULT_ADDR
export VAULT_TOKEN

.PHONY: build test install dev-server register build-linux

build:
	go build -o $(BINARY) $(CMD)

build-linux:
	GOOS=linux GOARCH=amd64 go build -o $(BINARY)-linux-amd64 $(CMD)
	GOOS=linux GOARCH=arm64 go build -o $(BINARY)-linux-arm64 $(CMD)

test:
	go test ./... -v

install: build
	mkdir -p $(PLUGIN_DIR)
	cp $(BINARY) $(PLUGIN_DIR)/$(BINARY)
	xattr -d com.apple.quarantine $(PLUGIN_DIR)/$(BINARY) 2>/dev/null || true

# Start a dev Vault server with plugin_directory pre-configured.
# Run this in a separate terminal, then use 'make register' in another.
dev-server: install
	vault server \
	  -dev \
	  -dev-root-token-id="$(VAULT_TOKEN)" \
	  -dev-plugin-dir="$(PLUGIN_DIR)" \
	  -dev-listen-address="127.0.0.1:8300"

# Register and mount the plugin (requires dev-server to be running)
register:
	$(eval SHA := $(shell shasum -a 256 $(PLUGIN_DIR)/$(BINARY) | awk '{print $$1}'))
	vault plugin register \
	  -sha256="$(SHA)" \
	  secret $(BINARY)
	vault secrets enable -path=keycloak-jwt $(BINARY)
	@echo ""
	@echo "Plugin mounted at: keycloak-jwt/"
	@echo "Next step:"
	@echo "  vault write keycloak-jwt/config base_url=https://... realm=... client_id=... client_secret=..."
