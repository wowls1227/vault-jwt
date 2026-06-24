package main

import (
	"log"
	"os"

	keycloakjwt "github.com/hiros/vault-plugin-secrets-keycloak-jwt"
	"github.com/hashicorp/vault/sdk/plugin"
)

func main() {
	meta := &plugin.ServeOpts{
		BackendFactoryFunc: keycloakjwt.Factory,
	}
	if err := plugin.Serve(meta); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}
