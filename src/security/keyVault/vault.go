package keyVault

import (
	"context"
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"

	"log"
	"os"
)

type KeyVault struct {
	c      *vault.Config
	Client *vault.Client
	Plugin vault.PluginAPIClientMeta
}

func NewKeyVault() *KeyVault {
	kv := &KeyVault{}
	kv.c = vault.DefaultConfig()
	kv.Client, _ = vault.NewClient(kv.c)
	token := os.Getenv("VAULT_DEV_TOKEN")
	kv.Client.SetToken(token)
	return kv
}

func (v *KeyVault) AddSecretKVV2(kvv2Name, secretName string, secretData map[string]interface{}) {

	_, err := v.Client.KVv2(kvv2Name).Put(context.Background(), secretName, secretData)
	if err != nil {
		log.Fatalf("unable to write secret: %v", err)
	}
}

func (v *KeyVault) ReadSecretKVV2(kvv2Name, secretName, secretKey string) (string, error) {
	s, err := v.Client.KVv2(kvv2Name).Get(context.Background(), secretName)
	return s.Data[secretKey].(string), err
}

func (v *KeyVault) Login(ctx context.Context) (*vault.Secret, error) {
	aprsid := &approle.SecretID{FromEnv: "APPROLE_SECRET_ID"}
	approleAuth, err := approle.NewAppRoleAuth("", aprsid, approle.WithWrappingToken())
	authInfo, err := v.Client.Auth().Login(ctx, approleAuth)
	if err != nil {
		return nil, fmt.Errorf("unable to login using approle auth method: %w", err)
	}
	if authInfo == nil {
		return nil, fmt.Errorf("no approle info was returned after login")
	}
	return authInfo, nil
}
