# vault-plugin-secrets-keycloak-jwt

Vault Secret Engine 플러그인으로, Keycloak JWT 토큰을 Vault Lease와 연동하여 발급·갱신·폐기합니다.

## 동작 방식

토큰을 요청할 때마다 Keycloak에 전용 임시 유저(`vault-<random>`)를 생성하고, 해당 유저로 JWT를 발급합니다. Vault Lease가 만료되거나 revoke되면 유저를 삭제하여 토큰을 즉시 무효화합니다.

```
vault read keycloak-jwt/token/myrole
  └─ Keycloak 유저 생성: vault-Xk3mP9aQ
  └─ 랜덤 패스워드 설정
  └─ password grant로 JWT 발급
  └─ Lease에 user_id, username, password 저장

vault lease renew <lease_id>
  └─ 기존 유저로 JWT 재발급 (유저 유지)

vault lease revoke <lease_id>  또는  TTL 만료
  └─ Keycloak 유저 삭제 → 세션 즉시 종료
  └─ introspect: active: false
  └─ 다른 Lease의 유저는 영향 없음
```

### TTL / max_ttl

```
발급 시점 ────────────────────────────────────────▶ 시간
          │←── ttl ───│
          │←────────── max_ttl ───────────────────│

- ttl     : 기본 Lease 수명. 만료 전 renew 가능.
- max_ttl : 절대 한계. 아무리 renew해도 이 시점이 되면 자동 만료 및 유저 삭제.
```

---

## 파일 구조

```
.
├── backend.go          # 플러그인 진입점 (Factory, 경로/Secret 등록)
├── path_config.go      # Keycloak 서버 연결 설정 (CRUD)
├── path_roles.go       # Role 관리 (scopes, ttl, max_ttl)
├── path_token.go       # 토큰 발급 / 갱신 / 폐기 로직
├── keycloak_client.go  # Keycloak Admin API & Token API HTTP 클라이언트
├── backend_test.go     # 유닛 테스트 (fake Keycloak 서버 사용)
└── cmd/
    └── vault-plugin-secrets-keycloak-jwt/
        └── main.go     # 플러그인 바이너리 진입점
```

---

## 코드 설명

### `backend.go`

Vault SDK의 `framework.Backend`를 초기화합니다. 세 가지 경로(`config`, `roles`, `token`)와 Dynamic Secret 타입(`keycloak_jwt`)을 등록합니다.

```go
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error)
```

---

### `path_config.go`

Keycloak 연결 정보를 Vault Storage에 저장합니다.

| 필드 | 설명 |
|---|---|
| `base_url` | Keycloak 주소 (예: `http://keycloak:8080`) |
| `realm` | Keycloak Realm 이름 |
| `client_id` | Direct Access Grants가 활성화된 Client ID |
| `client_secret` | Client Secret |
| `ca_cert` | 자체 서명 TLS 인증서 (선택) |
| `admin_client_id` | `manage-users` 권한을 가진 Admin Client ID |
| `admin_client_secret` | Admin Client Secret |

```bash
vault write keycloak-jwt/config \
  base_url=http://keycloak:8080 \
  realm=myrealm \
  client_id=vault-client \
  client_secret=<secret> \
  admin_client_id=vault-admin \
  admin_client_secret=<admin-secret>
```

---

### `path_roles.go`

토큰 발급 정책을 정의하는 Role을 관리합니다.

| 필드 | 설명 |
|---|---|
| `scopes` | 요청할 OAuth2 스코프 (공백 구분) |
| `ttl` | 기본 Lease 수명 |
| `max_ttl` | 최대 Lease 수명 |

```bash
vault write keycloak-jwt/roles/myrole \
  scopes="openid profile" \
  ttl=5m \
  max_ttl=1h

vault read  keycloak-jwt/roles/myrole
vault list  keycloak-jwt/roles/
vault delete keycloak-jwt/roles/myrole
```

---

### `path_token.go`

Dynamic Secret의 핵심 로직입니다.

#### `tokenRead` — 토큰 발급

1. `vault-<random>` 유저 생성 (Keycloak Admin API)
2. 랜덤 패스워드 설정 및 Required Actions 초기화
3. Password Grant로 JWT 발급
4. Vault Lease TTL = `min(role.ttl, keycloak expires_in)`
5. Lease Internal Data에 `user_id`, `username`, `password` 저장

반환 데이터:
```json
{
  "access_token": "eyJ...",
  "token_type":   "Bearer",
  "scope":        "openid profile",
  "expires_in":   3600,
  "username":     "vault-Xk3mP9aQ"
}
```

#### `tokenRenew` — 갱신

기존 유저(`username` + `password`)로 JWT를 재발급합니다. 새 유저를 만들지 않습니다. `max_ttl` 초과 시 Vault가 자동으로 revoke를 호출합니다.

#### `tokenRevoke` — 폐기

Lease Internal Data의 `user_id`로 Keycloak 유저를 삭제합니다. 유저 삭제 즉시 해당 유저의 모든 세션이 종료되어 access_token이 무효화됩니다.

---

### `keycloak_client.go`

Keycloak과 통신하는 HTTP 클라이언트입니다.

| 메서드 | 엔드포인트 | 설명 |
|---|---|---|
| `CreateUser` | `POST /admin/realms/{realm}/users` | 임시 유저 생성, Location 헤더에서 user_id 추출 |
| `SetPassword` | `PUT /admin/realms/{realm}/users/{id}/reset-password` | 패스워드 설정 |
| `clearRequiredActions` | `PUT /admin/realms/{realm}/users/{id}` | Required Actions 초기화 |
| `DeleteUser` | `DELETE /admin/realms/{realm}/users/{id}` | 유저 삭제 및 세션 종료 |
| `IssueToken` | `POST /realms/{realm}/protocol/openid-connect/token` | Password Grant로 JWT 발급 |
| `getAdminToken` | `POST /realms/{realm}/protocol/openid-connect/token` | Admin용 Client Credentials 토큰 발급 |

---

## 빌드 및 설치

```bash
# 테스트
make test

# macOS 빌드 및 dev 서버 실행
make dev-server   # 터미널 1

# 플러그인 등록
make register     # 터미널 2

# 리눅스 바이너리 크로스컴파일
make build-linux
# → vault-plugin-secrets-keycloak-jwt-linux-amd64
# → vault-plugin-secrets-keycloak-jwt-linux-arm64
```

### 리눅스 서버 등록

```bash
scp vault-plugin-secrets-keycloak-jwt-linux-amd64 user@server:/etc/vault/plugins/vault-plugin-secrets-keycloak-jwt
chmod +x /etc/vault/plugins/vault-plugin-secrets-keycloak-jwt

SHA=$(sha256sum /etc/vault/plugins/vault-plugin-secrets-keycloak-jwt | awk '{print $1}')
vault plugin register -sha256="$SHA" secret vault-plugin-secrets-keycloak-jwt
vault secrets enable -path=keycloak-jwt vault-plugin-secrets-keycloak-jwt
```

Vault 서버 설정(`/etc/vault/config.hcl`)에 반드시 `plugin_directory`가 지정돼 있어야 합니다:

```hcl
plugin_directory = "/etc/vault/plugins"
```

---

## Keycloak 사전 설정

### vault-client (토큰 발급용)

- **Client authentication**: ON
- **Direct access grants**: ON

### vault-admin (Admin API용)

- **Client authentication**: ON
- **Service accounts roles** → `realm-management` → `manage-users` 역할 추가

---

## 검증

### 1. 유저 생성 및 토큰 발급 확인

```bash
vault read -format=json keycloak-jwt/token/myrole > /tmp/t.json

# vault- prefix 유저명과 lease 정보 확인
cat /tmp/t.json | jq '{username: .data.username, lease_id, lease_duration}'

# Keycloak Admin API로 유저 존재 확인
ADMIN_TOKEN=$(curl -s \
  -d "client_id=vault-admin&client_secret=<admin-secret>&grant_type=client_credentials" \
  http://keycloak:8080/realms/myrealm/protocol/openid-connect/token | jq -r '.access_token')

USERNAME=$(cat /tmp/t.json | jq -r '.data.username')
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://keycloak:8080/admin/realms/myrealm/users?username=$USERNAME" | jq '.[0].username'
# 기대값: "vault-xxxxxxxx"
```

---

### 2. TTL 만료 확인

```bash
# TTL 짧게 설정
vault write keycloak-jwt/roles/test-ttl scopes="openid" ttl=15s max_ttl=1m

vault read -format=json keycloak-jwt/token/test-ttl > /tmp/ttl.json
LEASE_ID=$(cat /tmp/ttl.json | jq -r '.lease_id')

# 15초 대기
sleep 16

# lease 만료 확인
vault lease lookup $LEASE_ID
# 기대값: Error — lease not found

# Keycloak 유저도 삭제됐는지 확인
USERNAME=$(cat /tmp/ttl.json | jq -r '.data.username')
curl -s -H "Authorization: Bearer $ADMIN_TOKEN" \
  "http://keycloak:8080/admin/realms/myrealm/users?username=$USERNAME" | jq 'length'
# 기대값: 0
```

---

### 3. Lease 독립성 확인 (lease별 세션 분리)

```bash
# lease 두 개 발급
vault read -format=json keycloak-jwt/token/myrole > /tmp/a.json
vault read -format=json keycloak-jwt/token/myrole > /tmp/b.json

TOKEN_A=$(cat /tmp/a.json | jq -r '.data.access_token')
TOKEN_B=$(cat /tmp/b.json | jq -r '.data.access_token')

# 둘 다 active: true 확인
curl -s -u "vault-client:<secret>" -d "token=$TOKEN_A" \
  http://keycloak:8080/realms/myrealm/protocol/openid-connect/token/introspect | jq .active
curl -s -u "vault-client:<secret>" -d "token=$TOKEN_B" \
  http://keycloak:8080/realms/myrealm/protocol/openid-connect/token/introspect | jq .active

# lease-A만 revoke
vault lease revoke $(cat /tmp/a.json | jq -r '.lease_id')

# TOKEN_A → active: false, TOKEN_B → active: true (영향 없음)
curl -s -u "vault-client:<secret>" -d "token=$TOKEN_A" \
  http://keycloak:8080/realms/myrealm/protocol/openid-connect/token/introspect | jq .active
curl -s -u "vault-client:<secret>" -d "token=$TOKEN_B" \
  http://keycloak:8080/realms/myrealm/protocol/openid-connect/token/introspect | jq .active
```

---

### 4. Lease 갱신 (renew) 확인

```bash
vault read -format=json keycloak-jwt/token/myrole > /tmp/r.json
LEASE_ID=$(cat /tmp/r.json | jq -r '.lease_id')

# 갱신 전 만료 시각
vault lease lookup $LEASE_ID | grep expire_time

# 갱신
vault lease renew $LEASE_ID

# 갱신 후 만료 시각 (늘어났는지 확인)
vault lease lookup $LEASE_ID | grep expire_time

# max_ttl 초과 시 갱신 불가 (Error 반환)
```

---

### 5. 전체 lease 목록 확인

```bash
vault list sys/leases/lookup/keycloak-jwt/token/myrole/
```
# vault-jwt
