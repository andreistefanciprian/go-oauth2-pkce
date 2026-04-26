# oauth_play

A learning project for building OAuth 2.1 with PKCE from scratch in Go, built interactively with [Claude AI](https://claude.ai).

## Services

| Service | Port | Package | Responsibility |
|---|---|---|---|
| Frontend | `:9000` | `cmd/frontend` | Initiates login, handles callback, calls API server |
| Auth server | `:8080` | `cmd/authserver` | Issues auth codes and JWT tokens |
| API server | `:8081` | `cmd/api` | Serves protected data, validates JWTs |

The frontend is the only service the user interacts with directly.
The API server never sees auth codes or PKCE params, only Bearer tokens.

## OAuth 2.1 + PKCE Flow

```
Frontend (:9000)          Auth Server (:8080)         API (:8081)
      |                             |                            |
      | GET /login                  |                            |
      | GenerateCodeVerifier()      |                            |
      | GenerateCodeChallenge()     |                            |
      | GenerateState()             |                            |
      | store {state → verifier}    |                            |
      |   (session store)           |                            |
1.    |-- GET /authorize ---------->|                            |
      |   ?code_challenge=<hash>    | store: {                   |
      |   &code_challenge_method=S256   code → auth_code,        |
      |   &client_id=...            |   challenge,               |
      |   &redirect_uri=...         |   client_id,               |
      |   &state=<random>           |   redirect_uri,            |
      |                             |   expiry                   |
      |                             | }                          |
      |                             | (state NOT stored —        |
      |                             |  just echoed back)         |
      |                             |                            |
2.    |<-- redirect to /callback ---|                            |
      |    ?code=<auth_code>        |                            |
      |    &state=<random>          |                            |
      | GET /callback               |                            |
      | verify state matches  ✓     |                            |
      | retrieve verifier from store|                            |
      |                             |                            |
3.    |-- POST /token ------------->|                            |
      |   grant_type=               | Consume(code):             |
      |     authorization_code      |   delete code (single-use) |
      |   code=<auth_code>          |   VerifyCodeChallenge()    |
      |   code_verifier=<verifier>  |   verify redirect_uri      |
      |   redirect_uri=...          |   verify client_id         |
      |   client_id=...             |                            |
      |                             |                            |
4.    |<-- { access_token,          |                            |
      |       refresh_token }       |                            |
      |                             |                            |
5.    |-- GET /profile ---------------------------------->       |
      |   Authorization: Bearer <access_token>                   |
      |                             |   BearerAuth middleware:   |
      |                             |   ValidateAccessToken()    |
      |<-- 200 OK + claims ---------------------------           |
```

## Token Refresh Flow

The access token is short-lived (~15 min). When it expires, the client silently fetches a new one
using the refresh token — the user never has to log in again.

```
Frontend (:9000)                  Auth Server                Resource Server
      |                                    |                            |
1.    |-- GET /resource ---------------------------------->             |
      |   Authorization: Bearer <expired_access_token>                  |
      |<-- 401 Unauthorized ----------------------------------------   |
      |                                    |                            |
2.    |-- POST /token -------------------->|                            |
      |   grant_type=refresh_token         | look up refresh token      |
      |   refresh_token=<stored_token>     | verify not expired/revoked |
      |   client_id=...                    | issue new access token     |
      |                                    |                            |
3.    |<-- { new access_token }            |                            |
      |   (optionally: new refresh_token)  |                            |
      |                                    |                            |
4.    |-- GET /resource ---------------------------------->             |
      |   Authorization: Bearer <new_access_token>                      |
      |<-- 200 OK ----------------------------------------             |
```

Note: the refresh token grant (`grant_type=refresh_token`) is a separate branch in `/token` —
no PKCE involved, just the opaque refresh token the client stored from the first login response.

## Key Distinctions

**access token vs refresh token** — two tokens, two jobs:

| | Access Token | Refresh Token |
|---|---|---|
| Format | JWT (self-contained) | Opaque random string |
| Lifetime | Short (~15 min) | Long (days/weeks) |
| Sent to | Every API request | Only `/token` endpoint |
| Stored server-side? | No | Yes |
| Revocable? | No — expires naturally | Yes — delete from store |
| If stolen | Valid until expiry | Can be revoked immediately |

Access tokens are JWTs so the API server can verify them locally without calling the auth
server. The downside is they can't be revoked — that's why they're kept short-lived.
Refresh tokens are opaque and server-side, so logout works by simply deleting the store entry.

---

**TokenIssuer vs TokenValidator** — two types, strict separation of concerns:

| | `TokenIssuer` | `TokenValidator` |
|---|---|---|
| Used by | Auth server | API server |
| Can issue tokens? | Yes | No |
| Can verify tokens? | No | Yes |
| Used at runtime? | Yes (`/token` handler) | Yes (`BearerAuth` middleware) |
| Used in tests? | Yes (mint tokens) | Yes (assert tokens are valid) |

The auth server never calls `ValidateAccessToken` at runtime — it only issues.
The API server never calls `IssueAccessToken` — it only verifies.
This mirrors production reality: with RS256, the API server would hold only the
public key and couldn't issue tokens even if compromised.

---

**state vs code_verifier** — both are random strings but serve different purposes:

| | `code_verifier` | `state` |
|---|---|---|
| Protects against | Auth code interception | CSRF attacks |
| Validated by | Auth server (via `VerifyCodeChallenge`) | Client (compared to session) |
| How | Transformed into challenge via SHA256 | Sent raw, echoed back unchanged |
| Auth server stores it? | Yes (as the challenge) | No — just passes it through |

The auth server never validates `state` — it has no idea what it means. Only your app does.

## Running & Testing

**1. Start the servers** (two terminals):

```bash
go run ./cmd/authserver      # listens on :8080
go run ./cmd/api  # listens on :8081
```

**2. Generate curl commands with real PKCE values:**

```bash
go run ./cmd/frontend
```

This prints the three curl commands with a real verifier, challenge, and state pre-filled.

**3. Get an auth code** (copy the printed Step 1 curl and run it):

```bash
curl -v "http://localhost:8080/authorize?client_id=myapp&redirect_uri=http://localhost:9000/callback&code_challenge=<challenge>&code_challenge_method=S256&state=<state>"
```

Copy the `code` value from the `Location` header in the response.

**4. Exchange the code for tokens** — use `jq` to extract just the access token:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/token \
  -d "grant_type=authorization_code" \
  -d "code=<PASTE_CODE_HERE>" \
  -d "code_verifier=<PASTE_VERIFIER_FROM_CLIENT_OUTPUT>" \
  -d "redirect_uri=http://localhost:9000/callback" \
  -d "client_id=myapp" | jq -r .access_token)
```

**5. Call the protected resource:**

```bash
curl -v http://localhost:8081/profile \
  -H "Authorization: Bearer $TOKEN"
```

Expected response:
```json
{
  "message": "Successfully authorized with JWT — resource is available",
  "claims": {
    "client_id": "myapp",
    "exp": 1234567890,
    "iat": 1234567890,
    "iss": "oauth_play",
    "sub": "myapp"
  }
}
```

**Run unit tests:**

```bash
go test ./...
```

## Building Blocks

- [x] `GenerateCodeVerifier()` — 32-byte random URL-safe string (RFC 7636)
- [x] `GenerateCodeChallenge(verifier)` — BASE64URL(SHA256(verifier))
- [x] `VerifyCodeChallenge(verifier, challenge)` — validates verifier against stored challenge
- [x] `GenerateState()` — CSRF protection on the `/authorize` redirect
- [x] Auth code generator — random opaque token, short-lived
- [x] Auth code store — `map[code]→{challenge, client_id, redirect_uri, expiry}`
- [x] `/authorize` handler — validates client, issues auth code, redirects with `?code=&state=`
- [x] `/token` handler — calls `VerifyCodeChallenge`, exchanges code for JWT
- [x] JWT issuance — access token (short-lived ~15min) + refresh token
- [x] Token store — refresh tokens and revocation
- [x] Bearer middleware — API server validates access token
- [ ] `GET /login` — generates PKCE params, stores `{state → verifier}` in session, redirects to auth server
- [ ] `GET /callback` — validates state (CSRF check), retrieves verifier, calls `/token`, calls `/profile`, displays result
- [ ] Session store — `map[state]→{verifier}` (in prod: Redis/DB)
