# oauth_play

A learning project for building OAuth 2.1 with PKCE from scratch in Go.

## OAuth 2.1 + PKCE Flow

```
Client (browser/app)                  Auth Server                Resource Server
      |                                    |                            |
1.    | GenerateCodeVerifier()             |                            |
      | GenerateCodeChallenge(verifier)    |                            |
      | GenerateState()                    |                            |
      | save state in session              |                            |
      |                                    |                            |
2.    |-- GET /authorize ----------------->|                            |
      |   ?code_challenge=<challenge>      | store: {                   |
      |   &code_challenge_method=S256      |   code     → auth_code,    |
      |   &client_id=...                   |   challenge,               |
      |   &redirect_uri=...                |   client_id,               |
      |   &state=<random>   (CSRF guard)   |   redirect_uri,            |
      |                                    |   expiry                   |
      |                                    | }                          |
      |                                    | (state is NOT stored —     |
      |                                    |  just echoed back)         |
      |                                    |                            |
3.    |<-- redirect to redirect_uri -------|                            |
      |    ?code=<auth_code>               |                            |
      |    &state=<random>                 |                            |
      | verify state matches session  ✓    |                            |
      |                                    |                            |
4.    |-- POST /token -------------------->|                            |
      |   grant_type=authorization_code    | Consume(code):             |
      |   code=<auth_code>                 |   delete code (single-use) |
      |   code_verifier=<verifier>         |   VerifyCodeChallenge()    |
      |   redirect_uri=...                 |   verify redirect_uri      |
      |                                    |   verify client_id         |
      |                                    |                            |
5.    |<-- { access_token, refresh_token } |                            |
      |                                    |                            |
6.    |-- GET /resource ---------------------------------->             |
      |   Authorization: Bearer <token>                                 |
```

## Key Distinctions

**state vs code_verifier** — both are random strings but serve different purposes:

| | `code_verifier` | `state` |
|---|---|---|
| Protects against | Auth code interception | CSRF attacks |
| Validated by | Auth server (via `VerifyCodeChallenge`) | Client (compared to session) |
| How | Transformed into challenge via SHA256 | Sent raw, echoed back unchanged |
| Auth server stores it? | Yes (as the challenge) | No — just passes it through |

The auth server never validates `state` — it has no idea what it means. Only your app does.

## Building Blocks

- [x] `GenerateCodeVerifier()` — 32-byte random URL-safe string (RFC 7636)
- [x] `GenerateCodeChallenge(verifier)` — BASE64URL(SHA256(verifier))
- [x] `VerifyCodeChallenge(verifier, challenge)` — validates verifier against stored challenge
- [x] `GenerateState()` — CSRF protection on the `/authorize` redirect
- [x] Auth code generator — random opaque token, short-lived
- [x] Auth code store — `map[code]→{challenge, client_id, redirect_uri, expiry}`
- [x] `/authorize` handler — validates client, issues auth code, redirects with `?code=&state=`
- [ ] `/token` handler — calls `VerifyCodeChallenge`, exchanges code for JWT
- [ ] JWT issuance — access token (short-lived ~15min) + refresh token
- [ ] Token store — refresh tokens and revocation
- [ ] Bearer middleware — resource server validates access token
