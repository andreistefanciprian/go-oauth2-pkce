# oauth_play

A learning project for building OAuth 2.1 with PKCE from scratch in Go.

## OAuth 2.1 + PKCE Flow

```
Client (browser/app)                  Auth Server                Resource Server
      |                                    |                            |
1.    | GenerateCodeVerifier()             |                            |
      | GenerateCodeChallenge(verifier)    |                            |
      | GenerateState()                    |                            |
      |                                    |                            |
2.    |-- GET /authorize ----------------->|                            |
      |   ?code_challenge=<challenge>      |                            |
      |   &code_challenge_method=S256      |                            |
      |   &client_id=...                   |                            |
      |   &redirect_uri=...                |                            |
      |   &state=<random>   (CSRF guard)   |                            |
      |                                    |                            |
3.    |<-- redirect with ?code=<auth_code> |                            |
      |                                    |                            |
4.    |-- POST /token -------------------->|                            |
      |   grant_type=authorization_code    |                            |
      |   code=<auth_code>                 |                            |
      |   code_verifier=<verifier>  <------+-- VerifyCodeChallenge()    |
      |   redirect_uri=...                 |                            |
      |                                    |                            |
5.    |<-- { access_token, refresh_token } |                            |
      |                                    |                            |
6.    |-- GET /resource ---------------------------------->             |
      |   Authorization: Bearer <token>                                 |
```

## Building Blocks

- [x] `GenerateCodeVerifier()` — 32-byte random URL-safe string (RFC 7636)
- [x] `GenerateCodeChallenge(verifier)` — BASE64URL(SHA256(verifier))
- [x] `VerifyCodeChallenge(verifier, challenge)` — validates verifier against stored challenge
- [ ] `GenerateState()` — CSRF protection on the `/authorize` redirect
- [ ] Auth code generator — random opaque token, short-lived
- [ ] Auth code store — `map[code]→{challenge, client_id, redirect_uri, expiry}`
- [ ] `/authorize` handler — validates client, issues auth code, redirects with `?code=&state=`
- [ ] `/token` handler — calls `VerifyCodeChallenge`, exchanges code for JWT
- [ ] JWT issuance — access token (short-lived ~15min) + refresh token
- [ ] Token store — refresh tokens and revocation
- [ ] Bearer middleware — resource server validates access token
