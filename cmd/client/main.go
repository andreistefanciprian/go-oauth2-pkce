package main

import (
	"fmt"

	"github.com/andreistefanciprian/oauth_play/pkce"
)

const (
	clientID    = "myapp"
	redirectURI = "http://localhost:9000/callback"
	authServer  = "http://localhost:8080"
)

func main() {
	verifier, err := pkce.GenerateCodeVerifier()
	if err != nil {
		panic(err)
	}
	challenge := pkce.GenerateCodeChallenge(verifier)
	state, err := pkce.GenerateState()
	if err != nil {
		panic(err)
	}

	fmt.Println("=== Step 1: Get auth code ===")
	fmt.Printf(`curl -v "%s/authorize?client_id=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256&state=%s"`+"\n\n",
		authServer, clientID, redirectURI, challenge, state)

	fmt.Println("=== Copy the 'code' from the redirect Location header, then: ===")
	fmt.Println()
	fmt.Println("=== Step 2: Exchange code for tokens ===")
	fmt.Printf(`curl -v -X POST %s/token \`+"\n", authServer)
	fmt.Printf(`  -d "grant_type=authorization_code" \`+"\n")
	fmt.Printf(`  -d "code=<PASTE_CODE_HERE>" \`+"\n")
	fmt.Printf(`  -d "code_verifier=%s" \`+"\n", verifier)
	fmt.Printf(`  -d "redirect_uri=%s" \`+"\n", redirectURI)
	fmt.Printf(`  -d "client_id=%s"`+"\n\n", clientID)

	fmt.Println("=== Step 3: Call the resource server with the access token ===")
	fmt.Println(`curl -v http://localhost:8081/profile \`)
	fmt.Println(`  -H "Authorization: Bearer <PASTE_ACCESS_TOKEN_HERE>"`)
}
