package authserver

// Client represents a registered OAuth client.
type Client struct {
	ID           string
	RedirectURIs []string
}

// Server holds the auth server's runtime state.
type Server struct {
	Codes   *AuthCodeStore
	Tokens  *TokenIssuer
	clients map[string]Client // in prod: replace with Redis/DB lookup
}

func NewServer(clients []Client, signingKey []byte) *Server {
	m := make(map[string]Client, len(clients))
	for _, c := range clients {
		m[c.ID] = c
	}
	return &Server{
		Codes:   NewAuthCodeStore(),
		Tokens:  NewTokenIssuer(signingKey),
		clients: m,
	}
}

func (s *Server) lookupClient(clientID string) (Client, bool) {
	// in prod: query Redis/DB by client_id
	c, ok := s.clients[clientID]
	return c, ok
}

func (s *Server) isRedirectURIAllowed(client Client, redirectURI string) bool {
	for _, allowed := range client.RedirectURIs {
		if allowed == redirectURI {
			return true
		}
	}
	return false
}
