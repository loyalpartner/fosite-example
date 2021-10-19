package authorizationserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	_oauth2 "github.com/ory/fosite/handler/oauth2"

	"github.com/ory/fosite/handler/openid"
	"github.com/ory/fosite/storage"
	"github.com/ory/fosite/token/jwt"
)

func RegisterHandlers() {
	// Set up oauth2 endpoints. You could also use gorilla/mux or any other router.
	http.HandleFunc("/oauth2/auth", authEndpoint)
	http.HandleFunc("/oauth2/token", tokenEndpoint)

	// revoke tokens
	http.HandleFunc("/oauth2/revoke", revokeEndpoint)
	http.HandleFunc("/oauth2/introspect", introspectionEndpoint)
}

// fosite requires four parameters for the server to get up and running:
// 1. config - for any enforcement you may desire, you can do this using `compose.Config`. You like PKCE, enforce it!
// 2. store - no auth service is generally useful unless it can remember clients and users.
//    fosite is incredibly composable, and the store parameter enables you to build and BYODb (Bring Your Own Database)
// 3. secret - required for code, access and refresh token generation.
// 4. privateKey - required for id/jwt token generation.
var (
	// Check the api documentation of `compose.Config` for further configuration options.
	config = &compose.Config{
		AccessTokenLifespan: time.Minute * 30,
		// ...
	}

	// This is the example storage that contains:
	// * an OAuth2 Client with id "my-client" and secrets "foobar" and "foobaz" capable of all oauth2 and open id connect grant and response types.
	// * a User for the resource owner password credentials grant type with username "peter" and password "secret".
	//
	// You will most likely replace this with your own logic once you set up a real world application.
	store = storage.NewExampleStore()

	// This secret is used to sign authorize codes, access and refresh tokens.
	// It has to be 32-bytes long for HMAC signing. This requirement can be configured via `compose.Config` above.
	// In order to generate secure keys, the best thing to do is use crypto/rand:
	//
	// ```
	// package main
	//
	// import (
	//	"crypto/rand"
	//	"encoding/hex"
	//	"fmt"
	// )
	//
	// func main() {
	//	var secret = make([]byte, 32)
	//	_, err := rand.Read(secret)
	//	if err != nil {
	//		panic(err)
	//	}
	// }
	// ```
	//
	// If you require this to key to be stable, for example, when running multiple fosite servers, you can generate the
	// 32byte random key as above and push it out to a base64 encoded string.
	// This can then be injected and decoded as the `var secret []byte` on server start.
	secret = []byte("some-cool-secret-that-is-32bytes")

	// privateKey is used to sign JWT tokens. The default strategy uses RS256 (RSA Signature with SHA-256)
	privateKey, _ = rsa.GenerateKey(rand.Reader, 2048)
)

// Build a fosite instance with all OAuth2 and OpenID Connect handlers enabled, plugging in our configurations as specified above.
//var oauth2 = compose.ComposeAllEnabled(config, store, secret, privateKey)
var oauth2 = compose.Compose(
	config,
	store,
	&compose.CommonStrategy{
		CoreStrategy:               compose.NewOAuth2HMACStrategy(config, secret, nil),
		OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(config, privateKey),
		JWTStrategy: &jwt.RS256JWTStrategy{
			PrivateKey: privateKey,
		},
	},
	nil,

	compose.OAuth2AuthorizeExplicitFactory,
	compose.OAuth2AuthorizeImplicitFactory,
	compose.OAuth2ClientCredentialsGrantFactory,
	OAuth2RefreshTokenGrantFactory,
	compose.OAuth2ResourceOwnerPasswordCredentialsFactory,
	compose.RFC7523AssertionGrantFactory,

	compose.OpenIDConnectExplicitFactory,
	compose.OpenIDConnectImplicitFactory,
	compose.OpenIDConnectHybridFactory,
	compose.OpenIDConnectRefreshFactory,

	compose.OAuth2TokenIntrospectionFactory,
	compose.OAuth2TokenRevocationFactory,

	compose.OAuth2PKCEFactory,
)

type TokenHandler _oauth2.RefreshTokenGrantHandler

func (c *TokenHandler) PopulateTokenEndpointResponse(ctx context.Context, requester fosite.AccessRequester, responder fosite.AccessResponder) error {
	fmt.Print("PopulateToken")
	return nil
}

// HandleTokenEndpointRequest handles an authorize request. If the handler is not responsible for handling
// the request, this method should return ErrUnknownRequest and otherwise handle the request.
func (c *TokenHandler) HandleTokenEndpointRequest(ctx context.Context, requester fosite.AccessRequester) error {
	fmt.Print("HandleTokenEndpointRequest")
	return nil
}

// CanSkipClientAuth indicates if client authentication can be skipped. By default it MUST be false, unless you are
// implementing extension grant type, which allows unauthenticated client. CanSkipClientAuth must be called
// before HandleTokenEndpointRequest to decide, if AccessRequester will contain authenticated client.
func (c *TokenHandler) CanSkipClientAuth(requester fosite.AccessRequester) bool {
	fmt.Print("Skip")
	return false
}

// CanHandleRequest indicates, if TokenEndpointHandler can handle this request or not. If true,
// HandleTokenEndpointRequest can be called.
func (c *TokenHandler) CanHandleTokenEndpointRequest(requester fosite.AccessRequester) bool {
	fmt.Print("Handle")

	return true
}

func OAuth2RefreshTokenGrantFactory(config *compose.Config, storage interface{}, strategy interface{}) interface{} {
	return &TokenHandler{
		AccessTokenStrategy:      strategy.(_oauth2.AccessTokenStrategy),
		RefreshTokenStrategy:     strategy.(_oauth2.RefreshTokenStrategy),
		TokenRevocationStorage:   storage.(_oauth2.TokenRevocationStorage),
		AccessTokenLifespan:      config.GetAccessTokenLifespan(),
		RefreshTokenLifespan:     config.GetRefreshTokenLifespan(),
		ScopeStrategy:            config.GetScopeStrategy(),
		AudienceMatchingStrategy: config.GetAudienceStrategy(),
		RefreshTokenScopes:       config.GetRefreshTokenScopes(),
	}
}

// A session is passed from the `/auth` to the `/token` endpoint. You probably want to store data like: "Who made the request",
// "What organization does that person belong to" and so on.
// For our use case, the session will meet the requirements imposed by JWT access tokens, HMAC access tokens and OpenID Connect
// ID Tokens plus a custom field

// newSession is a helper function for creating a new session. This may look like a lot of code but since we are
// setting up multiple strategies it is a bit longer.
// Usually, you could do:
//
//  session = new(fosite.DefaultSession)
func newSession(user string) *openid.DefaultSession {
	return &openid.DefaultSession{
		Claims: &jwt.IDTokenClaims{
			Issuer:      "https://fosite.my-application.com",
			Subject:     user,
			Audience:    []string{"https://my-client.my-application.com"},
			ExpiresAt:   time.Now().Add(time.Hour * 6),
			IssuedAt:    time.Now(),
			RequestedAt: time.Now(),
			AuthTime:    time.Now(),
		},
		Headers: &jwt.Headers{
			Extra: make(map[string]interface{}),
		},
	}
}
