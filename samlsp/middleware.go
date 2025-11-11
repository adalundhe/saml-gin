package samlsp

import (
	"bytes"
	"encoding/xml"
	"log/slog"
	"net/http"

	"github.com/adalundhe/saml-gin"
	"github.com/gin-gonic/gin"
)

// Middleware implements middleware than allows a web application
// to support SAML.
//
// It implements http.Handler so that it can provide the metadata and ACS endpoints,
// typically /saml/metadata and /saml/acs, respectively.
//
// It also provides middleware RequireAccount which redirects users to
// the auth process if they do not have session credentials.
//
// When redirecting the user through the SAML auth flow, the middleware assigns
// a temporary cookie with a random name beginning with "saml_". The value of
// the cookie is a signed JSON Web Token containing the original URL requested
// and the SAML request ID. The random part of the name corresponds to the
// RelayState parameter passed through the SAML flow.
//
// When validating the SAML response, the RelayState is used to look up the
// correct cookie, validate that the SAML request ID, and redirect the user
// back to their original URL.
//
// Sessions are established by issuing a JSON Web Token (JWT) as a session
// cookie once the SAML flow has succeeded. The JWT token contains the
// authenticated attributes from the SAML assertion.
//
// When the middleware receives a request with a valid session JWT it extracts
// the SAML attributes and modifies the http.Request object adding a Context
// object to the request context that contains attributes from the initial
// SAML assertion.
//
// When issuing JSON Web Tokens, a signing key is required. Because the
// SAML service provider already has a private key, we borrow that key
// to sign the JWTs as well.

type Middleware interface {
	ServeMetadata(c *gin.Context) ([]byte, error)
	ServeACS(c *gin.Context) (string, error)
	RequireAccount() gin.HandlerFunc
	HandleStartAuthFlow(c *gin.Context)
	CreateSessionFromAssertion(c *gin.Context, assertion *saml.Assertion, redirectURI string) (string, error)
	GetSession() SessionProvider
	GetRequestTracker() RequestTracker
	GetServiceProvider() saml.ServiceProvider
	SetSession(session SessionProvider)
	SetRequestTracker(tracker RequestTracker)
	SetServiceProvider(sp saml.ServiceProvider)
	SetOnError(onErr func(ctx *gin.Context, err error) error)
}

type MiddlewareImpl struct {
	ServiceProvider  saml.ServiceProvider
	OnError          func(c *gin.Context, err error) error
	Binding          string // either saml.HTTPPostBinding or saml.HTTPRedirectBinding
	ResponseBinding  string // either saml.HTTPPostBinding or saml.HTTPArtifactBinding
	RequestTracker   RequestTracker
	Session          SessionProvider
	AssertionHandler AssertionHandler
	ForceRedirectUrl string
	ACSHandler       gin.HandlerFunc
	MetadataHandler  gin.HandlerFunc
}

func (m *MiddlewareImpl) GetSession() SessionProvider {
	return m.Session
}
func (m *MiddlewareImpl) SetSession(session SessionProvider) {
	m.Session = session
}

func (m *MiddlewareImpl) GetRequestTracker() RequestTracker {
	return m.RequestTracker
}

func (m *MiddlewareImpl) SetRequestTracker(tracker RequestTracker) {
	m.RequestTracker = tracker
}

func (m *MiddlewareImpl) GetServiceProvider() saml.ServiceProvider {
	return m.ServiceProvider
}

func (m *MiddlewareImpl) SetServiceProvider(sp saml.ServiceProvider) {
	m.ServiceProvider = sp
}

func (m *MiddlewareImpl) SetOnError(onErr func(ctx *gin.Context, err error) error) {
	m.OnError = onErr
}

// ServeMetadata handles requests for the SAML metadata endpoint.
func (m *MiddlewareImpl) ServeMetadata(c *gin.Context) ([]byte, error) {
	buf, _ := xml.MarshalIndent(m.ServiceProvider.Metadata(), "", "  ")
	c.Header("Content-Type", "application/samlmetadata+xml")
	return buf, nil
}

// ServeACS handles requests for the SAML ACS endpoint.
func (m *MiddlewareImpl) ServeACS(c *gin.Context) (string, error) {

	if err := c.Request.ParseForm(); err != nil {
		return "", m.OnError(c, err)
	}

	possibleRequestIDs := []string{}
	if m.ServiceProvider.IDPInitiatedAllowed() {
		possibleRequestIDs = append(possibleRequestIDs, "")
	}

	trackedRequests := m.RequestTracker.GetTrackedRequests(c.Request)
	for _, tr := range trackedRequests {
		possibleRequestIDs = append(possibleRequestIDs, tr.SAMLRequestID)
	}

	assertion, err := m.ServiceProvider.ParseResponse(c.Request, possibleRequestIDs)
	if err != nil {
		return "", m.OnError(c, err)
	}

	if handlerErr := m.AssertionHandler.HandleAssertion(assertion); handlerErr != nil {

		return "", m.OnError(c, handlerErr)
	}

	return m.CreateSessionFromAssertion(c, assertion, m.ServiceProvider.GetDefaultRedirectURI())

}

// RequireAccount is HTTP middleware that requires that each request be
// associated with a valid session. If the request is not associated with a valid
// session, then rather than serve the request, the middleware redirects the user
// to start the SAML auth flow.
func (m *MiddlewareImpl) RequireAccount() gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := m.Session.GetSession(c)
		if session != nil {
			c.Request = c.Request.WithContext(ContextWithSession(c, session))
			// handler.ServeHTTP(w, r)
			c.Next()
			return
		}
		if err == ErrNoSession {
			m.HandleStartAuthFlow(c)
			return
		}

		err = m.OnError(c, err)
		c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
	}
}

// HandleStartAuthFlow is called to start the SAML authentication process.
func (m *MiddlewareImpl) HandleStartAuthFlow(c *gin.Context) {
	// If we try to redirect when the original request is the ACS URL we'll
	// end up in a loop. This is a programming error, so we panic here. In
	// general this means a 500 to the user, which is preferable to a
	// redirect loop.
	if c.Request.URL.Path == m.ServiceProvider.GetAcsUrl().Path {
		panic("don't wrap Middleware with RequireAccount")
	}

	var binding, bindingLocation string
	if m.Binding != "" {
		binding = m.Binding
		bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
	} else {
		binding = saml.HTTPRedirectBinding
		bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
		if bindingLocation == "" {
			binding = saml.HTTPPostBinding
			bindingLocation = m.ServiceProvider.GetSSOBindingLocation(binding)
		}
	}

	authReq, err := m.ServiceProvider.MakeAuthenticationRequest(bindingLocation, binding, m.ResponseBinding)
	if err != nil {
		err = m.OnError(c, err)
		c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})
		return
	}

	// relayState is limited to 80 bytes but also must be integrity protected.
	// this means that we cannot use a JWT because it is way to long. Instead
	// we set a signed cookie that encodes the original URL which we'll check
	// against the SAML response when we get it.
	relayState, err := m.RequestTracker.TrackRequest(c.Writer, c.Request, authReq.ID)
	if err != nil {
		err = m.OnError(c, err)
		c.JSON(http.StatusInternalServerError, map[string]string{
			"error": err.Error(),
		})

		return
	}

	if binding == saml.HTTPRedirectBinding {
		redirectURL, err := authReq.Redirect(relayState, m.GetServiceProvider())
		if err != nil {
			err = m.OnError(c, err)
			c.JSON(http.StatusInternalServerError, map[string]string{
				"error": err.Error(),
			})
			return
		}
		slog.Info("Redirecting to:", slog.Any("url", redirectURL))
		c.Header("Location", redirectURL.String())
		c.Redirect(http.StatusFound, redirectURL.String())
		return
	}
	if binding == saml.HTTPPostBinding {
		c.Header("Content-Security-Policy", ""+
			"default-src; "+
			"script-src 'sha256-AjPdJSbZmeWHnEc5ykvJFay8FTWeTeRbs9dutfZ0HqE='; "+
			"reflected-xss block; referrer no-referrer;")
		c.Header("Content-type", "text/html")
		var buf bytes.Buffer
		buf.WriteString(`<!DOCTYPE html><html><body>`)
		buf.Write(authReq.Post(relayState))
		buf.WriteString(`</body></html>`)
		if _, err := c.Writer.Write(buf.Bytes()); err != nil {
			err = m.OnError(c, err)
			c.JSON(http.StatusInternalServerError, map[string]string{
				"error": err.Error(),
			})
			return
		}
		return
	}
	panic("not reached")
}

// CreateSessionFromAssertion is invoked by ServeHTTP when we have a new, valid SAML assertion.
func (m *MiddlewareImpl) CreateSessionFromAssertion(c *gin.Context, assertion *saml.Assertion, redirectURI string) (string, error) {
	if trackedRequestIndex := c.Request.Form.Get("RelayState"); trackedRequestIndex != "" {
		trackedRequest, err := m.RequestTracker.GetTrackedRequest(c.Request, trackedRequestIndex)
		if err != nil {
			if err == http.ErrNoCookie && m.ServiceProvider.IDPInitiatedAllowed() {
				if uri := c.Request.Form.Get("RelayState"); uri != "" {
					redirectURI = uri
				}
			} else {
				return "", m.OnError(c, err)
			}
		} else {
			if err := m.RequestTracker.StopTrackingRequest(c.Writer, c.Request, trackedRequestIndex); err != nil {
				return "", m.OnError(c, err)
			}

			redirectURI = trackedRequest.URI
		}
	}

	if err := m.Session.CreateSession(c, assertion); err != nil {
		return "", m.OnError(c, err)
	}

	slog.Info("Redirecting to:", slog.Any("url", redirectURI))
	return redirectURI, nil
}

// RequireAttribute returns a middleware function that requires that the
// SAML attribute `name` be set to `value`. This can be used to require
// that a remote user be a member of a group. It relies on the Claims assigned
// to to the context in RequireAccount.
func RequireAttribute(name, value string) gin.HandlerFunc {

	return func(ctx *gin.Context) {
		if session := SessionFromContext(ctx); session != nil {
			// this will panic if we have the wrong type of Session, and that is OK.
			sessionWithAttributes := session.(SessionWithAttributes)
			attributes := sessionWithAttributes.GetAttributes()
			if values, ok := attributes[name]; ok {
				for _, v := range values {
					if v == value {
						ctx.Next()
						return
					}
				}
			}
		}

		ctx.JSON(http.StatusForbidden, map[string]string{
			"error": http.StatusText(http.StatusForbidden),
		})
	}
}
