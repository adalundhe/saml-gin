package samlsp

import (
	"net"
	"net/http"
	"time"

	"github.com/adalundhe/saml-gin"
	"github.com/gin-gonic/gin"
)

const defaultSessionCookieName = "token"

var _ SessionProvider = &CookieSessionProvider{}

// CookieSessionProvider is an implementation of SessionProvider that stores
// session tokens in an HTTP cookie.
type CookieSessionProvider struct {
	Name     string
	Domain   string
	HTTPOnly bool
	Secure   bool
	SameSite http.SameSite
	MaxAge   time.Duration
	Path     string
	Codec    SessionCodec
}

func (c *CookieSessionProvider) GetName() string {
	return c.Name
}

func (c *CookieSessionProvider) SetName(name string) {
	c.Name = name
}

func (c *CookieSessionProvider) GetMaxAge() time.Duration {
	return c.MaxAge
}

func (c *CookieSessionProvider) SetMaxAge(age time.Duration) {
	c.MaxAge = age
}

func (c *CookieSessionProvider) GetCodec() SessionCodec {
	return c.Codec
}

func (c *CookieSessionProvider) SetCodec(codec SessionCodec) {
	c.Codec = codec
}

// CreateSession is called when we have received a valid SAML assertion and
// should create a new session and modify the http response accordingly, e.g. by
// setting a cookie.
func (c *CookieSessionProvider) CreateSession(ctx *gin.Context, assertion *saml.Assertion) error {
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	session, err := c.Codec.New(assertion)
	if err != nil {
		return err
	}

	value, err := c.Codec.Encode(session)
	if err != nil {
		return err
	}

	path := c.Path
	if path == "" {
		path = "/"
	}

	ctx.SetCookie(
		c.Name,
		value,
		int(c.MaxAge.Seconds()),
		path,
		c.Domain,
		c.Secure || ctx.Request.URL.Scheme == "https",
		c.HTTPOnly,
	)

	return nil
}

// DeleteSession is called to modify the response such that it removed the current
// session, e.g. by deleting a cookie.
func (c *CookieSessionProvider) DeleteSession(ctx *gin.Context) error {
	// Cookies should not have the port attached to them so strip it off
	if domain, _, err := net.SplitHostPort(c.Domain); err == nil {
		c.Domain = domain
	}

	cookie, err := ctx.Request.Cookie(c.Name)

	if err == http.ErrNoCookie {
		return nil
	}
	if err != nil {
		return err
	}

	cookie.Value = ""
	cookie.Expires = time.Unix(1, 0) // past time as close to epoch as possible, but not zero time.Time{}
	cookie.Path = "/"
	cookie.Domain = c.Domain

	ctx.SetCookie(
		cookie.Name,
		cookie.Value,
		cookie.MaxAge,
		cookie.Path,
		cookie.Domain,
		cookie.Secure,
		cookie.HttpOnly,
	)
	return nil
}

// GetSession returns the current Session associated with the request, or
// ErrNoSession if there is no valid session.
func (c *CookieSessionProvider) GetSession(ctx *gin.Context) (Session, error) {
	cookie, err := ctx.Request.Cookie(c.Name)
	if err == http.ErrNoCookie {
		return nil, ErrNoSession
	} else if err != nil {
		return nil, err
	}

	session, err := c.Codec.Decode(cookie.Value)
	if err != nil {
		return nil, ErrNoSession
	}
	return session, nil
}
