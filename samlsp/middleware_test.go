package samlsp

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/loopfz/gadgeto/tonic"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"github.com/adalundhe/saml-gin"
	"github.com/adalundhe/saml-gin/testsaml"
)

type MiddlewareTest struct {
	AuthnRequest          []byte
	SamlResponse          []byte
	Key                   *rsa.PrivateKey
	Certificate           *x509.Certificate
	IDPMetadata           []byte
	Middleware            Middleware
	expectedSessionCookie string
}

type testRandomReader struct {
	Next byte
}

func (tr *testRandomReader) Read(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		p[i] = tr.Next
		tr.Next += 2
	}
	return len(p), nil
}

func testHTTPResponse(r *gin.Engine, req *http.Request, assertions ...func(w *httptest.ResponseRecorder)) {

	// Create a response recorder
	w := httptest.NewRecorder()

	// Create the service and process the above request.
	r.ServeHTTP(w, req)

	for _, assertion := range assertions {
		assertion(w)
	}
}

func testMiddlewareRequest(r *gin.Engine, req *http.Request, assertions ...func(w *httptest.ResponseRecorder)) {
	testHTTPResponse(r, req, assertions...)
}

func getRouter(withTemplates bool, middleware ...gin.HandlerFunc) *gin.Engine {
	r := gin.Default()
	if withTemplates {
		r.LoadHTMLGlob("templates/*")
		r.Use(middleware...)

	}

	return r
}

func NewMiddlewareTest(t *testing.T) *MiddlewareTest {
	test := MiddlewareTest{}
	saml.TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 MST 2006", "Mon Dec 1 01:57:09.123456789 UTC 2015")
		return rv
	}
	saml.Clock = dsig.NewFakeClockAt(saml.TimeNow())
	saml.RandReader = &testRandomReader{}

	test.AuthnRequest = golden.Get(t, "authn_request.url")
	test.SamlResponse = golden.Get(t, "saml_response.xml")
	test.Key = mustParsePrivateKey(golden.Get(t, "key.pem")).(*rsa.PrivateKey)
	test.Certificate = mustParseCertificate(golden.Get(t, "cert.pem"))
	test.IDPMetadata = golden.Get(t, "idp_metadata.xml")

	var metadata saml.EntityDescriptor
	if err := xml.Unmarshal(test.IDPMetadata, &metadata); err != nil {
		panic(err)
	}

	opts := Options{
		URL:         mustParseURL("https://15661444.ngrok.io/"),
		Key:         test.Key,
		Certificate: test.Certificate,
		IDPMetadata: &metadata,
	}

	var err error
	test.Middleware, err = New(opts)
	if err != nil {
		panic(err)
	}

	sessionProvider := DefaultSessionProvider(opts)
	sessionProvider.Name = "ttt"
	sessionProvider.MaxAge = 7200 * time.Second

	sessionCodec := sessionProvider.Codec.(JWTSessionCodec)
	sessionCodec.MaxAge = 7200 * time.Second
	sessionProvider.Codec = sessionCodec

	test.Middleware.SetSession(sessionProvider)

	serviceProvider := test.Middleware.GetServiceProvider()

	metadataUrl := serviceProvider.GetMetadataURL()
	metadataUrl.Path = "/saml2/metadata"
	serviceProvider.SetMetadataUrl(metadataUrl)

	acsUrl := serviceProvider.GetAcsUrl()
	acsUrl.Path = "/saml2/acs"
	serviceProvider.SetAcsUrl(*acsUrl)

	sloUrl := serviceProvider.GetSloUrl()
	sloUrl.Path = "/saml2/slo"
	serviceProvider.SetSloUrl(sloUrl)

	test.Middleware.SetServiceProvider(serviceProvider)

	var tc JWTSessionClaims
	if err := json.Unmarshal(golden.Get(t, "token.json"), &tc); err != nil {
		panic(err)
	}
	test.expectedSessionCookie, err = sessionProvider.Codec.Encode(tc)
	if err != nil {
		panic(err)
	}

	return &test
}

func (test *MiddlewareTest) makeTrackedRequest(id string) string {
	codec := test.Middleware.GetRequestTracker().(CookieRequestTracker).Codec
	token, err := codec.Encode(TrackedRequest{
		Index:         "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6",
		SAMLRequestID: id,
		URI:           "/frob",
	})
	if err != nil {
		panic(err)
	}
	return token
}

func TestMiddlewareCanProduceMetadata(t *testing.T) {
	test := NewMiddlewareTest(t)

	req := httptest.NewRequest(http.MethodGet, "/saml2/metadata", nil)
	resp := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(resp)
	ctx.Request = req

	buffer, err := test.Middleware.ServeMetadata(ctx)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(http.StatusOK, resp.Code))
	assert.Check(t, is.Equal("application/samlmetadata+xml",
		resp.Header().Get("Content-type")))

	golden.Assert(t, string(buffer), "expected_middleware_metadata.xml")
}

func TestMiddlewareRequireAccountNoCreds(t *testing.T) {

	test := NewMiddlewareTest(t)
	serviceProvider := test.Middleware.GetServiceProvider()

	acsUrl := serviceProvider.GetAcsUrl()
	acsUrl.Scheme = "http"
	serviceProvider.SetAcsUrl(*acsUrl)
	test.Middleware.SetServiceProvider(serviceProvider)

	handler := test.Middleware.RequireAccount()

	r := getRouter(false)
	r.Handle(http.MethodGet, "/saml2/metadata", tonic.Handler(test.Middleware.ServeMetadata, http.StatusFound))
	r.Handle(http.MethodGet, "/saml2/acs", tonic.Handler(test.Middleware.ServeACS, http.StatusFound))
	r.GET("/frob", handler, func(_ *gin.Context) {
		panic("not reached")
	})

	testMiddlewareRequest(
		r,
		httptest.NewRequest(http.MethodGet, "/frob", nil),
		func(resp *httptest.ResponseRecorder) {
			assert.Check(t, is.Equal(http.StatusFound, resp.Code))
		},
		func(resp *httptest.ResponseRecorder) {
			assert.Check(t, is.Equal("saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+
				test.makeTrackedRequest("id-00020406080a0c0e10121416181a1c1e20222426")+"; Path=/saml2/acs; Max-Age=90; HttpOnly",
				resp.Header().Get("Set-Cookie")))
		},
		func(resp *httptest.ResponseRecorder) {
			redirectURL, err := url.Parse(resp.Header().Get("Location"))
			assert.Check(t, err)
			decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
			assert.Check(t, err)
			golden.Assert(t, string(decodedRequest), "expected_authn_request.xml")
		},
	)

}

func TestMiddlewareRequireAccountNoCredsSecure(t *testing.T) {
	test := NewMiddlewareTest(t)

	handler := test.Middleware.RequireAccount()

	r := getRouter(false)
	r.Handle(http.MethodGet, "/saml2/metadata", tonic.Handler(test.Middleware.ServeMetadata, http.StatusFound))
	r.Handle(http.MethodGet, "/saml2/acs", tonic.Handler(test.Middleware.ServeACS, http.StatusFound))
	r.GET("/frob", handler, func(ctx *gin.Context) {
		panic("not reached")
	})

	testMiddlewareRequest(
		r,
		httptest.NewRequest(http.MethodGet, "/frob", nil),
		func(resp *httptest.ResponseRecorder) {
			assert.Check(t, is.Equal(http.StatusFound, resp.Code))
		},
		func(resp *httptest.ResponseRecorder) {
			assert.Check(t, is.Equal("saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("id-00020406080a0c0e10121416181a1c1e20222426")+"; Path=/saml2/acs; Max-Age=90; HttpOnly; Secure",
				resp.Header().Get("Set-Cookie")))

			redirectURL, err := url.Parse(resp.Header().Get("Location"))

			assert.Check(t, err)
			decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
			assert.Check(t, err)
			golden.Assert(t, string(decodedRequest), "expected_authn_request_secure.xml")
		},
	)
}

func TestMiddlewareRequireAccountNoCredsPostBinding(t *testing.T) {
	test := NewMiddlewareTest(t)

	idpMetadata := test.Middleware.GetServiceProvider().GetIDPMetadata()
	idpMetadata.IDPSSODescriptors[0].SingleSignOnServices = idpMetadata.IDPSSODescriptors[0].SingleSignOnServices[1:2]
	test.Middleware.GetServiceProvider().SetIDPMetadata(idpMetadata)

	serviceProvider := test.Middleware.GetServiceProvider()
	assert.Check(t, is.Equal("",
		serviceProvider.GetSSOBindingLocation(saml.HTTPRedirectBinding)))

	handler := test.Middleware.RequireAccount()

	r := getRouter(false)
	r.Handle(http.MethodGet, "/saml2/metadata", tonic.Handler(test.Middleware.ServeMetadata, http.StatusFound))
	r.Handle(http.MethodGet, "/saml2/acs", tonic.Handler(test.Middleware.ServeACS, http.StatusFound))
	r.GET("/frob", handler, func(ctx *gin.Context) {
		panic("not reached")
	})

	testMiddlewareRequest(
		r,
		httptest.NewRequest(http.MethodGet, "/frob", nil),
		func(resp *httptest.ResponseRecorder) {
			assert.Check(t, is.Equal(http.StatusOK, resp.Code))
		},
		func(resp *httptest.ResponseRecorder) {
			assert.Check(t, is.Equal("saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("id-00020406080a0c0e10121416181a1c1e20222426")+"; Path=/saml2/acs; Max-Age=90; HttpOnly; Secure",
				resp.Header().Get("Set-Cookie")))

			golden.Assert(t, resp.Body.String(), "expected_post_binding_response.html")

			// check that the CSP script hash is set correctly
			scriptContent := "document.getElementById('SAMLSubmitButton').style.visibility=\"hidden\";document.getElementById('SAMLRequestForm').submit();"
			scriptSum := sha256.Sum256([]byte(scriptContent))
			scriptHash := base64.StdEncoding.EncodeToString(scriptSum[:])
			assert.Check(t, is.Equal("default-src; script-src 'sha256-"+scriptHash+"'; reflected-xss block; referrer no-referrer;",
				resp.Header().Get("Content-Security-Policy")))

			assert.Check(t, is.Equal("text/html", resp.Header().Get("Content-type")))
		},
	)

}

func TestMiddlewareRequireAccountCreds(t *testing.T) {

	test := NewMiddlewareTest(t)
	handler := test.Middleware.RequireAccount()

	req := httptest.NewRequest(http.MethodGet, "/frob", nil)
	req.Header.Set("Cookie", ""+
		"ttt="+test.expectedSessionCookie+"; "+
		"Path=/; Max-Age=7200")

	r := getRouter(false)
	r.Handle(http.MethodGet, "/saml2/metadata", tonic.Handler(test.Middleware.ServeMetadata, http.StatusFound))
	r.Handle(http.MethodGet, "/saml2/acs", tonic.Handler(test.Middleware.ServeACS, http.StatusFound))
	r.GET("/frob", handler, func(ctx *gin.Context) {
		genericSession := SessionFromContext(ctx)
		jwtSession := genericSession.(JWTSessionClaims)
		assert.Check(t, is.Equal("555-5555", jwtSession.Attributes.Get("telephoneNumber")))
		assert.Check(t, is.Equal("And I", jwtSession.Attributes.Get("sn")))
		assert.Check(t, is.Equal("urn:mace:dir:entitlement:common-lib-terms", jwtSession.Attributes.Get("eduPersonEntitlement")))
		assert.Check(t, is.Equal("", jwtSession.Attributes.Get("eduPersonTargetedID")))
		assert.Check(t, is.Equal("Me Myself", jwtSession.Attributes.Get("givenName")))
		assert.Check(t, is.Equal("Me Myself And I", jwtSession.Attributes.Get("cn")))
		assert.Check(t, is.Equal("myself", jwtSession.Attributes.Get("uid")))
		assert.Check(t, is.Equal("myself@testshib.org", jwtSession.Attributes.Get("eduPersonPrincipalName")))
		assert.Check(t, is.DeepEqual([]string{"Member@testshib.org", "Staff@testshib.org"}, jwtSession.Attributes["eduPersonScopedAffiliation"]))
		assert.Check(t, is.DeepEqual([]string{"Member", "Staff"}, jwtSession.Attributes["eduPersonAffiliation"]))
		ctx.Writer.WriteHeader(http.StatusTeapot)
	})

	testMiddlewareRequest(
		r,
		req,
		func(resp *httptest.ResponseRecorder) {
			assert.Check(t, is.Equal(http.StatusTeapot, resp.Code))
		},
	)

}

func TestMiddlewareRequireAccountBadCreds(t *testing.T) {
	test := NewMiddlewareTest(t)
	handler := test.Middleware.RequireAccount()

	req := httptest.NewRequest(http.MethodGet, "/frob", nil)

	req.Header.Set("Cookie", ""+
		"ttt=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.yejJbiI6Ik1lIE15c2VsZiBBbmQgSSIsImVkdVBlcnNvbkFmZmlsaWF0aW9uIjoiU3RhZmYiLCJlZHVQZXJzb25FbnRpdGxlbWVudCI6InVybjptYWNlOmRpcjplbnRpdGxlbWVudDpjb21tb24tbGliLXRlcm1zIiwiZWR1UGVyc29uUHJpbmNpcGFsTmFtZSI6Im15c2VsZkB0ZXN0c2hpYi5vcmciLCJlZHVQZXJzb25TY29wZWRBZmZpbGlhdGlvbiI6IlN0YWZmQHRlc3RzaGliLm9yZyIsImVkdVBlcnNvblRhcmdldGVkSUQiOiIiLCJleHAiOjE0NDg5Mzg2MjksImdpdmVuTmFtZSI6Ik1lIE15c2VsZiIsInNuIjoiQW5kIEkiLCJ0ZWxlcGhvbmVOdW1iZXIiOiI1NTUtNTU1NSIsInVpZCI6Im15c2VsZiJ9.SqeTkbGG35oFj_9H-d9oVdV-Hb7Vqam6LvZLcmia7FY; "+
		"Path=/; Max-Age=7200; Secure")

	r := getRouter(false)
	r.Handle(http.MethodGet, "/saml2/metadata", tonic.Handler(test.Middleware.ServeMetadata, http.StatusFound))
	r.Handle(http.MethodGet, "/saml2/acs", tonic.Handler(test.Middleware.ServeACS, http.StatusFound))
	r.GET("/frob", handler, func(ctx *gin.Context) {
		panic("not reached")
	})

	testMiddlewareRequest(
		r,
		req,
		func(resp *httptest.ResponseRecorder) {
			assert.Check(t, is.Equal(http.StatusFound, resp.Code))

			assert.Check(t, is.Equal("saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("id-00020406080a0c0e10121416181a1c1e20222426")+"; Path=/saml2/acs; Max-Age=90; HttpOnly; Secure",
				resp.Header().Get("Set-Cookie")))

			redirectURL, err := url.Parse(resp.Header().Get("Location"))
			assert.Check(t, err)
			decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
			assert.Check(t, err)
			golden.Assert(t, string(decodedRequest), "expected_authn_request_secure.xml")
		},
	)

}

func TestMiddlewareRequireAccountExpiredCreds(t *testing.T) {
	test := NewMiddlewareTest(t)
	saml.TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Mon Dec 1 01:31:21 UTC 2115")
		return rv
	}

	handler := test.Middleware.RequireAccount()
	r := getRouter(false)
	r.Handle(http.MethodGet, "/saml2/metadata", tonic.Handler(test.Middleware.ServeMetadata, http.StatusFound))
	r.Handle(http.MethodGet, "/saml2/acs", tonic.Handler(test.Middleware.ServeACS, http.StatusFound))
	r.GET("/frob", handler, func(ctx *gin.Context) {
		panic("not reached")
	})

	req := httptest.NewRequest(http.MethodGet, "/frob", nil)
	req.Header.Set("Cookie", ""+
		"ttt="+test.expectedSessionCookie+"; "+
		"Path=/; Max-Age=7200")

	testMiddlewareRequest(
		r,
		req,
		func(resp *httptest.ResponseRecorder) {
			assert.Check(t, is.Equal(http.StatusFound, resp.Code))
			assert.Check(t, is.Equal("saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("id-00020406080a0c0e10121416181a1c1e20222426")+"; Path=/saml2/acs; Max-Age=90; HttpOnly; Secure",
				resp.Header().Get("Set-Cookie")))

			redirectURL, err := url.Parse(resp.Header().Get("Location"))
			assert.Check(t, err)
			decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
			assert.Check(t, err)
			golden.Assert(t, strings.Replace(string(decodedRequest), `IssueInstant="2115-12-01T01:31:21Z"`, `IssueInstant="2015-12-01T01:57:09.123Z"`, 1), "expected_authn_request_secure.xml")
		},
	)
}

func TestMiddlewareRequireAccountPanicOnRequestToACS(t *testing.T) {
	test := NewMiddlewareTest(t)
	resp := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(resp)

	req := httptest.NewRequest(http.MethodPost, "https://15661444.ngrok.io/saml2/acs", nil)
	ctx.Request = req

	assert.Check(t, is.Panics(func() {
		_, err := test.Middleware.ServeACS(ctx)

		if err != nil {
			panic(err)
		}
	}))
}

func TestMiddlewareRequireAttribute(t *testing.T) {
	test := NewMiddlewareTest(t)
	requireAccount := test.Middleware.RequireAccount()
	requireAttribute := RequireAttribute("eduPersonAffiliation", "Staff")

	r := getRouter(false)
	r.Handle(http.MethodGet, "/saml2/metadata", tonic.Handler(test.Middleware.ServeMetadata, http.StatusFound))
	r.Handle(http.MethodGet, "/saml2/acs", tonic.Handler(test.Middleware.ServeACS, http.StatusFound))
	r.GET("/frob", requireAccount, requireAttribute, func(ctx *gin.Context) {
		ctx.Writer.WriteHeader(http.StatusTeapot)
	})

	req := httptest.NewRequest(http.MethodGet, "/frob", nil)
	req.Header.Set("Cookie", ""+
		"ttt="+test.expectedSessionCookie+"; "+
		"Path=/; Max-Age=7200")

	testMiddlewareRequest(
		r,
		req,
		func(resp *httptest.ResponseRecorder) {
			assert.Check(t, is.Equal(http.StatusTeapot, resp.Code))
		},
	)
}

func TestMiddlewareRequireAttributeWrongValue(t *testing.T) {
	test := NewMiddlewareTest(t)

	requireAccount := test.Middleware.RequireAccount()
	requireAttribute := RequireAttribute("eduPersonAffiliation", "DomainAdmins")

	r := getRouter(false)
	r.Handle(http.MethodGet, "/saml2/metadata", tonic.Handler(test.Middleware.ServeMetadata, http.StatusFound))
	r.Handle(http.MethodGet, "/saml2/acs", tonic.Handler(test.Middleware.ServeACS, http.StatusFound))
	r.GET("/frob", requireAccount, requireAttribute, func(ctx *gin.Context) {
		ctx.Writer.WriteHeader(http.StatusTeapot)
	})

	req := httptest.NewRequest(http.MethodGet, "/frob", nil)
	req.Header.Set("Cookie", ""+
		"ttt="+test.expectedSessionCookie+"; "+
		"Path=/; Max-Age=7200")

	testMiddlewareRequest(
		r,
		req,
		func(resp *httptest.ResponseRecorder) {
			assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
		},
	)

}

func TestMiddlewareRequireAttributeNotPresent(t *testing.T) {
	test := NewMiddlewareTest(t)

	requireAccount := test.Middleware.RequireAccount()
	requireAttribute := RequireAttribute("valueThatDoesntExist", "doesntMatter")

	r := getRouter(false)
	r.Handle(http.MethodGet, "/saml2/metadata", tonic.Handler(test.Middleware.ServeMetadata, http.StatusFound))
	r.Handle(http.MethodGet, "/saml2/acs", tonic.Handler(test.Middleware.ServeACS, http.StatusFound))
	r.GET("/frob", requireAccount, requireAttribute, func(ctx *gin.Context) {
		ctx.Writer.WriteHeader(http.StatusTeapot)
	})

	req := httptest.NewRequest(http.MethodGet, "/frob", nil)
	req.Header.Set("Cookie", ""+
		"ttt="+test.expectedSessionCookie+"; "+
		"Path=/; Max-Age=7200")

	testMiddlewareRequest(
		r,
		req,
		func(resp *httptest.ResponseRecorder) {
			assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
		},
	)

}

func TestMiddlewareRequireAttributeMissingAccount(t *testing.T) {
	test := NewMiddlewareTest(t)

	requireAccount := test.Middleware.RequireAccount()
	requireAttribute := RequireAttribute("eduPersonAffiliation", "DomainAdmins")

	r := getRouter(false)
	r.Handle(http.MethodGet, "/saml2/metadata", tonic.Handler(test.Middleware.ServeMetadata, http.StatusFound))
	r.Handle(http.MethodGet, "/saml2/acs", tonic.Handler(test.Middleware.ServeACS, http.StatusFound))
	r.GET("/frob", requireAccount, requireAttribute, func(ctx *gin.Context) {
		ctx.Writer.WriteHeader(http.StatusTeapot)
	})

	req := httptest.NewRequest(http.MethodGet, "/frob", nil)
	req.Header.Set("Cookie", ""+
		"ttt="+test.expectedSessionCookie+"; "+
		"Path=/; Max-Age=7200")

	testMiddlewareRequest(
		r,
		req,
		func(resp *httptest.ResponseRecorder) {
			assert.Check(t, is.Equal(http.StatusForbidden, resp.Code))
		},
	)
}

func TestMiddlewareCanParseResponse(t *testing.T) {
	test := NewMiddlewareTest(t)
	v := &url.Values{}
	v.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	v.Set("RelayState", "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6")

	req := httptest.NewRequest(http.MethodPost, "/saml2/acs", bytes.NewReader([]byte(v.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", ""+
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("id-9e61753d64e928af5a7a341a97f420c9"))

	resp := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(resp)
	ctx.Request = req

	redirectUri, err := test.Middleware.ServeACS(ctx)

	assert.NilError(t, err)

	assert.Check(t, is.Equal("/frob", redirectUri))
	assert.Check(t, is.DeepEqual([]string{
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6=; Path=/saml2/acs; Domain=15661444.ngrok.io; Expires=Thu, 01 Jan 1970 00:00:01 GMT",
		"ttt=" + test.expectedSessionCookie + "; " +
			"Path=/; Domain=15661444.ngrok.io; Max-Age=7200; HttpOnly; Secure",
	},
		resp.Header()["Set-Cookie"]))
}

func TestMiddlewareDefaultCookieDomainIPv4(t *testing.T) {
	test := NewMiddlewareTest(t)
	ipv4Loopback := net.IP{127, 0, 0, 1}

	sp := DefaultSessionProvider(Options{
		URL: mustParseURL("https://" + net.JoinHostPort(ipv4Loopback.String(), "54321")),
		Key: test.Key,
	})

	resp := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(resp)

	assert.Check(t, sp.CreateSession(ctx, &saml.Assertion{}))

	assert.Check(t,
		strings.Contains(resp.Header().Get("Set-Cookie"), "Domain=127.0.0.1;"),
		"Cookie domain must not contain a port or the cookie cannot be set properly: %v", resp.Header().Get("Set-Cookie"))
}

func TestMiddlewareDefaultCookieDomainIPv6(t *testing.T) {
	t.Skip("fails") // TODO(ross): fix this test

	test := NewMiddlewareTest(t)

	sp := DefaultSessionProvider(Options{
		URL: mustParseURL("https://" + net.JoinHostPort(net.IPv6loopback.String(), "54321")),
		Key: test.Key,
	})

	resp := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(resp)
	assert.Check(t, sp.CreateSession(ctx, &saml.Assertion{}))

	assert.Check(t,
		strings.Contains(resp.Header().Get("Set-Cookie"), "Domain=::1;"),
		"Cookie domain must not contain a port or the cookie cannot be set properly: %v", resp.Header().Get("Set-Cookie"))
}

func TestMiddlewareRejectsInvalidRelayState(t *testing.T) {
	test := NewMiddlewareTest(t)

	test.Middleware.SetOnError(func(ctx *gin.Context, err error) error {
		assert.Check(t, is.Error(err, http.ErrNoCookie.Error()))
		return err
	})

	v := &url.Values{}
	v.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	v.Set("RelayState", "ICIkJigqLC4wMjQ2ODo8PkBCREZISkxOUFJUVlhaXF5gYmRmaGpsbnBy")
	req := httptest.NewRequest(http.MethodPost, "/saml2/acs", bytes.NewReader([]byte(v.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", ""+
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("id-9e61753d64e928af5a7a341a97f420c9"))

	resp := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(resp)
	ctx.Request = req

	redirectUri, err := test.Middleware.ServeACS(ctx)

	assert.Check(t, is.Error(err, err.Error()))
	assert.Check(t, is.Equal("", redirectUri))
	assert.Check(t, is.Equal("", resp.Header().Get("Set-Cookie")))
}

func TestMiddlewareRejectsInvalidCookie(t *testing.T) {
	test := NewMiddlewareTest(t)

	test.Middleware.SetOnError(func(ctx *gin.Context, err error) error {
		assert.Check(t, is.Error(err, "Authentication failed"))
		return err
	})

	v := &url.Values{}
	v.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	v.Set("RelayState", "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6")
	req := httptest.NewRequest(http.MethodPost, "/saml2/acs", bytes.NewReader([]byte(v.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", ""+
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("wrong"))

	resp := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(resp)
	ctx.Request = req

	redirectUri, err := test.Middleware.ServeACS(ctx)
	assert.Check(t, is.Error(err, err.Error()))
	assert.Check(t, is.Equal("", redirectUri))
	assert.Check(t, is.Equal("", resp.Header().Get("Set-Cookie")))
}

func TestMiddlewareHandlesInvalidResponse(t *testing.T) {
	test := NewMiddlewareTest(t)

	v := &url.Values{}
	v.Set("SAMLResponse", "this is not a valid saml response")
	v.Set("RelayState", "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6")

	req := httptest.NewRequest(http.MethodPost, "/saml2/acs", bytes.NewReader([]byte(v.Encode())))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", ""+
		"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("wrong"))

	resp := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(resp)
	ctx.Request = req

	redirectUri, err := test.Middleware.ServeACS(ctx)
	// note: it is important that when presented with an invalid request,
	// the ACS handles DOES NOT reveal detailed error information in the
	// HTTP response.
	assert.Check(t, is.Error(err, err.Error()))
	assert.Check(t, is.Equal("Forbidden: Authentication failed", err.Error()))
	assert.Check(t, is.Equal("", redirectUri))
	assert.Check(t, is.Equal("", resp.Header().Get("Set-Cookie")))
}
