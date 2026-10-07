package web

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
)

type scriptedSSOClient struct {
	responses []*http.Response
	requests  []*http.Request
}

func (c *scriptedSSOClient) Do(request *http.Request) (*http.Response, error) {
	c.requests = append(c.requests, request)
	response := c.responses[0]
	c.responses = c.responses[1:]
	return response, nil
}

func TestSSOBuildFlowFollowsOnlyTrustedXAIHTTPSRedirects(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://auth.x.ai/next"}, "Set-Cookie": []string{"session=abc; Path=/; Secure"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "test-agent", cookies: map[string]string{"sso": "secret"}}
	status, finalURL, body, err := flow.do(context.Background(), http.MethodGet, ssoDeviceURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK || finalURL != "https://auth.x.ai/next" || string(body) != "ok" {
		t.Fatalf("response = %d %s %q", status, finalURL, body)
	}
	if len(client.requests) != 2 || client.requests[1].Header.Get("User-Agent") != "test-agent" {
		t.Fatalf("requests = %#v", client.requests)
	}
	cookie := client.requests[1].Header.Get("Cookie")
	if !strings.Contains(cookie, "sso=secret") || !strings.Contains(cookie, "session=abc") {
		t.Fatalf("redirect cookies = %q", cookie)
	}

	unsafe := &scriptedSSOClient{responses: []*http.Response{{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://example.com/steal"}}, Body: io.NopCloser(strings.NewReader(""))}}}
	flow = &ssoBuildFlow{client: unsafe, userAgent: "test-agent", cookies: map[string]string{"sso": "secret"}}
	if _, _, _, err := flow.do(context.Background(), http.MethodGet, ssoDeviceURL, nil); err == nil {
		t.Fatal("unsafe redirect was accepted")
	}
}

func TestSSOBuildFlowMapsDeadSSOToUnauthorized(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			`{"device_code":"dc","user_code":"uc","interval":1,"expires_in":1800}`))},
		{StatusCode: http.StatusSeeOther, Header: http.Header{"Location": []string{"https://accounts.x.ai/sign-in"}}, Body: io.NopCloser(strings.NewReader(""))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: map[string]string{"sso": "dead"}}
	_, err := flow.convert(context.Background(), fakeCredential())
	if !errors.Is(err, provider.ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if len(client.requests) != 2 {
		t.Fatalf("requests = %d, want 2 (device, verify)", len(client.requests))
	}
}

func TestSSOBuildFlowUsesConsentPageTokenAndTrustedEndpoints(t *testing.T) {
	consentToken := "eyJhbGciOiJFUzI1NiJ9.eyJkYyI6ImRjIn0.signature"
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			`{"device_code":"dc","user_code":"uc","interval":1,"expires_in":1800}`))},
		{StatusCode: http.StatusSeeOther, Header: http.Header{"Location": []string{"https://accounts.x.ai/oauth2/device/consent"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			`<form><input value='` + consentToken + `' data-test='consent' name='consent_token'></form>`))},
		{StatusCode: http.StatusSeeOther, Header: http.Header{"Location": []string{"https://accounts.x.ai/oauth2/device/done"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			`{"access_token":"access","refresh_token":"refresh","expires_in":3600}`))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: map[string]string{"sso": "live", "sso-rw": "live"}}
	seed, err := flow.convert(context.Background(), fakeCredential())
	if err != nil {
		t.Fatal(err)
	}
	if seed.AccessToken != "access" || seed.RefreshToken != "refresh" || len(client.requests) != 5 {
		t.Fatalf("seed=%#v requests=%d", seed, len(client.requests))
	}
	want := []struct{ method, path, host string }{
		{http.MethodPost, "/oauth2/device/code", "auth.x.ai"},
		{http.MethodPost, "/oauth2/device/verify", "auth.x.ai"},
		{http.MethodGet, "/oauth2/device/consent", "accounts.x.ai"},
		{http.MethodPost, "/oauth2/device/approve", "auth.x.ai"},
		{http.MethodPost, "/oauth2/token", "auth.x.ai"},
	}
	for i, request := range client.requests {
		if request.Method != want[i].method || request.URL.Path != want[i].path || request.URL.Hostname() != want[i].host {
			t.Fatalf("request %d = %s %s, want %s %s", i, request.Method, request.URL, want[i].method, want[i].path)
		}
	}
	if got := client.requests[3].Header.Get("Origin"); got != "https://accounts.x.ai" {
		t.Fatalf("approve Origin = %q", got)
	}
	if got := client.requests[3].Header.Get("Referer"); got != "https://accounts.x.ai/oauth2/device/consent" {
		t.Fatalf("approve Referer = %q", got)
	}
	approveBody, err := io.ReadAll(client.requests[3].Body)
	if err != nil {
		t.Fatal(err)
	}
	approveForm, err := url.ParseQuery(string(approveBody))
	if err != nil {
		t.Fatal(err)
	}
	if got := approveForm.Get("consent_token"); got != consentToken {
		t.Fatalf("approve consent_token = %q, want submitted page token", got)
	}
}

func TestExtractConsentTokenSupportsHTMLAndRSC(t *testing.T) {
	const consentToken = "eyJhbGciOiJFUzI1NiJ9.eyJkYyI6ImRjIn0.signature"
	tests := map[string][]byte{
		"HTML attributes in any order": []byte(`<input value='` + consentToken + `' name='consent_token'>`),
		"RSC escaped JSON":             []byte("self.__next_f.push([1, \"{\\\"consentToken\\\":\\\"" + consentToken + "\\\"}\"]);"),
		"RSC snake_case JSON":          []byte(`{"consent_token":"` + consentToken + `"}`),
	}
	for name, body := range tests {
		t.Run(name, func(t *testing.T) {
			if got := extractConsentToken(body); got != consentToken {
				t.Fatalf("extractConsentToken() = %q, want consent token", got)
			}
		})
	}
	if got := extractConsentToken([]byte(`<input name="consent_token" value="not-a-jwt">`)); got != "" {
		t.Fatalf("malformed consent token accepted: %q", got)
	}
}

func TestSummarizeOAuthErrorUsesStructuredFieldsAndOmitsSensitiveText(t *testing.T) {
	body := []byte(`{"error":"request_not_verified","error_description":" Request could not be verified\n"}`)
	if got := summarizeOAuthError(body); got != "Request could not be verified" {
		t.Fatalf("summarizeOAuthError() = %q", got)
	}
	if got := summarizeOAuthError([]byte(`{"message":"eyJheader.payload.signature"}`)); strings.Contains(got, "eyJ") {
		t.Fatalf("token-like error detail was not omitted: %q", got)
	}
	if got := summarizeOAuthError([]byte(`<html>upstream error</html>`)); got != "" {
		t.Fatalf("unstructured upstream body leaked: %q", got)
	}
	if got := summarizeOAuthError([]byte(`<html><p>Request could not be verified</p></html>`)); got != "Request could not be verified" {
		t.Fatalf("HTML verification error summary = %q", got)
	}
}

func TestSSOBuildFlowVerifyDoesNotFollowRedirect(t *testing.T) {
	const consentToken = "eyJhbGciOiJFUzI1NiJ9.eyJkYyI6ImRjIn0.signature"
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusSeeOther, Header: http.Header{"Location": []string{"https://accounts.x.ai/oauth2/device/consent"}}, Body: io.NopCloser(strings.NewReader(`<input name="consent_token" value="` + consentToken + `">`))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: map[string]string{"sso": "live"}}
	status, finalURL, body, err := flow.doWithFollow(context.Background(), http.MethodPost, ssoVerifyURL, url.Values{"user_code": {"uc"}}, false)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusSeeOther {
		t.Fatalf("status = %d, want 303", status)
	}
	if finalURL != "https://accounts.x.ai/oauth2/device/consent" {
		t.Fatalf("finalURL = %q", finalURL)
	}
	if got := extractConsentToken(body); got != consentToken {
		t.Fatalf("verify body consent_token = %q", got)
	}
	if len(client.requests) != 1 {
		t.Fatalf("redirect must not be followed, requests = %d", len(client.requests))
	}
}

func TestSSODeviceRedirectStateRequiresExactTrustedPath(t *testing.T) {
	tests := map[string]string{
		"https://accounts.x.ai/oauth2/device/consent":           "consent",
		"https://accounts.x.ai/oauth2/device/done/":             "done",
		"https://accounts.x.ai/sign-in?returnTo=%2Foauth2":      "sign-in",
		"https://accounts.x.ai/other?next=consent":              "",
		"https://accounts.x.ai/oauth2/device/consent-untrusted": "",
		"https://example.com/oauth2/device/consent":             "",
	}
	for raw, wanted := range tests {
		if actual := ssoDeviceRedirectState(raw); actual != wanted {
			t.Fatalf("ssoDeviceRedirectState(%q)=%q want=%q", raw, actual, wanted)
		}
	}
}

func fakeCredential() accountdomain.Credential { return accountdomain.Credential{} }

func TestSSOBuildConversionSanitizesTokenAndURLs(t *testing.T) {
	if token := normalizeSSOToken("sso=token-value; x-userid=drop"); token != "token-value" {
		t.Fatalf("token = %q", token)
	}
	for _, value := range []string{"https://accounts.x.ai/", "https://auth.x.ai/oauth2/device/code"} {
		if !safeXAIURL(value) {
			t.Fatalf("trusted URL rejected: %s", value)
		}
	}
	for _, value := range []string{"http://auth.x.ai/", "https://x.ai.example.com/", "https://user@auth.x.ai/"} {
		if safeXAIURL(value) {
			t.Fatalf("unsafe URL accepted: %s", value)
		}
	}
	origin, err := ssoOrigin("https://accounts.x.ai/oauth2/device/consent?state=abc")
	if err != nil || origin != "https://accounts.x.ai" {
		t.Fatalf("ssoOrigin() = %q, %v", origin, err)
	}
	if _, err := ssoOrigin("https://example.com/oauth2/device/consent"); err == nil {
		t.Fatal("untrusted consent origin accepted")
	}
}
