package web

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/chenyme/grok2api/backend/internal/infra/provider"
)

func TestAuthCodeConversionExchangesConsentForBuildToken(t *testing.T) {
	rememberAuthCodeAction(ssoAuthCodeKnownAction)
	access := testBuildJWT(`{"sub":"user-1","email":"a@b.c","referrer":"grok-build"}`)
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("accounts"))},
		{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://accounts.x.ai/oauth2/consent?state=1"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("<html>consent</html>"))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("0:{\"code\":\"auth-code\",\"success\":true}\n"))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			`{"access_token":"` + access + `","refresh_token":"refresh","expires_in":21600}`))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: ssoBuildCookies("live", "cf_clearance=clearance")}
	seed, err := flow.convertWithAuthCode(context.Background(), fakeCredential())
	if err != nil {
		t.Fatal(err)
	}
	if seed.AccessToken != access || seed.RefreshToken != "refresh" || seed.Email != "a@b.c" || seed.UserID != "user-1" || seed.OIDCClientID != ssoBuildClientID {
		t.Fatalf("seed = %#v", seed)
	}
	if len(client.requests) != 5 {
		t.Fatalf("requests = %d", len(client.requests))
	}
	authorize := client.requests[1].URL.Query()
	if authorize.Get("client_id") != ssoBuildClientID || authorize.Get("response_type") != "code" || authorize.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize query = %v", authorize)
	}
	if authorize.Get("referrer") != "grok-build" || authorize.Get("plan") != "generic" || authorize.Get("redirect_uri") != ssoAuthCodeRedirect {
		t.Fatalf("authorize identity = %v", authorize)
	}
	if strings.Contains(authorize.Get("scope"), "conversations:") || strings.Contains(authorize.Get("scope"), "workspaces:") {
		t.Fatalf("scope includes client-rejected grants: %s", authorize.Get("scope"))
	}
	sum := sha256.Sum256([]byte(mustAuthCodeVerifier(t, client.requests[4])))
	if authorize.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) {
		t.Fatal("code_challenge does not match code_verifier")
	}
	consent := client.requests[3]
	if consent.Header.Get("Next-Action") != ssoAuthCodeKnownAction || consent.Header.Get("Content-Type") != "text/plain;charset=UTF-8" || consent.Header.Get("Accept") != "text/x-component" {
		t.Fatalf("consent headers = %#v", consent.Header)
	}
	if !strings.Contains(consent.Header.Get("Cookie"), "sso=live") || !strings.Contains(consent.Header.Get("Cookie"), "cf_clearance=clearance") {
		t.Fatalf("consent cookie = %q", consent.Header.Get("Cookie"))
	}
	body, err := io.ReadAll(consent.Body)
	if err != nil {
		t.Fatal(err)
	}
	var posted []authCodeConsentBody
	if err := json.Unmarshal(body, &posted); err != nil {
		t.Fatalf("consent body %s: %v", body, err)
	}
	if len(posted) != 1 || posted[0].Action != "allow" || posted[0].Referrer != "grok-build" || posted[0].PrincipalID != "" || posted[0].Scope != ssoAuthCodeScope {
		t.Fatalf("consent payload = %#v", posted)
	}
}

func TestAuthCodeConversionRejectsDeadSSO(t *testing.T) {
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://accounts.x.ai/sign-in"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("sign-in"))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: map[string]string{"sso": "dead"}}
	_, err := flow.convertWithAuthCode(context.Background(), fakeCredential())
	if !errors.Is(err, provider.ErrUnauthorized) {
		t.Fatalf("err = %v", err)
	}
	if len(client.requests) != 2 {
		t.Fatalf("requests = %d", len(client.requests))
	}
}

func TestAuthCodeConversionStopsWhenConsentDeniesAccount(t *testing.T) {
	rememberAuthCodeAction(ssoAuthCodeKnownAction)
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("accounts"))},
		{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://accounts.x.ai/oauth2/consent"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("<html>consent</html>"))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`1:{"success":false,"error":"Access denied"}`))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: map[string]string{"sso": "live"}}
	_, err := flow.convertWithAuthCode(context.Background(), fakeCredential())
	if !errors.Is(err, provider.ErrAuthorizationDenied) {
		t.Fatalf("err = %v", err)
	}
	if len(client.requests) != 4 {
		t.Fatalf("denied consent must not exchange a token, requests = %d", len(client.requests))
	}
}

func TestAuthCodeConversionRediscoversNextAction(t *testing.T) {
	dead := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	found := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	rememberAuthCodeAction(dead)
	access := testBuildJWT(`{"sub":"user-2","email":"c@d.e"}`)
	consentHTML := `<script src="/_next/static/chunks/oauth-consent.js"></script>`
	script := `createServerReference("` + found + `")`
	client := &scriptedSSOClient{responses: []*http.Response{
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("accounts"))},
		{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://accounts.x.ai/oauth2/consent"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(consentHTML))},
		{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("server action not found"))},
		{StatusCode: http.StatusNotFound, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("server action not found"))},
		{StatusCode: http.StatusFound, Header: http.Header{"Location": []string{"https://accounts.x.ai/oauth2/consent"}}, Body: io.NopCloser(strings.NewReader(""))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(consentHTML))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(script))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(`0:{"code":"fresh-code"}`))},
		{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(
			`{"access_token":"` + access + `","refresh_token":"refresh-2","expires_in":3600}`))},
	}}
	flow := &ssoBuildFlow{client: client, userAgent: "lease-agent", cookies: map[string]string{"sso": "live"}}
	seed, err := flow.convertWithAuthCode(context.Background(), fakeCredential())
	if err != nil {
		t.Fatal(err)
	}
	if seed.RefreshToken != "refresh-2" || currentAuthCodeAction() != found {
		t.Fatalf("seed refresh = %q action = %q", seed.RefreshToken, currentAuthCodeAction())
	}
	var posted []string
	for _, request := range client.requests {
		if id := request.Header.Get("Next-Action"); id != "" {
			posted = append(posted, id)
		}
	}
	if len(posted) != 3 || posted[0] != dead || posted[1] != ssoAuthCodeBootstrap || posted[2] != found {
		t.Fatalf("action attempts = %#v", posted)
	}
}

func TestParseAuthCodeConsentAndActionIDs(t *testing.T) {
	code, serverErr := parseAuthCodeConsent("0:{\"success\":false,\"error\":\"Access denied\"}\n")
	if code != "" || serverErr != "Access denied" {
		t.Fatalf("deny = %q %q", code, serverErr)
	}
	code, serverErr = parseAuthCodeConsent("2:{\"code\":\"abc\",\"success\":true}")
	if code != "abc" || serverErr != "" {
		t.Fatalf("allow = %q %q", code, serverErr)
	}
	ids := extractAuthCodeActionIDs([]byte(`createServerReference("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")`))
	if len(ids) != 1 || ids[0] != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Fatalf("ids = %#v", ids)
	}
	if authCodeScriptURL("https://example.com/chunk.js") != "" {
		t.Fatal("external script URL was accepted")
	}
}

func testBuildJWT(payload string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none"}`)) + "." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".x"
}

func mustAuthCodeVerifier(t *testing.T, request *http.Request) string {
	t.Helper()
	body, err := io.ReadAll(request.Body)
	if err != nil {
		t.Fatal(err)
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		t.Fatal(err)
	}
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "auth-code" || form.Get("redirect_uri") != ssoAuthCodeRedirect {
		t.Fatalf("token form = %v", form)
	}
	if request.Header.Get("X-Grok-Client-Version") != ssoAuthCodeVersion {
		t.Fatalf("token version = %q", request.Header.Get("X-Grok-Client-Version"))
	}
	return form.Get("code_verifier")
}
