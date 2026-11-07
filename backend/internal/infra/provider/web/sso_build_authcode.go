package web

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	accountdomain "github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/infra/provider"
	"github.com/chenyme/grok2api/backend/internal/infra/security"
)

// Authorization Code + PKCE，对齐 grok-register sso_to_token_auth_code。
// consent 走 accounts.x.ai 的 Next.js Server Action，不经过 device/approve。
const (
	ssoAuthCodeScope       = "openid profile email offline_access grok-cli:access api:access"
	ssoAuthCodeRedirect    = "http://127.0.0.1:56121/callback"
	ssoAuthCodeReferrer    = "grok-build"
	ssoAuthCodePlan        = "generic"
	ssoAuthCodeVersion     = "0.2.93"
	ssoAuthCodeTokenUA     = "grok-pager/" + ssoAuthCodeVersion + " grok-shell/" + ssoAuthCodeVersion + " (linux; x86_64)"
	ssoAuthCodeAccounts    = "https://accounts.x.ai/"
	ssoAuthCodeAuthorize   = "https://auth.x.ai/oauth2/authorize"
	ssoAuthCodeBootstrap   = "401b73e22a5e68737d0037e1aa449fef82cd1b35fb"
	ssoAuthCodeKnownAction = "401ce882800a9c98c11b0066c135231259bc3b003a"
)

var (
	authCodeActionMu       sync.Mutex
	authCodeNextActionID   = ssoAuthCodeKnownAction
	authCodeActionIDRe     = regexp.MustCompile(`(?i)^[0-9a-f]{40,44}$`)
	authCodeCreateServerRe = regexp.MustCompile(`(?i)createServerReference\)?\(["']([0-9a-f]{40,44})["']`)
	authCodeCallServerRe   = regexp.MustCompile(`(?i)["']([0-9a-f]{40,44})["']\s*,\s*(?:callServer|findSourceMapURL)`)
	authCodeNextActionRe   = regexp.MustCompile(`(?i)(?:\$ACTION_ID_|next-action["']?\s*[:=]\s*["']|["'])([0-9a-f]{40,44})["']`)
	authCodeScriptSrcRe    = regexp.MustCompile(`(?i)src=["']([^"']+)["']`)
)

func (f *ssoBuildFlow) convertWithAuthCode(ctx context.Context, credential accountdomain.Credential) (provider.CredentialSeed, error) {
	status, finalURL, _, err := f.do(ctx, http.MethodGet, ssoAuthCodeAccounts, nil)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	if status == http.StatusUnauthorized || authCodeSessionRejected(finalURL) {
		return provider.CredentialSeed{}, provider.ErrUnauthorized
	}
	if status < 200 || status >= 300 {
		return provider.CredentialSeed{}, fmt.Errorf("检查 SSO 会话失败: %w", conversionHTTPError{status: status})
	}

	verifier, challenge, state, nonce, err := newAuthCodePKCE()
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	authorizeURL := ssoAuthCodeAuthorize + "?" + url.Values{
		"client_id":             {ssoBuildClientID},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
		"nonce":                 {nonce},
		"plan":                  {ssoAuthCodePlan},
		"redirect_uri":          {ssoAuthCodeRedirect},
		"referrer":              {ssoAuthCodeReferrer},
		"response_type":         {"code"},
		"scope":                 {ssoAuthCodeScope},
		"state":                 {state},
	}.Encode()

	consentURL, consentHTML, err := f.openAuthCodeConsent(ctx, authorizeURL)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	payload, err := json.Marshal([]authCodeConsentBody{{
		Action: "allow", ClientID: ssoBuildClientID, RedirectURI: ssoAuthCodeRedirect,
		Scope: ssoAuthCodeScope, State: state, CodeChallenge: challenge, CodeChallengeMethod: "S256",
		Nonce: nonce, PrincipalType: "User", PrincipalID: "", Referrer: ssoAuthCodeReferrer,
	}})
	if err != nil {
		return provider.CredentialSeed{}, err
	}

	code, err := f.submitAuthCodeConsent(ctx, authorizeURL, consentURL, consentHTML, payload)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	token, err := f.exchangeAuthCode(ctx, code, verifier)
	if err != nil {
		return provider.CredentialSeed{}, err
	}
	return authCodeSeed(token, credential), nil
}

type authCodeConsentBody struct {
	Action              string `json:"action"`
	ClientID            string `json:"clientId"`
	RedirectURI         string `json:"redirectUri"`
	Scope               string `json:"scope"`
	State               string `json:"state"`
	CodeChallenge       string `json:"codeChallenge"`
	CodeChallengeMethod string `json:"codeChallengeMethod"`
	Nonce               string `json:"nonce"`
	PrincipalType       string `json:"principalType"`
	PrincipalID         string `json:"principalId"`
	Referrer            string `json:"referrer"`
}

func (f *ssoBuildFlow) openAuthCodeConsent(ctx context.Context, authorizeURL string) (string, []byte, error) {
	status, finalURL, body, err := f.do(ctx, http.MethodGet, authorizeURL, nil)
	if err != nil {
		return "", nil, err
	}
	if authCodeSessionRejected(finalURL) {
		return "", nil, provider.ErrUnauthorized
	}
	if status < 200 || status >= 300 || !strings.Contains(finalURL, "/oauth2/consent") {
		return "", nil, fmt.Errorf("authorize 未进入 consent: %s", finalURL)
	}
	return finalURL, body, nil
}

func (f *ssoBuildFlow) submitAuthCodeConsent(ctx context.Context, authorizeURL, consentURL string, consentHTML, payload []byte) (string, error) {
	tried := map[string]struct{}{}
	var lastErr error
	for round := 0; round < 2; round++ {
		pageURL, pageHTML := consentURL, consentHTML
		var candidates []string
		if round == 0 {
			candidates = authCodeActionCandidates(pageHTML, false, nil)
		} else {
			var err error
			pageURL, pageHTML, err = f.openAuthCodeConsent(ctx, authorizeURL)
			if err != nil {
				return "", err
			}
			candidates = authCodeActionCandidates(pageHTML, true, f.discoverAuthCodeActions(ctx, pageHTML))
		}
		attempted := 0
		for _, actionID := range candidates {
			if _, seen := tried[actionID]; seen {
				continue
			}
			if attempted >= 8 {
				break
			}
			tried[actionID] = struct{}{}
			attempted++
			status, _, body, err := f.doAuthCodeRaw(ctx, http.MethodPost, pageURL, payload, true, map[string]string{
				"Content-Type": "text/plain;charset=UTF-8",
				"Accept":       "text/x-component",
				"Origin":       "https://accounts.x.ai",
				"Referer":      pageURL,
				"Next-Action":  actionID,
			})
			if err != nil {
				lastErr = err
				continue
			}
			text := string(body)
			if status == http.StatusNotFound || strings.Contains(strings.ToLower(text), "server action not found") {
				invalidateAuthCodeAction(actionID)
				lastErr = fmt.Errorf("Next-Action %s 无效: HTTP %d", actionID[:12], status)
				continue
			}
			if status < 200 || status >= 300 {
				lastErr = fmt.Errorf("xAI consent HTTP %d", status)
				continue
			}
			code, serverErr := parseAuthCodeConsent(text)
			if code != "" {
				rememberAuthCodeAction(actionID)
				return code, nil
			}
			if serverErr != "" {
				rememberAuthCodeAction(actionID)
				if strings.EqualFold(serverErr, "Access denied") {
					return "", provider.ErrAuthorizationDenied
				}
				return "", fmt.Errorf("xAI consent 拒绝: %s", serverErr)
			}
			lastErr = fmt.Errorf("Next-Action %s 未返回 authorization code", actionID[:12])
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("未解析到可用的 Next-Action")
	}
	return "", fmt.Errorf("SSO 授权码确认失败: %w", lastErr)
}

func (f *ssoBuildFlow) exchangeAuthCode(ctx context.Context, code, verifier string) (ssoBuildToken, error) {
	status, _, body, err := f.doWithFollowHeaders(ctx, http.MethodPost, ssoTokenURL, url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {ssoAuthCodeRedirect},
		"client_id":     {ssoBuildClientID},
		"code_verifier": {verifier},
	}, true, map[string]string{
		"User-Agent":            ssoAuthCodeTokenUA,
		"X-Grok-Client-Version": ssoAuthCodeVersion,
		"Accept":                "*/*",
	})
	if err != nil {
		return ssoBuildToken{}, err
	}
	var payload struct {
		AccessToken      string `json:"access_token"`
		RefreshToken     string `json:"refresh_token"`
		IDToken          string `json:"id_token"`
		ExpiresIn        int    `json:"expires_in"`
		Error            string `json:"error"`
		ErrorDescription string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return ssoBuildToken{}, fmt.Errorf("解析 xAI OAuth Token: %w", err)
	}
	if status < 200 || status >= 300 || payload.AccessToken == "" {
		return ssoBuildToken{}, fmt.Errorf("xAI OAuth Token 失败 (%s): %w", firstValue(payload.ErrorDescription, payload.Error), conversionHTTPError{status: status})
	}
	if payload.ExpiresIn <= 0 {
		payload.ExpiresIn = 3600
	}
	return ssoBuildToken{
		AccessToken: payload.AccessToken, RefreshToken: payload.RefreshToken, IDToken: payload.IDToken,
		ExpiresAt: time.Now().UTC().Add(time.Duration(payload.ExpiresIn) * time.Second),
	}, nil
}

func authCodeSeed(token ssoBuildToken, credential accountdomain.Credential) provider.CredentialSeed {
	claims := decodeBuildClaims(firstValue(token.IDToken, token.AccessToken))
	userID := claimString(claims, "sub")
	email := claimString(claims, "email")
	teamID := claimString(claims, "team_id")
	name := strings.TrimSpace(credential.Name)
	if name == "" {
		name = "Grok Web account"
	}
	return provider.CredentialSeed{
		Provider: accountdomain.ProviderBuild, AuthType: accountdomain.AuthTypeOAuth,
		Name: firstValue(email, name+" Build", userID, "Grok Build account"), Email: email, UserID: userID, TeamID: teamID,
		SourceKey: "sso-build:" + security.HashToken(token.AccessToken), OIDCClientID: ssoBuildClientID,
		AccessToken: token.AccessToken, RefreshToken: token.RefreshToken, ExpiresAt: token.ExpiresAt,
	}
}

func (f *ssoBuildFlow) doAuthCodeRaw(ctx context.Context, method, endpoint string, raw []byte, follow bool, headers map[string]string) (int, string, []byte, error) {
	if !safeXAIURL(endpoint) {
		return 0, "", nil, fmt.Errorf("xAI OAuth URL 不安全")
	}
	currentURL := endpoint
	currentMethod := method
	currentBody := raw
	for redirects := 0; redirects <= 8; redirects++ {
		var reader io.Reader
		if len(currentBody) > 0 && currentMethod != http.MethodGet && currentMethod != http.MethodHead {
			reader = bytes.NewReader(currentBody)
		}
		request, err := http.NewRequestWithContext(ctx, currentMethod, currentURL, reader)
		if err != nil {
			return 0, "", nil, err
		}
		request.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")
		request.Header.Set("User-Agent", f.userAgent)
		request.Header.Set("Cookie", f.cookieHeader())
		if currentMethod == method {
			for key, value := range headers {
				request.Header.Set(key, value)
			}
		}
		response, err := f.client.Do(request)
		if err != nil {
			return 0, "", nil, err
		}
		f.captureCookies(response)
		data, readErr := io.ReadAll(io.LimitReader(response.Body, maxAuthBody+1))
		_ = response.Body.Close()
		if readErr != nil {
			return response.StatusCode, currentURL, nil, readErr
		}
		if len(data) > maxAuthBody {
			return response.StatusCode, currentURL, nil, fmt.Errorf("xAI OAuth 响应超过 2 MiB")
		}
		if response.StatusCode < 300 || response.StatusCode > 399 {
			return response.StatusCode, currentURL, data, nil
		}
		location := strings.TrimSpace(response.Header.Get("Location"))
		if location == "" {
			return response.StatusCode, currentURL, data, fmt.Errorf("xAI OAuth 重定向缺少 Location")
		}
		base, _ := url.Parse(currentURL)
		next, err := url.Parse(location)
		if err != nil {
			return response.StatusCode, currentURL, data, err
		}
		currentURL = base.ResolveReference(next).String()
		if !safeXAIURL(currentURL) {
			return response.StatusCode, currentURL, data, fmt.Errorf("xAI OAuth 重定向到非受信域名")
		}
		if !follow {
			return response.StatusCode, currentURL, data, nil
		}
		if response.StatusCode == http.StatusSeeOther || ((response.StatusCode == http.StatusMovedPermanently || response.StatusCode == http.StatusFound) && currentMethod != http.MethodGet && currentMethod != http.MethodHead) {
			currentMethod = http.MethodGet
			currentBody = nil
		}
	}
	return 0, currentURL, nil, fmt.Errorf("xAI OAuth 重定向次数过多")
}

func (f *ssoBuildFlow) discoverAuthCodeActions(ctx context.Context, page []byte) []string {
	type scored struct {
		score int
		src   string
	}
	var srcs []scored
	for _, src := range authCodeScriptSrcRe.FindAllSubmatch(page, -1) {
		raw := string(src[1])
		low := strings.ToLower(raw)
		if !strings.Contains(low, "chunk") && !strings.Contains(low, "/_next/") {
			continue
		}
		score := 0
		for _, key := range []string{"consent", "oauth", "auth", "login", "sign"} {
			if strings.Contains(low, key) {
				score += 5
			}
		}
		srcs = append(srcs, scored{score: score, src: raw})
	}
	sort.Slice(srcs, func(i, j int) bool {
		if srcs[i].score == srcs[j].score {
			return srcs[i].src < srcs[j].src
		}
		return srcs[i].score > srcs[j].score
	})
	var found []string
	fetched := 0
	for _, src := range srcs {
		if fetched >= 40 {
			break
		}
		full := authCodeScriptURL(src.src)
		if full == "" {
			continue
		}
		status, _, body, err := f.do(ctx, http.MethodGet, full, nil)
		fetched++
		if err != nil || status < 200 || status >= 300 {
			continue
		}
		found = append(found, extractAuthCodeActionIDs(body)...)
	}
	return found
}

func authCodeActionCandidates(page []byte, discovered bool, extra []string) []string {
	var ordered []string
	seen := map[string]struct{}{}
	add := func(id string) {
		id = strings.ToLower(strings.TrimSpace(id))
		if !authCodeActionIDRe.MatchString(id) {
			return
		}
		if _, ok := seen[id]; ok {
			return
		}
		seen[id] = struct{}{}
		ordered = append(ordered, id)
	}
	if !discovered {
		add(currentAuthCodeAction())
		add(ssoAuthCodeBootstrap)
		for _, id := range extractAuthCodeActionIDs(page) {
			add(id)
		}
		return ordered
	}
	for _, id := range extra {
		add(id)
	}
	for _, id := range extractAuthCodeActionIDs(page) {
		add(id)
	}
	if len(ordered) == 0 {
		add(currentAuthCodeAction())
		add(ssoAuthCodeBootstrap)
	}
	return ordered
}

func extractAuthCodeActionIDs(body []byte) []string {
	var ids []string
	seen := map[string]struct{}{}
	for _, re := range []*regexp.Regexp{authCodeCreateServerRe, authCodeCallServerRe, authCodeNextActionRe} {
		for _, match := range re.FindAllSubmatch(body, -1) {
			id := strings.ToLower(string(match[1]))
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			ids = append(ids, id)
		}
	}
	return ids
}

func authCodeScriptURL(src string) string {
	if strings.HasPrefix(src, "http://") || strings.HasPrefix(src, "https://") {
		if safeXAIURL(src) {
			return src
		}
		return ""
	}
	base, err := url.Parse("https://accounts.x.ai/")
	if err != nil {
		return ""
	}
	next, err := url.Parse(src)
	if err != nil {
		return ""
	}
	full := base.ResolveReference(next).String()
	if !safeXAIURL(full) {
		return ""
	}
	return full
}

func parseAuthCodeConsent(body string) (string, string) {
	serverErr := ""
	for _, line := range strings.Split(body, "\n") {
		start := strings.IndexByte(line, '{')
		if start < 0 {
			continue
		}
		var data map[string]any
		if json.Unmarshal([]byte(line[start:]), &data) != nil {
			continue
		}
		if code, _ := data["code"].(string); code != "" && data["success"] != false {
			return code, ""
		}
		if errText, _ := data["error"].(string); errText != "" {
			serverErr = errText
		} else if data["success"] == false && serverErr == "" {
			serverErr = "success=false"
		}
	}
	return "", serverErr
}

func authCodeSessionRejected(raw string) bool {
	parsed, err := url.Parse(raw)
	if err != nil {
		return true
	}
	path := strings.ToLower(parsed.EscapedPath())
	return strings.Contains(path, "sign-in") || strings.Contains(path, "sign-up")
}

func newAuthCodePKCE() (verifier, challenge, state, nonce string, err error) {
	verifier, err = authCodeRandom(32)
	if err != nil {
		return "", "", "", "", err
	}
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	state, err = authCodeRandom(16)
	if err != nil {
		return "", "", "", "", err
	}
	nonce, err = authCodeRandom(16)
	if err != nil {
		return "", "", "", "", err
	}
	return verifier, challenge, state, nonce, nil
}

func authCodeRandom(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func currentAuthCodeAction() string {
	authCodeActionMu.Lock()
	defer authCodeActionMu.Unlock()
	return authCodeNextActionID
}

func rememberAuthCodeAction(id string) {
	id = strings.ToLower(strings.TrimSpace(id))
	if !authCodeActionIDRe.MatchString(id) {
		return
	}
	authCodeActionMu.Lock()
	authCodeNextActionID = id
	authCodeActionMu.Unlock()
}

func invalidateAuthCodeAction(id string) {
	id = strings.ToLower(strings.TrimSpace(id))
	authCodeActionMu.Lock()
	if authCodeNextActionID == id {
		authCodeNextActionID = ""
	}
	authCodeActionMu.Unlock()
}
