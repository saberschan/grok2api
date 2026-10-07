package cli

import (
	"context"
	"net/http"
	"testing"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	infraegress "github.com/chenyme/grok2api/backend/internal/infra/egress"
)

func TestOAuthRefreshRequestIsNarrowlyMatched(t *testing.T) {
	ctx := infraegress.WithOAuthAccount(context.Background(), 42)
	tests := []struct {
		name   string
		method string
		url    string
		marked bool
		want   bool
	}{
		{name: "refresh token endpoint", method: http.MethodPost, url: "https://auth.x.ai/oauth2/token", marked: true, want: true},
		{name: "other auth endpoint", method: http.MethodPost, url: "https://auth.x.ai/oauth2/device/code", marked: true},
		{name: "other auth subdomain", method: http.MethodPost, url: "https://login.auth.x.ai/oauth2/token", marked: true},
		{name: "host suffix attack", method: http.MethodPost, url: "https://auth.x.ai.attacker.invalid/oauth2/token", marked: true},
		{name: "wrong scheme", method: http.MethodPost, url: "http://auth.x.ai/oauth2/token", marked: true},
		{name: "wrong method", method: http.MethodGet, url: "https://auth.x.ai/oauth2/token", marked: true},
		{name: "ordinary request without refresh identity", method: http.MethodPost, url: "https://auth.x.ai/oauth2/token"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, err := http.NewRequest(test.method, test.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			requestCtx := context.Background()
			if test.marked {
				requestCtx = ctx
			}
			if got := isOAuthRefreshRequest(request.WithContext(requestCtx)); got != test.want {
				t.Fatalf("isOAuthRefreshRequest() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestOAuthRefreshContextPreservesPrimaryEgressIdentity(t *testing.T) {
	credential := account.Credential{ID: 42, Provider: account.ProviderBuild, EgressNodeID: 17}
	ctx := infraegress.WithOAuthAccount(infraegress.WithCredential(context.Background(), credential), credential.ID)
	if got := infraegress.OAuthAccountFromContext(ctx); got != credential.ID {
		t.Fatalf("OAuth account identity = %d, want %d", got, credential.ID)
	}
	if got := infraegress.EgressNodeFromContext(ctx); got != credential.EgressNodeID {
		t.Fatalf("primary egress node = %d, want %d", got, credential.EgressNodeID)
	}
	if got := infraegress.AccountFromContext(ctx); got == "" {
		t.Fatal("primary account affinity was lost from refresh context")
	}
}
func TestDeviceOAuthAdapterMarksStartAndPollForOAuthEgress(t *testing.T) {
	var paths []string
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if !infraegress.OAuthDeviceFlowFromContext(request.Context()) {
			t.Fatalf("device OAuth request %s was not marked for the OAuth egress pool", request.URL.Path)
		}
		paths = append(paths, request.URL.Path)
		switch request.URL.Path {
		case "/oauth2/device/code":
			return oauthResponse(http.StatusOK, `{"device_code":"device","user_code":"ABCD-EFGH","verification_uri":"https://auth.x.ai/activate","interval":1,"expires_in":1800}`), nil
		case "/oauth2/token":
			return oauthResponse(http.StatusOK, `{"access_token":"access","refresh_token":"refresh","expires_in":3600}`), nil
		default:
			t.Fatalf("unexpected OAuth path %q", request.URL.Path)
			return nil, nil
		}
	})}
	adapter := &Adapter{oauth: newOAuthClient(httpClient, nil)}
	authorization, err := adapter.StartDeviceAuthorization(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	seed, err := adapter.PollDeviceAuthorization(context.Background(), authorization.DeviceCode)
	if err != nil {
		t.Fatal(err)
	}
	if seed.AccessToken != "access" || len(paths) != 2 || paths[0] != "/oauth2/device/code" || paths[1] != "/oauth2/token" {
		t.Fatalf("seed=%#v paths=%v", seed, paths)
	}
}
