// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hydra

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gofrs/uuid"

	"github.com/ory/x/httpx"
	"github.com/ory/x/sqlxx"

	"github.com/pkg/errors"

	"github.com/ory/herodot"
	hydraclientgo "github.com/ory/hydra-client-go/v2"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
)

type (
	hydraDependencies interface {
		config.Provider
		x.HTTPClientProvider
		session.ManagementProvider
		session.PersistenceProvider
		x.LoggingProvider
		identity.ManagementProvider
		identity.PoolProvider
	}
	Provider interface {
		Hydra() Hydra
	}
	AcceptLoginRequestParams struct {
		LoginChallenge        string
		ReturnTo              string
		IdentityID            string
		SessionID             string
		AuthenticationMethods session.AuthenticationMethods
	}
	Hydra interface {
		AcceptLoginRequest(ctx context.Context, params AcceptLoginRequestParams) (string, error)
		GetLoginRequest(ctx context.Context, loginChallenge string) (*hydraclientgo.OAuth2LoginRequest, error)
		ExchangeTokenForHydraJWT(ctx context.Context, subject, clientID string, expiresInSeconds int64, nonce string) (string, error)
	}
	DefaultHydra struct {
		d hydraDependencies
	}
)

func NewDefaultHydra(d hydraDependencies) *DefaultHydra {
	return &DefaultHydra{
		d: d,
	}
}

func GetLoginChallengeID(conf *config.Config, r *http.Request) (sqlxx.NullString, error) {
	if !r.URL.Query().Has("login_challenge") {
		return "", nil
	} else if conf.OAuth2ProviderURL(r.Context()) == nil {
		return "", errors.WithStack(herodot.ErrInternalServerError.WithReason("refusing to parse login_challenge query parameter because " + config.ViperKeyOAuth2ProviderURL + " is invalid or unset"))
	}

	loginChallenge := r.URL.Query().Get("login_challenge")
	if loginChallenge == "" {
		return "", errors.WithStack(herodot.ErrBadRequest.WithReason("the login_challenge parameter is present but empty"))
	}

	return sqlxx.NullString(loginChallenge), nil
}

func (h *DefaultHydra) getAdminURL(ctx context.Context) (string, error) {
	u := h.d.Config().OAuth2ProviderURL(ctx)
	if u == nil {
		return "", errors.WithStack(herodot.ErrInternalServerError.WithReason(config.ViperKeyOAuth2ProviderURL + " is not configured"))
	}
	return u.String(), nil
}

func (h *DefaultHydra) getAdminAPIClient(ctx context.Context) (hydraclientgo.OAuth2API, error) {
	url, err := h.getAdminURL(ctx)
	if err != nil {
		return nil, err
	}

	configuration := hydraclientgo.NewConfiguration()
	configuration.Servers = hydraclientgo.ServerConfigurations{{URL: url}}

	client := h.d.HTTPClient(ctx).StandardClient()
	if header := h.d.Config().OAuth2ProviderHeader(ctx); header != nil {
		client.Transport = httpx.WrapTransportWithHeader(client.Transport, header)
	}

	configuration.HTTPClient = client
	return hydraclientgo.NewAPIClient(configuration).OAuth2API, nil
}

func (h *DefaultHydra) AcceptLoginRequest(ctx context.Context, params AcceptLoginRequestParams) (string, error) {
	remember := h.d.Config().SessionPersistentCookie(ctx)
	rememberFor := int64(h.d.Config().SessionLifespan(ctx) / time.Second)

	alr := hydraclientgo.NewAcceptOAuth2LoginRequest(params.IdentityID)
	alr.IdentityProviderSessionId = &params.SessionID
	alr.Remember = &remember
	alr.RememberFor = &rememberFor
	alr.Amr = []string{}
	for _, r := range params.AuthenticationMethods {
		alr.Amr = append(alr.Amr, string(r.Method))
	}

	aa, err := h.getAdminAPIClient(ctx)
	if err != nil {
		return "", err
	}

	sID, err := uuid.FromString(params.SessionID)
	if err != nil {
		return "", errors.WithStack(herodot.ErrBadRequest.WithReason("invalid session ID"))
	}

	expandables := []session.Expandable{session.ExpandSessionIdentity, session.ExpandSessionIdentityCredentials}
	sess, err := h.d.SessionPersister().GetSession(ctx, sID, expandables)
	if err != nil {
		return "", errors.WithStack(herodot.ErrBadRequest.WithReason("session not found"))
	}

	var aalErr *session.ErrAALNotSatisfied
	if err = h.d.SessionManager().DoesSessionSatisfy(ctx, sess, config.HighestAvailableAAL); errors.As(err, &aalErr) {
		if aalErr.PassReturnToAndLoginChallengeParametersDirect(params.LoginChallenge, params.ReturnTo) != nil {
			_ = aalErr.WithDetail("pass_request_params_error", "failed to pass request parameters to aalErr.RedirectTo")
		}
		h.d.Audit().WithError(err).Warnf("Session was found but AAL is not satisfied for logging in with hydra for Identity=%s.", sess.IdentityID)
		return aalErr.RedirectTo, nil
	}

	resp, r, err := aa.AcceptOAuth2LoginRequest(ctx).LoginChallenge(params.LoginChallenge).AcceptOAuth2LoginRequest(*alr).Execute()
	if err != nil {
		innerErr := herodot.ErrInternalServerError.WithWrap(err).WithReasonf("Unable to accept OAuth 2.0 Login Challenge.")
		if r != nil {
			innerErr = innerErr.
				WithDetail("status_code", r.StatusCode).
				WithDebug(err.Error())
		}

		if openApiErr := new(hydraclientgo.GenericOpenAPIError); errors.As(err, &openApiErr) {
			switch oauth2Err := openApiErr.Model().(type) {
			case hydraclientgo.ErrorOAuth2:
				innerErr = innerErr.WithDetail("oauth2_error_hint", oauth2Err.GetErrorHint())
			case *hydraclientgo.ErrorOAuth2:
				innerErr = innerErr.WithDetail("oauth2_error_hint", oauth2Err.GetErrorHint())
			}
		}

		return "", errors.WithStack(innerErr)
	}

	return resp.RedirectTo, nil
}

func (h *DefaultHydra) GetLoginRequest(ctx context.Context, loginChallenge string) (*hydraclientgo.OAuth2LoginRequest, error) {
	if loginChallenge == "" {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReason("invalid login_challenge"))
	}

	aa, err := h.getAdminAPIClient(ctx)
	if err != nil {
		return nil, err
	}

	hlr, r, err := aa.GetOAuth2LoginRequest(ctx).LoginChallenge(loginChallenge).Execute()
	if err != nil {
		var innerErr *herodot.DefaultError
		if r == nil || r.StatusCode >= 500 {
			innerErr = &herodot.ErrInternalServerError
		} else {
			innerErr = &herodot.ErrBadRequest
		}
		innerErr = innerErr.WithReasonf("Unable to get OAuth 2.0 Login Challenge.")
		if r != nil {
			innerErr = innerErr.
				WithDetail("status_code", r.StatusCode).
				WithDebug(err.Error())
		}

		if openApiErr := new(hydraclientgo.GenericOpenAPIError); errors.As(err, &openApiErr) {
			switch oauth2Err := openApiErr.Model().(type) {
			case hydraclientgo.ErrorOAuth2:
				innerErr = innerErr.WithDetail("oauth2_error_hint", oauth2Err.GetErrorHint())
			case *hydraclientgo.ErrorOAuth2:
				innerErr = innerErr.WithDetail("oauth2_error_hint", oauth2Err.GetErrorHint())
			}
		}

		return nil, errors.WithStack(innerErr)
	}

	return hlr, nil
}

func (h *DefaultHydra) ExchangeTokenForHydraJWT(
	ctx context.Context,
	subject, clientID string,
	expiresInSeconds int64,
	nonce string,
) (string, error) {
	type requestBody struct {
		Subject  string                 `json:"subject"`
		ClientID string                 `json:"client_id"`
		Extra    map[string]interface{} `json:"extra,omitempty"`
		Exp      int64                  `json:"exp,omitempty"`
	}

	extra := map[string]interface{}{}
	if nonce != "" {
		extra["nonce"] = nonce
	}

	reqData := requestBody{
		Subject:  subject,
		ClientID: clientID,
		Exp:      expiresInSeconds,
	}

	if len(extra) > 0 {
		reqData.Extra = extra
	}

	bodyBytes, err := json.Marshal(reqData)
	if err != nil {
		return "", fmt.Errorf("failed to encode request: %w", err)
	}

	hydraAdminURL, err := h.getAdminURL(ctx)
	if err != nil {
		return "", fmt.Errorf("failed to get hydra admin url: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", fmt.Sprintf("%s/admin/sessions/token", hydraAdminURL), bytes.NewReader(bodyBytes))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("request to hydra failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("hydra responded with status: %s", resp.Status)
	}

	var parsed struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return parsed.Token, nil
}
