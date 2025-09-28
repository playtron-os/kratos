// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package session

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"github.com/gofrs/uuid"
	"github.com/pkg/errors"
	"github.com/tidwall/gjson"

	"github.com/ory/herodot"
	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/x/logrusx"
)

func bearerTokenFromRequest(r *http.Request) (string, bool) {
	parts := strings.Split(r.Header.Get("Authorization"), " ")

	if len(parts) == 2 && strings.ToLower(parts[0]) == "bearer" {
		return parts[1], true
	}

	return "", false
}

type MFAAutoAdditionDependencies interface {
	PrivilegedIdentityPool() identity.PrivilegedPool
	IdentityManager() *identity.Manager
	Logger() *logrusx.Logger
}

// AutoAddMFACodeMethod automatically adds MFA code method to an identity if it doesn't have any
// when AAL2 is requested or when highest available AAL is requested.
func AutoAddMFACodeMethod(ctx context.Context, deps MFAAutoAdditionDependencies, identityID uuid.UUID, requestedAAL string) (*identity.Identity, error) {
	if requestedAAL != config.HighestAvailableAAL && requestedAAL != string(identity.AuthenticatorAssuranceLevel2) {
		return nil, nil
	}

	// Fetch the identity with all credentials
	i, err := deps.PrivilegedIdentityPool().GetIdentity(ctx, identityID, identity.ExpandEverything)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to fetch identity: %s", err))
	}

	// Check if identity already has MFA code method
	_, ok := i.GetCredentials(identity.CredentialsTypeCodeAuth)
	if ok {
		return i, nil // Already has MFA code method
	}

	deps.Logger().Infof("Auto-adding MFA code method to identity %s because it does not have any", identityID)

	// Extract email from traits
	email := gjson.GetBytes(i.Traits, "email").String()
	if email == "" {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to extract email from identity traits"))
	}

	// Create code credentials
	cred := identity.CredentialsCode{
		Addresses: []identity.CredentialsCodeAddress{
			{Channel: identity.CodeChannelEmail, Address: email},
		},
	}
	co, err := json.Marshal(&cred)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to encode code credentials to JSON: %s", err))
	}

	// Add the credentials to the identity
	i.UpsertCredentialsConfig(identity.CredentialsTypeCodeAuth, co, 0)

	// Update the identity in the database
	err = deps.IdentityManager().Update(ctx, i, identity.ManagerAllowWriteProtectedTraits)
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithWrap(err).WithReason("failed to update identity"))
	}

	// Refresh available AAL
	if err := deps.IdentityManager().RefreshAvailableAAL(ctx, i); err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithWrap(err).WithReason("failed to refresh available AAL"))
	}

	return i, nil
}
