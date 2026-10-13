// Copyright © 2026 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package session_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/identity"
	"github.com/ory/kratos/pkg"
	"github.com/ory/kratos/pkg/testhelpers"
	"github.com/ory/kratos/session"
	"github.com/ory/kratos/x"
	"github.com/ory/x/configx"
)

// Playtron adds email-code MFA to identities that lack it.
func TestAutoAddMFACodeMethod(t *testing.T) {
	t.Parallel()

	// The stub schema doesn't make the email a code identifier, unlike Playtron's.
	_, reg := pkg.NewFastRegistryWithMocks(t, configx.WithValues(testhelpers.DefaultIdentitySchemaConfig("file://./stub/identity.schema.json")))
	ctx := t.Context()

	create := func(t *testing.T, traits string) *identity.Identity {
		i := identity.NewIdentity(config.DefaultIdentityTraitsSchemaID)
		i.Traits = identity.Traits(traits)
		require.NoError(t, reg.IdentityManager().Create(ctx, i))
		return i
	}

	t.Run("case=adds the account email as a code identifier", func(t *testing.T) {
		email := "Auto-MFA-" + x.NewUUID().String() + "@ory.sh"
		i := create(t, `{"email":"`+email+`"}`)

		_, err := session.AutoAddMFACodeMethod(ctx, reg, i.ID, config.HighestAvailableAAL)
		require.NoError(t, err)

		stored, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
		require.NoError(t, err)
		code, ok := stored.GetCredentials(identity.CredentialsTypeCodeAuth)
		require.True(t, ok)
		assert.Equal(t, []string{x.NormalizeEmailIdentifier(email)}, code.Identifiers)
		assert.Contains(t, string(code.Config), x.NormalizeEmailIdentifier(email))

		found, _, err := reg.PrivilegedIdentityPool().FindByCredentialsIdentifier(ctx, identity.CredentialsTypeCodeAuth, x.NormalizeEmailIdentifier(email))
		require.NoError(t, err)
		assert.Equal(t, i.ID, found.ID)
	})

	t.Run("case=leaves an identity without an email alone", func(t *testing.T) {
		i := create(t, `{}`)

		updated, err := session.AutoAddMFACodeMethod(ctx, reg, i.ID, config.HighestAvailableAAL)
		require.NoError(t, err)
		assert.Nil(t, updated)

		stored, err := reg.PrivilegedIdentityPool().GetIdentityConfidential(ctx, i.ID)
		require.NoError(t, err)
		_, ok := stored.GetCredentials(identity.CredentialsTypeCodeAuth)
		assert.False(t, ok)
	})

	t.Run("case=does nothing for aal1", func(t *testing.T) {
		i := create(t, `{"email":"`+x.NewUUID().String()+`@ory.sh"}`)

		updated, err := session.AutoAddMFACodeMethod(ctx, reg, i.ID, string(identity.AuthenticatorAssuranceLevel1))
		require.NoError(t, err)
		assert.Nil(t, updated)
	})
}
