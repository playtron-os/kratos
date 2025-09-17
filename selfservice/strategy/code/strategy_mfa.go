// Copyright © 2024 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"encoding/json"

	"github.com/pkg/errors"

	"github.com/ory/herodot"
	"github.com/ory/kratos/identity"
)

func FindAllIdentifiers(i *identity.Identity) (result []Address) {
	for _, a := range i.VerifiableAddresses {
		if len(a.Via) == 0 || len(a.Value) == 0 {
			continue
		}

		result = append(result, Address{Via: identity.CodeChannel(a.Via), To: a.Value})
	}
	return result
}

func FindCodeAddressCandidates(i *identity.Identity, fallbackEnabled bool) (result []Address, found bool, _ error) {
	// If no hint was given, we show all OTP addresses from the credentials.
	creds, ok := i.GetCredentials(identity.CredentialsTypeCodeAuth)
	if !ok {
		if !fallbackEnabled {
			// Without a fallback and with no credentials found, we can't really do a lot and exit early.
			return nil, false, nil
		}

		return FindAllIdentifiers(i), true, nil
	} else {
		var conf identity.CredentialsCode
		if len(creds.Config) > 0 {
			if err := json.Unmarshal(creds.Config, &conf); err != nil {
				return nil, false, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Unable to unmarshal credentials config: %s", err))
			}
		}

		if len(conf.Addresses) == 0 {
			if !fallbackEnabled {
				// Without a fallback and with no credentials found, we can't really do a lot and exit early.
				return nil, false, nil
			}

			return FindAllIdentifiers(i), true, nil
		}

		addressMap := make(map[Address]struct{})
		for _, addr := range conf.Addresses {
			if len(addr.Address) == 0 || len(addr.Channel) == 0 {
				continue
			}
			addressMap[Address{Via: addr.Channel, To: addr.Address}] = struct{}{}
		}
		for addr := range addressMap {
			result = append(result, addr)
		}
		return result, true, nil
	}
}
