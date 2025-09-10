// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package x

import (
	"net/http"
	"path"
	"strings"
)

const AdminPrefix = "/admin"

func RedirectAdminMiddleware(rw http.ResponseWriter, r *http.Request, next http.HandlerFunc) {
	if !strings.HasPrefix(r.URL.Path, AdminPrefix) {
		target := r.URL
		target.Path = path.Join(AdminPrefix, r.URL.Path)
		http.Redirect(rw, r, target.String(), http.StatusTemporaryRedirect)
		return
	}
	next(rw, r)
}
