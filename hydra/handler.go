package hydra

import (
	"encoding/json"
	"net/http"

	"github.com/ory/kratos/selfservice/sessiontokenexchange"
	"github.com/ory/kratos/session"

	"github.com/julienschmidt/httprouter"
	"github.com/pkg/errors"

	"github.com/ory/x/decoderx"
	"github.com/ory/x/errorsx"

	"github.com/ory/herodot"

	"github.com/ory/kratos/driver/config"
	"github.com/ory/kratos/x"
)

type (
	handlerDependencies interface {
		x.WriterProvider
		x.TracingProvider
		x.LoggingProvider
		config.Provider
		sessiontokenexchange.PersistenceProvider
		Provider
		session.ManagementProvider
	}
	Handler struct {
		r  handlerDependencies
		dx *decoderx.HTTP
	}
)

func NewHandler(
	r handlerDependencies,
) *Handler {
	return &Handler{
		r:  r,
		dx: decoderx.NewHTTP(),
	}
}

const (
	Route              = "/hydra"
	RouteExchangeToken = Route + "/token-exchange"
)

func (h *Handler) RegisterPublicRoutes(router *x.RouterPublic) {
	router.GET(RouteExchangeToken, h.exchangeToken)
}

func (h *Handler) exchangeToken(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	ctx, span := h.r.Tracer(r.Context()).Tracer().Start(r.Context(), "hydra.Handler.exchangeToken")
	defer span.End()

	clientID := r.URL.Query().Get("client_id")
	nonce := r.URL.Query().Get("nonce")

	if clientID == "" {
		h.r.Writer().WriteError(w, r, errorsx.WithStack(herodot.ErrBadRequest.WithReason("client_id is required")))
		return
	}

	s, err := h.r.SessionManager().FetchFromRequest(ctx, r)
	c := h.r.Config()
	if err != nil {
		h.r.Audit().WithRequest(r).WithError(err).Info("No valid session found.")
		h.r.Writer().WriteError(w, r, session.ErrNoSessionFound.WithWrap(err))
		return
	}

	var aalErr *session.ErrAALNotSatisfied
	if err := h.r.SessionManager().DoesSessionSatisfy(r, s, c.SessionWhoAmIAAL(ctx),
		// For the time being we want to update the AAL in the database if it is unset.
		session.UpsertAAL,
	); errors.As(err, &aalErr) {
		h.r.Audit().WithRequest(r).WithError(err).Info("Session was found but AAL is not satisfied for calling this endpoint.")
		h.r.Writer().WriteError(w, r, err)
		return
	} else if err != nil {
		h.r.Audit().WithRequest(r).WithError(err).Info("No valid session cookie found.")
		h.r.Writer().WriteError(w, r, herodot.ErrUnauthorized.WithWrap(err).WithReasonf("Unable to determine AAL."))
		return
	}

	// s.Devices = nil
	s.Identity = s.Identity.CopyWithoutCredentials()

	jwt, err := h.r.Hydra().ExchangeTokenForHydraJWT(ctx, s.Identity.ID.String(), clientID, s.ExpiresAt.Unix(), nonce)
	if err != nil {
		h.r.Writer().WriteError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"tokenized": jwt,
	})
}
