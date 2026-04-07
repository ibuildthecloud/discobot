package handler

import (
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/obot-platform/discobot/authservice/internal/config"
	"github.com/obot-platform/discobot/authservice/internal/model"
	"github.com/obot-platform/discobot/authservice/internal/service"
	"github.com/obot-platform/discobot/authservice/static"
)

const (
	sessionCookieName      = "discobot_auth_session"
	upstreamStateCookie    = "discobot_auth_upstream_state"
	upstreamProviderCookie = "discobot_auth_upstream_provider"
	upstreamReturnToCookie = "discobot_auth_upstream_return_to"
)

type Handler struct {
	cfg       *config.Config
	service   *service.Service
	loginTmpl *template.Template
}

func New(cfg *config.Config, svc *service.Service) *Handler {
	return &Handler{cfg: cfg, service: svc, loginTmpl: template.Must(template.ParseFS(static.Files, "login.html"))}
}

func (h *Handler) Router() http.Handler {
	r := chi.NewRouter()
	r.Get("/health", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(`{"status":"ok"}`)) })
	r.Get("/.well-known/openid-configuration", h.WellKnown)
	r.Get("/.well-known/jwks.json", h.JWKS)
	r.Get("/authorize", h.Authorize)
	r.Post("/token", h.Token)
	r.Get("/userinfo", h.UserInfo)
	r.Post("/register", h.RegisterClient)
	r.Get("/register/{clientID}", h.GetRegistration)
	r.Get("/login/{provider}", h.LoginStart)
	r.Get("/login/{provider}/callback", h.LoginCallback)
	return r
}

func (h *Handler) WellKnown(w http.ResponseWriter, _ *http.Request) {
	h.json(w, http.StatusOK, h.service.Metadata())
}

func (h *Handler) JWKS(w http.ResponseWriter, r *http.Request) {
	jwks, err := h.service.JWKS(r.Context())
	if err != nil {
		h.error(w, http.StatusInternalServerError, err)
		return
	}
	h.json(w, http.StatusOK, jwks)
}

func (h *Handler) Authorize(w http.ResponseWriter, r *http.Request) {
	req := service.AuthorizeRequest{
		ClientID:            r.URL.Query().Get("client_id"),
		RedirectURI:         r.URL.Query().Get("redirect_uri"),
		ResponseType:        r.URL.Query().Get("response_type"),
		Scope:               r.URL.Query().Get("scope"),
		State:               r.URL.Query().Get("state"),
		Nonce:               r.URL.Query().Get("nonce"),
		CodeChallenge:       r.URL.Query().Get("code_challenge"),
		CodeChallengeMethod: r.URL.Query().Get("code_challenge_method"),
	}
	client, err := h.service.GetAuthorizeClient(r.Context(), req)
	if err != nil {
		h.error(w, http.StatusBadRequest, err)
		return
	}
	user, err := h.currentUser(r)
	if err != nil || user == nil {
		if provider, ok := h.service.SingleProvider(); ok {
			http.Redirect(w, r, "/login/"+provider+"?return_to="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
			return
		}
		data := h.service.LoginPageData(r.URL.RequestURI())
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = h.loginTmpl.Execute(w, data)
		return
	}
	code, err := h.service.CreateAuthorizationCode(r.Context(), client, user, req)
	if err != nil {
		h.error(w, http.StatusInternalServerError, err)
		return
	}
	redirectURL, err := addQuery(req.RedirectURI, map[string]string{"code": code, "state": req.State})
	if err != nil {
		h.error(w, http.StatusInternalServerError, err)
		return
	}
	http.Redirect(w, r, redirectURL, http.StatusFound)
}

func (h *Handler) LoginStart(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	if !h.service.ProviderAvailable(provider) {
		h.error(w, http.StatusBadRequest, http.ErrNotSupported)
		return
	}
	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}
	state, err := service.GenerateState()
	if err != nil {
		h.error(w, http.StatusInternalServerError, err)
		return
	}
	h.setCookie(w, upstreamStateCookie, state, 600)
	h.setCookie(w, upstreamProviderCookie, provider, 600)
	h.setCookie(w, upstreamReturnToCookie, returnTo, 600)
	redirectURL := h.cfg.PublicBaseURL() + "/login/" + provider + "/callback"
	authURL, err := h.service.AuthorizationURL(provider, state, redirectURL)
	if err != nil {
		h.error(w, http.StatusBadRequest, err)
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (h *Handler) LoginCallback(w http.ResponseWriter, r *http.Request) {
	provider := chi.URLParam(r, "provider")
	state := r.URL.Query().Get("state")
	code := r.URL.Query().Get("code")
	if state == "" || code == "" || state != h.readCookie(r, upstreamStateCookie) || provider != h.readCookie(r, upstreamProviderCookie) {
		h.error(w, http.StatusBadRequest, http.ErrNoCookie)
		return
	}
	redirectURL := h.cfg.PublicBaseURL() + "/login/" + provider + "/callback"
	identity, err := h.service.ExchangeUpstreamIdentity(r.Context(), provider, code, redirectURL)
	if err != nil {
		h.error(w, http.StatusBadGateway, err)
		return
	}
	user, err := h.service.CreateOrUpdateUser(r.Context(), identity)
	if err != nil {
		h.error(w, http.StatusInternalServerError, err)
		return
	}
	token, err := h.service.CreateBrowserSession(r.Context(), user.ID)
	if err != nil {
		h.error(w, http.StatusInternalServerError, err)
		return
	}
	h.setCookie(w, sessionCookieName, token, int((24 * time.Hour).Seconds()))
	returnTo := h.readCookie(r, upstreamReturnToCookie)
	h.clearCookie(w, upstreamStateCookie)
	h.clearCookie(w, upstreamProviderCookie)
	h.clearCookie(w, upstreamReturnToCookie)
	if returnTo == "" {
		returnTo = "/"
	}
	http.Redirect(w, r, returnTo, http.StatusFound)
}

func (h *Handler) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		h.error(w, http.StatusBadRequest, err)
		return
	}
	clientID, clientSecret := clientCredentials(r)
	if clientID == "" {
		clientID = r.FormValue("client_id")
		clientSecret = r.FormValue("client_secret")
	}
	resp, err := h.service.ExchangeAuthorizationCode(r.Context(), clientID, clientSecret, r.FormValue("code"), r.FormValue("redirect_uri"), r.FormValue("code_verifier"))
	if err != nil {
		h.error(w, http.StatusBadRequest, err)
		return
	}
	h.json(w, http.StatusOK, resp)
}

func (h *Handler) UserInfo(w http.ResponseWriter, r *http.Request) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "Bearer ") {
		h.error(w, http.StatusUnauthorized, http.ErrNoCookie)
		return
	}
	info, err := h.service.UserInfoFromToken(r.Context(), strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		h.error(w, http.StatusUnauthorized, err)
		return
	}
	h.json(w, http.StatusOK, info)
}

func (h *Handler) RegisterClient(w http.ResponseWriter, r *http.Request) {
	var req service.ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.error(w, http.StatusBadRequest, err)
		return
	}
	resp, err := h.service.RegisterClient(r.Context(), req)
	if err != nil {
		h.error(w, http.StatusBadRequest, err)
		return
	}
	h.json(w, http.StatusCreated, resp)
}

func (h *Handler) GetRegistration(w http.ResponseWriter, r *http.Request) {
	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(auth, "Bearer ") {
		h.error(w, http.StatusUnauthorized, http.ErrNoCookie)
		return
	}
	resp, err := h.service.GetClientRegistration(r.Context(), chi.URLParam(r, "clientID"), strings.TrimPrefix(auth, "Bearer "))
	if err != nil {
		h.error(w, http.StatusUnauthorized, err)
		return
	}
	h.json(w, http.StatusOK, resp)
}

func (h *Handler) currentUser(r *http.Request) (*model.User, error) {
	token := h.readCookie(r, sessionCookieName)
	if token == "" {
		return nil, nil
	}
	return h.service.GetUserBySessionToken(r.Context(), token)
}

func (h *Handler) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: h.cfg.CookiesSecure(), SameSite: http.SameSiteLaxMode, MaxAge: maxAge})
}

func (h *Handler) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: "", Path: "/", HttpOnly: true, Secure: h.cfg.CookiesSecure(), MaxAge: -1})
}

func (h *Handler) readCookie(r *http.Request, name string) string {
	cookie, err := r.Cookie(name)
	if err != nil {
		return ""
	}
	return cookie.Value
}

func (h *Handler) json(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (h *Handler) error(w http.ResponseWriter, status int, err error) {
	h.json(w, status, map[string]string{"error": err.Error()})
}

func addQuery(rawURL string, values map[string]string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	query := parsed.Query()
	for key, value := range values {
		if value != "" {
			query.Set(key, value)
		}
	}
	parsed.RawQuery = query.Encode()
	return parsed.String(), nil
}

func clientCredentials(r *http.Request) (string, string) {
	username, password, ok := r.BasicAuth()
	if !ok {
		return "", ""
	}
	return username, password
}
