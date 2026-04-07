package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"golang.org/x/oauth2"

	"github.com/obot-platform/discobot/server/internal/model"
	"github.com/obot-platform/discobot/server/internal/service"
)

// AuthLogin handles OIDC login redirect
func (h *Handler) AuthLogin(w http.ResponseWriter, r *http.Request) {
	// If auth is disabled, redirect to home
	if !h.cfg.AuthEnabled {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Generate state for CSRF protection
	state, err := service.GenerateState()
	if err != nil {
		h.Error(w, http.StatusInternalServerError, "Failed to generate state")
		return
	}

	// Store state in cookie
	h.setStateCookie(w, state)
	if returnTo := h.sanitizeReturnTo(r.URL.Query().Get("return_to")); returnTo != "" {
		h.setReturnToCookie(w, returnTo)
	}

	// Build redirect URL
	redirectURL := h.cfg.PublicBaseURL() + "/auth/callback"

	var authURL string
	nonce, nonceErr := service.GenerateState()
	if nonceErr != nil {
		h.Error(w, http.StatusInternalServerError, "Failed to generate nonce")
		return
	}
	verifier := oauth2.GenerateVerifier()
	challenge := oauth2.S256ChallengeFromVerifier(verifier)
	h.setNonceCookie(w, nonce)
	h.setPKCEVerifierCookie(w, verifier)
	authURL, err = h.authService.GetOIDCAuthURL(r.Context(), redirectURL, state, nonce, challenge)
	if err != nil {
		h.Error(w, http.StatusBadRequest, err.Error())
		return
	}

	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// AuthCallback handles OIDC callback
func (h *Handler) AuthCallback(w http.ResponseWriter, r *http.Request) {
	// If auth is disabled, redirect to home
	if !h.cfg.AuthEnabled {
		http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
		return
	}

	// Verify state
	state := r.URL.Query().Get("state")
	savedState := h.getStateCookie(w, r)
	if state == "" || state != savedState {
		h.Error(w, http.StatusBadRequest, "Invalid state parameter")
		return
	}

	// Check for error from provider
	if errMsg := r.URL.Query().Get("error"); errMsg != "" {
		errDesc := r.URL.Query().Get("error_description")
		h.Error(w, http.StatusBadRequest, fmt.Sprintf("OAuth error: %s - %s", errMsg, errDesc))
		return
	}

	// Get authorization code
	code := r.URL.Query().Get("code")
	if code == "" {
		h.Error(w, http.StatusBadRequest, "Missing authorization code")
		return
	}

	// Build redirect URL (must match the one used in login)
	redirectURL := h.cfg.PublicBaseURL() + "/auth/callback"

	var (
		providerUser *service.User
		err          error
	)
	nonce := h.getNonceCookie(w, r)
	verifier := h.getPKCEVerifierCookie(w, r)
	if nonce == "" || verifier == "" {
		h.Error(w, http.StatusBadRequest, "Missing OIDC login state")
		return
	}
	providerUser, err = h.authService.ExchangeOIDCCode(r.Context(), redirectURL, code, nonce, verifier)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, fmt.Sprintf("Failed to exchange code: %v", err))
		return
	}

	// Create or update user in database
	user, err := h.authService.CreateOrUpdateUser(r.Context(), providerUser)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, fmt.Sprintf("Failed to save user: %v", err))
		return
	}

	// Create session
	token, err := h.authService.CreateSession(r.Context(), user.ID)
	if err != nil {
		h.Error(w, http.StatusInternalServerError, fmt.Sprintf("Failed to create session: %v", err))
		return
	}

	// Set session cookie
	h.setSessionCookie(w, token)

	returnTo := h.sanitizeReturnTo(h.getReturnToCookie(w, r))
	if returnTo == "" {
		returnTo = "/"
	}

	// Redirect to frontend
	http.Redirect(w, r, returnTo, http.StatusTemporaryRedirect)
}

// sanitizeReturnTo restricts post-login redirects to relative paths or allowed same-origin UI URLs.
func (h *Handler) sanitizeReturnTo(returnTo string) string {
	trimmed := strings.TrimSpace(returnTo)
	if trimmed == "" {
		return ""
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return ""
	}

	if !parsed.IsAbs() {
		if strings.HasPrefix(trimmed, "//") || !strings.HasPrefix(trimmed, "/") {
			return ""
		}
		return trimmed
	}

	publicURL, err := url.Parse(h.cfg.PublicBaseURL())
	if err != nil || publicURL.Host == "" {
		return ""
	}

	if !sameOriginUIHost(parsed.Host, publicURL.Host) {
		return ""
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return ""
	}
	return parsed.String()
}

func sameOriginUIHost(returnToHost, publicHost string) bool {
	returnToHost = strings.ToLower(returnToHost)
	publicHost = strings.ToLower(publicHost)
	if returnToHost == publicHost {
		return true
	}
	uiHost := strings.Replace(publicHost, "-svc-api.", "-svc-ui.", 1)
	if returnToHost == uiHost {
		return true
	}
	uiSvelteHost := strings.Replace(publicHost, "-svc-api.", "-svc-ui-svelte.", 1)
	return returnToHost == uiSvelteHost
}

// AuthLogout handles user logout
func (h *Handler) AuthLogout(w http.ResponseWriter, r *http.Request) {
	// If auth is disabled, just return success (no sessions to clear)
	if !h.cfg.AuthEnabled {
		h.JSON(w, http.StatusOK, map[string]bool{"success": true})
		return
	}

	token := h.getSessionToken(r)
	if token != "" {
		// Delete session from database
		_ = h.authService.DeleteSession(r.Context(), token)
	}

	// Clear session cookie
	h.clearSessionCookie(w)

	h.JSON(w, http.StatusOK, map[string]bool{"success": true})
}

// AuthMe returns current user info
func (h *Handler) AuthMe(w http.ResponseWriter, r *http.Request) {
	// If auth is disabled, return anonymous user
	if !h.cfg.AuthEnabled {
		h.JSON(w, http.StatusOK, &service.User{
			ID:    model.AnonymousUserID,
			Email: model.AnonymousUserEmail,
			Name:  model.AnonymousUserName,
		})
		return
	}

	token := h.getSessionToken(r)
	if token == "" {
		h.Error(w, http.StatusUnauthorized, "Not authenticated")
		return
	}

	user, err := h.authService.ValidateSession(r.Context(), token)
	if err != nil {
		h.clearSessionCookie(w)
		h.Error(w, http.StatusUnauthorized, "Session expired")
		return
	}

	h.JSON(w, http.StatusOK, user)
}
