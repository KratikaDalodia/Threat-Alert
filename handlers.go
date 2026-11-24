package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
)

type Server struct {
	store *Store
}

func NewServer() *Server {
	return &Server{store: NewStore()}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /register", s.register)
	mux.HandleFunc("POST /users", s.addUser)
	mux.HandleFunc("POST /apps", s.addApp)
	mux.HandleFunc("POST /alerts", s.reportAlert)
	mux.HandleFunc("GET /alerts", s.listAlerts)
	mux.HandleFunc("GET /alerts/{id}", s.getAlert)
	mux.HandleFunc("POST /alerts/{id}/resolve", s.resolveAlert)
	return mux
}

// ---------- helpers ----------

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// decodeBody writes a 400 and returns false if the body is not valid JSON.
func decodeBody(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	dec := json.NewDecoder(r.Body)
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	// A second Decode must hit end-of-body; anything else means trailing data.
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return false
	}
	return true
}

// authUser checks "Authorization: Bearer <token>". Writes 401 on failure.
func (s *Server) authUser(w http.ResponseWriter, r *http.Request) (User, bool) {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if len(h) <= len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		writeError(w, http.StatusUnauthorized, "missing or invalid token")
		return User{}, false
	}
	u, ok := s.store.UserByToken(h[len(prefix):])
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing or invalid token")
		return User{}, false
	}
	return u, true
}

// authAdmin = authUser (401) then role check (403).
func (s *Server) authAdmin(w http.ResponseWriter, r *http.Request) (User, bool) {
	u, ok := s.authUser(w, r)
	if !ok {
		return User{}, false
	}
	if u.Role != "admin" {
		writeError(w, http.StatusForbidden, "only an admin can do this")
		return User{}, false
	}
	return u, true
}

func validPerson(name, email string) bool {
	return strings.TrimSpace(name) != "" && strings.Contains(email, "@")
}

// ---------- handlers ----------

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var in struct {
		OrgName string `json:"orgName"`
		Name    string `json:"name"`
		Email   string `json:"email"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.OrgName) == "" || !validPerson(in.Name, in.Email) {
		writeError(w, http.StatusBadRequest, "orgName and name are required, email must contain @")
		return
	}
	writeJSON(w, http.StatusCreated, s.store.Register(in.OrgName, in.Name, in.Email))
}

func (s *Server) addUser(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.authAdmin(w, r)
	if !ok {
		return
	}
	var in struct {
		Name  string `json:"name"`
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	if !validPerson(in.Name, in.Email) {
		writeError(w, http.StatusBadRequest, "name is required, email must contain @")
		return
	}
	if in.Role != "admin" && in.Role != "viewer" {
		writeError(w, http.StatusBadRequest, "role must be admin or viewer")
		return
	}
	writeJSON(w, http.StatusCreated, s.store.AddUser(admin.OrgID, in.Name, in.Email, in.Role))
}

func (s *Server) addApp(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.authAdmin(w, r)
	if !ok {
		return
	}
	var in struct {
		Name     string `json:"name"`
		Platform string `json:"platform"`
	}
	if !decodeBody(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.Name) == "" {
		writeError(w, http.StatusBadRequest, "name is required")
		return
	}
	if in.Platform != "android" && in.Platform != "ios" {
		writeError(w, http.StatusBadRequest, "platform must be android or ios")
		return
	}
	writeJSON(w, http.StatusCreated, s.store.AddApp(admin.OrgID, in.Name, in.Platform))
}

func (s *Server) reportAlert(w http.ResponseWriter, r *http.Request) {
	app, ok := s.store.AppByKey(r.Header.Get("X-App-Key"))
	if !ok {
		writeError(w, http.StatusUnauthorized, "missing or invalid app key")
		return
	}
	var in struct {
		DeviceID   string          `json:"deviceId"`
		ThreatType string          `json:"threatType"`
		Severity   json.RawMessage `json:"severity"` // raw, so "5" or 4.5 are rejected
	}
	if !decodeBody(w, r, &in) {
		return
	}
	if strings.TrimSpace(in.DeviceID) == "" || strings.TrimSpace(in.ThreatType) == "" {
		writeError(w, http.StatusBadRequest, "deviceId and threatType are required")
		return
	}
	severity, err := strconv.Atoi(string(in.Severity)) // fails for "", null, "5", 4.5
	if err != nil || severity < 1 || severity > 5 {
		writeError(w, http.StatusBadRequest, "severity must be a whole number from 1 to 5")
		return
	}

	alert, created := s.store.ReportAlert(app, in.DeviceID, in.ThreatType, severity)
	if created {
		writeJSON(w, http.StatusCreated, alert)
	} else {
		writeJSON(w, http.StatusOK, alert)
	}
}

func (s *Server) listAlerts(w http.ResponseWriter, r *http.Request) {
	u, ok := s.authUser(w, r)
	if !ok {
		return
	}
	status := ""
	if r.URL.Query().Has("status") {
		status = r.URL.Query().Get("status")
		if status != "open" && status != "resolved" {
			writeError(w, http.StatusBadRequest, "status must be open or resolved")
			return
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"alerts": s.store.ListAlerts(u.OrgID, status)})
}

func (s *Server) getAlert(w http.ResponseWriter, r *http.Request) {
	u, ok := s.authUser(w, r)
	if !ok {
		return
	}
	a, found := s.store.GetAlert(u.OrgID, r.PathValue("id"))
	if !found {
		writeError(w, http.StatusNotFound, "alert not found")
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (s *Server) resolveAlert(w http.ResponseWriter, r *http.Request) {
	admin, ok := s.authAdmin(w, r)
	if !ok {
		return
	}
	a, err := s.store.Resolve(admin.OrgID, r.PathValue("id"), admin.UserID)
	switch err {
	case nil:
		writeJSON(w, http.StatusOK, a)
	case errResolved:
		writeError(w, http.StatusConflict, "alert is already resolved")
	default:
		writeError(w, http.StatusNotFound, "alert not found")
	}
}
