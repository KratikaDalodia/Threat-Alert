package main

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

var (
	errNotFound = errors.New("not found")
	errResolved = errors.New("alert already resolved")
)

type User struct {
	UserID string `json:"userId"`
	OrgID  string `json:"orgId"`
	Name   string `json:"name"`
	Email  string `json:"email"`
	Role   string `json:"role"`
	Token  string `json:"token"`
}

type App struct {
	AppID    string `json:"appId"`
	Name     string `json:"name"`
	Platform string `json:"platform"`
	AppKey   string `json:"appKey"`
	orgID    string // unexported: never sent in JSON
}

type Alert struct {
	ID         string `json:"id"`
	AppID      string `json:"appId"`
	DeviceID   string `json:"deviceId"`
	ThreatType string `json:"threatType"`
	Severity   int    `json:"severity"`
	Count      int    `json:"count"`
	Status     string `json:"status"`
	FirstSeen  string `json:"firstSeen"`
	LastSeen   string `json:"lastSeen"`
	ResolvedBy string `json:"resolvedBy"`

	// internal only (unexported, so not in JSON)
	orgID      string
	seq        int
	lastSeenAt time.Time
}

// alertKey identifies "the same alert" for repeat detection.
type alertKey struct {
	appID, deviceID, threatType string
}

// Store keeps all data in memory. ONE mutex guards every map and counter.
type Store struct {
	mu sync.Mutex

	orgSeq, userSeq, appSeq, alertSeq int

	orgs         map[string]string // orgID -> orgName
	usersByToken map[string]User
	appsByKey    map[string]App
	alerts       map[string]*Alert
	openAlerts   map[alertKey]*Alert // only OPEN alerts live here
}

func NewStore() *Store {
	return &Store{
		orgs:         map[string]string{},
		usersByToken: map[string]User{},
		appsByKey:    map[string]App{},
		alerts:       map[string]*Alert{},
		openAlerts:   map[alertKey]*Alert{},
	}
}

// newSecret returns 16 random bytes as 32 hex chars (rule R7).
func newSecret() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// newUser must be called with s.mu held.
func (s *Store) newUser(orgID, name, email, role string) User {
	s.userSeq++
	u := User{
		UserID: fmt.Sprintf("usr_%d", s.userSeq),
		OrgID:  orgID,
		Name:   name,
		Email:  email,
		Role:   role,
		Token:  newSecret(),
	}
	s.usersByToken[u.Token] = u
	return u
}

func (s *Store) Register(orgName, name, email string) User {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.orgSeq++
	orgID := fmt.Sprintf("org_%d", s.orgSeq)
	s.orgs[orgID] = orgName
	return s.newUser(orgID, name, email, "admin")
}

func (s *Store) AddUser(orgID, name, email, role string) User {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.newUser(orgID, name, email, role)
}

func (s *Store) AddApp(orgID, name, platform string) App {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.appSeq++
	a := App{
		AppID:    fmt.Sprintf("app_%d", s.appSeq),
		Name:     name,
		Platform: platform,
		AppKey:   newSecret(),
		orgID:    orgID,
	}
	s.appsByKey[a.AppKey] = a
	return a
}

func (s *Store) UserByToken(token string) (User, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.usersByToken[token]
	return u, ok
}

func (s *Store) AppByKey(key string) (App, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.appsByKey[key]
	return a, ok
}

// ReportAlert is the repeat-alert logic. The "look for an open alert, then
// create or update" sequence runs entirely under ONE lock, so two identical
// alerts can never both decide "no alert exists yet" (rule R8).
// Returns a copy of the alert and true if it was newly created.
func (s *Store) ReportAlert(app App, deviceID, threatType string, severity int) (Alert, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	key := alertKey{app.AppID, deviceID, threatType}

	if a, ok := s.openAlerts[key]; ok {
		a.Count++
		a.lastSeenAt = now
		a.LastSeen = now.Format(time.RFC3339)
		return *a, false
	}

	s.alertSeq++
	a := &Alert{
		ID:         fmt.Sprintf("alr_%d", s.alertSeq),
		AppID:      app.AppID,
		DeviceID:   deviceID,
		ThreatType: threatType,
		Severity:   severity,
		Count:      1,
		Status:     "open",
		FirstSeen:  now.Format(time.RFC3339),
		LastSeen:   now.Format(time.RFC3339),
		orgID:      app.orgID,
		seq:        s.alertSeq,
		lastSeenAt: now,
	}
	s.alerts[a.ID] = a
	s.openAlerts[key] = a
	return *a, true
}

// ListAlerts returns the company's alerts, newest lastSeen first.
// status "" means no filter.
func (s *Store) ListAlerts(orgID, status string) []Alert {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := []Alert{} // non-nil so JSON shows [] not null
	for _, a := range s.alerts {
		if a.orgID == orgID && (status == "" || a.Status == status) {
			out = append(out, *a)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].lastSeenAt.Equal(out[j].lastSeenAt) {
			return out[i].lastSeenAt.After(out[j].lastSeenAt)
		}
		return out[i].seq > out[j].seq
	})
	return out
}

// GetAlert only finds alerts of the given company (rule R6).
func (s *Store) GetAlert(orgID, id string) (Alert, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.alerts[id]
	if !ok || a.orgID != orgID {
		return Alert{}, false
	}
	return *a, true
}

func (s *Store) Resolve(orgID, id, userID string) (Alert, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	a, ok := s.alerts[id]
	if !ok || a.orgID != orgID {
		return Alert{}, errNotFound
	}
	if a.Status == "resolved" {
		return Alert{}, errResolved
	}
	a.Status = "resolved"
	a.ResolvedBy = userID
	delete(s.openAlerts, alertKey{a.AppID, a.DeviceID, a.ThreatType}) // next report makes a new alert
	return *a, nil
}
