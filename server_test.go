package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func call(h http.Handler, method, path string, headers map[string]string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func bearer(token string) map[string]string {
	return map[string]string{"Authorization": "Bearer " + token}
}

func parse(t *testing.T, rec *httptest.ResponseRecorder, dst any) {
	t.Helper()
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("bad JSON %q: %v", rec.Body.String(), err)
	}
}

// register creates a company and returns its admin.
func register(t *testing.T, h http.Handler, org string) User {
	t.Helper()
	rec := call(h, "POST", "/register", nil, `{"orgName":"`+org+`","name":"Admin","email":"a@`+org+`.test"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("register: got %d", rec.Code)
	}
	var u User
	parse(t, rec, &u)
	return u
}

// setupAlert returns a company admin, a viewer of that company, and one open alert.
func setupAlert(t *testing.T, h http.Handler) (admin, viewer User, alert Alert, appKey string) {
	t.Helper()
	admin = register(t, h, "acme")

	rec := call(h, "POST", "/users", bearer(admin.Token), `{"name":"Vik","email":"vik@acme.test","role":"viewer"}`)
	parse(t, rec, &viewer)

	var app App
	rec = call(h, "POST", "/apps", bearer(admin.Token), `{"name":"Acme Pay","platform":"android"}`)
	parse(t, rec, &app)
	appKey = app.AppKey

	rec = call(h, "POST", "/alerts", map[string]string{"X-App-Key": appKey},
		`{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":5}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("report alert: got %d", rec.Code)
	}
	parse(t, rec, &alert)
	return
}

// R9 test 1
func TestViewerCannotResolve(t *testing.T) {
	h := NewServer().Routes()
	_, viewer, alert, _ := setupAlert(t, h)

	rec := call(h, "POST", "/alerts/"+alert.ID+"/resolve", bearer(viewer.Token), "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("want 403, got %d", rec.Code)
	}
}

// R9 test 2
func TestOtherCompanyGets404(t *testing.T) {
	h := NewServer().Routes()
	_, _, alert, _ := setupAlert(t, h)
	other := register(t, h, "beta")

	if rec := call(h, "GET", "/alerts/"+alert.ID, bearer(other.Token), ""); rec.Code != http.StatusNotFound {
		t.Fatalf("GET: want 404, got %d", rec.Code)
	}
	if rec := call(h, "POST", "/alerts/"+alert.ID+"/resolve", bearer(other.Token), ""); rec.Code != http.StatusNotFound {
		t.Fatalf("resolve: want 404, got %d", rec.Code)
	}
}

// R9 test 3
func TestFiftyConcurrentAlertsMakeOneAlert(t *testing.T) {
	h := NewServer().Routes()
	admin, _, _, appKey := setupAlert(t, h)

	const n = 50
	codes := make(chan int, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			rec := call(h, "POST", "/alerts", map[string]string{"X-App-Key": appKey},
				`{"deviceId":"d2","threatType":"FRIDA_DETECTED","severity":4}`)
			codes <- rec.Code
		}()
	}
	wg.Wait()
	close(codes)

	created := 0
	for c := range codes {
		if c == http.StatusCreated {
			created++
		}
	}
	if created != 1 {
		t.Fatalf("want exactly one 201, got %d", created)
	}

	rec := call(h, "GET", "/alerts?status=open", bearer(admin.Token), "")
	var out struct{ Alerts []Alert }
	parse(t, rec, &out)

	var d2 []Alert
	for _, a := range out.Alerts {
		if a.DeviceID == "d2" {
			d2 = append(d2, a)
		}
	}
	if len(d2) != 1 || d2[0].Count != n {
		t.Fatalf("want one d2 alert with count %d, got %+v", n, d2)
	}
}

// extra: a repeat after resolve creates a new alert; resolving twice is 409
func TestResolveThenRepeat(t *testing.T) {
	h := NewServer().Routes()
	admin, _, alert, appKey := setupAlert(t, h)

	if rec := call(h, "POST", "/alerts/"+alert.ID+"/resolve", bearer(admin.Token), ""); rec.Code != http.StatusOK {
		t.Fatalf("resolve: got %d", rec.Code)
	}
	if rec := call(h, "POST", "/alerts/"+alert.ID+"/resolve", bearer(admin.Token), ""); rec.Code != http.StatusConflict {
		t.Fatalf("second resolve: want 409, got %d", rec.Code)
	}
	rec := call(h, "POST", "/alerts", map[string]string{"X-App-Key": appKey},
		`{"deviceId":"d1","threatType":"ROOT_DETECTED","severity":5}`)
	var again Alert
	parse(t, rec, &again)
	if rec.Code != http.StatusCreated || again.ID == alert.ID || again.Count != 1 {
		t.Fatalf("want new alert with count 1, got %d %+v", rec.Code, again)
	}
}
func TestTrailingGarbageIs400(t *testing.T) {
	h := NewServer().Routes()
	rec := call(h, "POST", "/register", nil, `{"orgName":"A","name":"B","email":"a@b.c"} xyz`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("want 400, got %d", rec.Code)
	}
}