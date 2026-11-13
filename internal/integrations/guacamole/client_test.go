package guacamole

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// fakeGuac is just enough of the Guacamole REST API to exercise the broker:
// tokens, connections (create/get/params/delete), user permissions, active
// connections (list/kill).
type fakeGuac struct {
	mu          sync.Mutex
	logins      int
	connections map[string]map[string]any // id -> {name, protocol, parameters}
	perms       map[string][]string       // user -> connection ids
	active      map[string]ActiveConnection
	nextID      int
	rejectToken bool
}

func newFakeGuac() *fakeGuac {
	f := &fakeGuac{connections: map[string]map[string]any{}, perms: map[string][]string{}, active: map[string]ActiveConnection{}, nextID: 100}
	f.connections["7"] = map[string]any{"name": "prod-bastion", "protocol": "ssh",
		"parameters": map[string]string{"hostname": "10.1.0.9", "port": "22", "username": "deploy", "password": "s3cret"}}
	f.active["a1"] = ActiveConnection{Identifier: "a1", ConnectionIdentifier: "7", Username: "alice"}
	return f
}

func (f *fakeGuac) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/tokens", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.logins++
		f.mu.Unlock()
		if r.FormValue("username") != "api" || r.FormValue("password") != "pw" {
			http.Error(w, `{"message":"Permission Denied."}`, 403)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"authToken": "tok123", "dataSource": "mysql", "username": "api"})
	})
	mux.HandleFunc("/api/session/data/mysql/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "tok123" || r.Header.Get("Guacamole-Token") != "tok123" {
			http.Error(w, "no token", 401)
			return
		}
		f.mu.Lock()
		if f.rejectToken {
			f.rejectToken = false
			f.mu.Unlock()
			http.Error(w, `{"message":"Permission Denied."}`, 403)
			return
		}
		f.mu.Unlock()
		path := strings.TrimPrefix(r.URL.Path, "/api/session/data/mysql")
		body, _ := io.ReadAll(r.Body)
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case path == "/connections" && r.Method == http.MethodPost:
			var in map[string]any
			_ = json.Unmarshal(body, &in)
			f.nextID++
			id := strconvI(f.nextID)
			params := map[string]string{}
			if p, ok := in["parameters"].(map[string]any); ok {
				for k, v := range p {
					params[k] = v.(string)
				}
			}
			f.connections[id] = map[string]any{"name": in["name"], "protocol": in["protocol"], "parameters": params}
			_ = json.NewEncoder(w).Encode(map[string]any{"identifier": id, "name": in["name"], "protocol": in["protocol"]})
		case strings.HasPrefix(path, "/connections/") && strings.HasSuffix(path, "/parameters"):
			id := strings.TrimSuffix(strings.TrimPrefix(path, "/connections/"), "/parameters")
			c, ok := f.connections[id]
			if !ok {
				http.Error(w, "not found", 404)
				return
			}
			_ = json.NewEncoder(w).Encode(c["parameters"])
		case strings.HasPrefix(path, "/connections/") && r.Method == http.MethodGet:
			id := strings.TrimPrefix(path, "/connections/")
			c, ok := f.connections[id]
			if !ok {
				http.Error(w, "not found", 404)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"identifier": id, "name": c["name"], "protocol": c["protocol"]})
		case strings.HasPrefix(path, "/connections/") && r.Method == http.MethodDelete:
			id := strings.TrimPrefix(path, "/connections/")
			if _, ok := f.connections[id]; !ok {
				http.Error(w, "not found", 404)
				return
			}
			delete(f.connections, id)
			w.WriteHeader(204)
		case strings.HasPrefix(path, "/users/") && strings.HasSuffix(path, "/permissions") && r.Method == http.MethodPatch:
			user := strings.TrimSuffix(strings.TrimPrefix(path, "/users/"), "/permissions")
			if user == "ghost" {
				http.Error(w, `{"message":"No such user"}`, 404)
				return
			}
			var patch []map[string]string
			_ = json.Unmarshal(body, &patch)
			for _, p := range patch {
				f.perms[user] = append(f.perms[user], strings.TrimPrefix(p["path"], "/connectionPermissions/"))
			}
			w.WriteHeader(204)
		case path == "/activeConnections" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(f.active)
		case path == "/activeConnections" && r.Method == http.MethodPatch:
			var patch []map[string]string
			_ = json.Unmarshal(body, &patch)
			for _, p := range patch {
				delete(f.active, strings.TrimPrefix(p["path"], "/"))
			}
			w.WriteHeader(204)
		default:
			http.Error(w, "unhandled "+r.Method+" "+path, 500)
		}
	})
	return mux
}

func strconvI(i int) string { return strings.TrimSpace(strings.Repeat(" ", 0) + itoa(i)) }

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

func TestBrokerActivateClonesTemplateAndRecords(t *testing.T) {
	f := newFakeGuac()
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Username: "api", Password: "pw", HTTP: srv.Client()}
	b := &Broker{Client: c, RecordingPath: "/recordings", TypescriptPath: "/typescripts"}

	id, err := b.Activate(context.Background(), Request{GrantID: "grant-1", User: "alice", Kind: "ssh", TemplateID: "7"})
	if err != nil {
		t.Fatal(err)
	}
	conn := f.connections[id]
	if conn == nil || conn["name"] != "pam-grant-1-alice" || conn["protocol"] != "ssh" {
		t.Fatalf("connection = %+v", conn)
	}
	params := conn["parameters"].(map[string]string)
	if params["hostname"] != "10.1.0.9" || params["password"] != "s3cret" || params["username"] != "deploy" {
		t.Fatalf("template params not cloned: %v", params)
	}
	if params["recording-path"] != "/recordings" || !strings.HasPrefix(params["recording-name"], "pam-grant-1-") ||
		params["typescript-path"] != "/typescripts" || params["create-recording-path"] != "true" {
		t.Fatalf("recording params: %v", params)
	}
	if perms := f.perms["alice"]; len(perms) != 1 || perms[0] != id {
		t.Fatalf("alice perms = %v", perms)
	}
	if u := b.LaunchURL(id); !strings.HasPrefix(u, srv.URL+"/#/client/") {
		t.Fatalf("launch url = %q", u)
	}
	// Template still intact; only one login happened so far.
	if _, ok := f.connections["7"]; !ok || f.logins != 1 {
		t.Fatalf("template deleted or logins=%d", f.logins)
	}

	// A live session on the per-grant connection is killed and the connection
	// removed on deactivate; the template's session is untouched.
	f.mu.Lock()
	f.active["a2"] = ActiveConnection{Identifier: "a2", ConnectionIdentifier: id, Username: "alice"}
	f.mu.Unlock()
	if err := b.Deactivate(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.active["a2"]; ok {
		t.Fatal("active session not killed")
	}
	if _, ok := f.active["a1"]; !ok {
		t.Fatal("unrelated session killed")
	}
	if _, ok := f.connections[id]; ok {
		t.Fatal("connection not deleted")
	}
	// Deactivating twice is harmless (404 on delete is success).
	if err := b.Deactivate(context.Background(), id); err != nil {
		t.Fatalf("second deactivate: %v", err)
	}
}

func TestBrokerWithoutTemplateAndUnknownUser(t *testing.T) {
	f := newFakeGuac()
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Username: "api", Password: "pw", HTTP: srv.Client()}
	b := &Broker{Client: c}
	id, err := b.Activate(context.Background(), Request{GrantID: "g2", User: "ghost", Kind: "rdp", Host: "10.1.0.11", Port: 3389, Login: "admin"})
	if err != nil {
		t.Fatalf("unknown guacamole user must not fail activation: %v", err)
	}
	params := f.connections[id]["parameters"].(map[string]string)
	if params["hostname"] != "10.1.0.11" || params["port"] != "3389" || params["username"] != "admin" || f.connections[id]["protocol"] != "rdp" {
		t.Fatalf("params = %v", params)
	}
	if _, ok := params["recording-path"]; ok {
		t.Fatal("recording set without a path configured")
	}
	if _, err := b.Activate(context.Background(), Request{GrantID: "g3", User: "x", Kind: "l3", Host: "10.0.0.1"}); err == nil {
		t.Fatal("l3 brokered")
	}
	if _, err := (&Broker{Client: &Client{}}).Activate(context.Background(), Request{Kind: "ssh"}); err != ErrNotConfigured {
		t.Fatalf("unconfigured: %v", err)
	}
}

func TestClientReloginsOnRejectedToken(t *testing.T) {
	f := newFakeGuac()
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	c := &Client{BaseURL: srv.URL, Username: "api", Password: "pw", HTTP: srv.Client()}
	if _, err := c.ActiveConnections(context.Background(), ""); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.rejectToken = true
	f.mu.Unlock()
	if _, err := c.ActiveConnections(context.Background(), "7"); err != nil {
		t.Fatalf("after token rejection: %v", err)
	}
	if f.logins != 2 {
		t.Fatalf("logins = %d, want re-login once", f.logins)
	}
	bad := &Client{BaseURL: srv.URL, Username: "api", Password: "wrong", HTTP: srv.Client()}
	_, err := bad.ActiveConnections(context.Background(), "")
	var apiErr *APIError
	if !asAPIError(err, &apiErr) || apiErr.Status != 403 {
		t.Fatalf("bad credentials: %v", err)
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Fatal("password echoed in error")
	}
}
