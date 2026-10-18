// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package webhooks_test

import (
	"bufio"
	"context"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"cloudeng.io/webapp/webhooks"
)

// sessionLine is a line sent to a reader, with the session that it is part of
// and whether it is the last, as GitHubWorkflowSessionKey finds them.
type sessionLine struct {
	webhooks.Delivery
	Session string
	Last    bool
}

func newLine(d webhooks.Delivery) sessionLine {
	key, last := webhooks.GitHubWorkflowSessionKey(d.Headers, d.Payload)
	return sessionLine{Delivery: d, Session: key, Last: last}
}

// sessionServer is a relay, with sessions, that is served over HTTP, since the
// the responses to requests for sessions are long lived.
type sessionServer struct {
	t     *testing.T
	srv   *httptest.Server
	relay *webhooks.Relay
}

func newSessionServer(t *testing.T, opts ...webhooks.Option) *sessionServer {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	opts = append([]webhooks.Option{webhooks.WithSessions(webhooks.GitHubWorkflowSessionKey)}, opts...)
	relay := webhooks.NewRelay(ctx, webhooks.NoopValidator, opts...)
	srv := httptest.NewServer(http.HandlerFunc(relay.Handler("/api/webhook", "/api/wait")))
	t.Cleanup(func() {
		srv.CloseClientConnections()
		srv.Close()
		cancel()
		relay.Stop(context.Background())
	})
	return &sessionServer{t: t, srv: srv, relay: relay}
}

// post sends a webhook of the type event, with body.
func (s *sessionServer) post(event, body string) {
	s.t.Helper()
	req, err := http.NewRequest(http.MethodPost, s.srv.URL+"/api/webhook", strings.NewReader(body))
	if err != nil {
		s.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-GitHub-Event", event)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		s.t.Fatalf("got %v", resp.Status)
	}
}

func (s *sessionServer) job(run int, name string) {
	s.t.Helper()
	s.post("workflow_job", fmt.Sprintf(`{"action":"in_progress","workflow_job":{"run_id":%d,"name":%q}}`, run, name))
}

func (s *sessionServer) completed(run int) {
	s.t.Helper()
	s.post("workflow_run", fmt.Sprintf(`{"action":"completed","workflow_run":{"id":%d}}`, run))
}

func (s *sessionServer) ping(n int) {
	s.t.Helper()
	s.post("ping", fmt.Sprintf(`{"zen":"ping %d"}`, n))
}

// reader is a long polling request that asks for a session.
type reader struct {
	lines  chan sessionLine
	done   chan struct{} // closed when the response ends
	cancel context.CancelFunc
}

// session starts a long polling request that asks for a session.
func (s *sessionServer) session() *reader {
	s.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.srv.URL+"/api/wait?stream=1", nil)
	if err != nil {
		s.t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		s.t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		s.t.Fatalf("got %v", resp.Status)
	}
	rd := &reader{lines: make(chan sessionLine, 1000), done: make(chan struct{}), cancel: cancel}
	s.t.Cleanup(cancel)
	go func() {
		defer close(rd.done)
		defer resp.Body.Close()
		sc := bufio.NewScanner(resp.Body)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			var d webhooks.Delivery
			if err := json.Unmarshal(sc.Bytes(), &d); err != nil {
				s.t.Errorf("bad line %q: %v", sc.Bytes(), err)
				return
			}
			rd.lines <- newLine(d)
		}
	}()
	return rd
}

// next returns the next line, which must arrive in time.
func (r *reader) next(t *testing.T) sessionLine {
	t.Helper()
	select {
	case l := <-r.lines:
		return l
	case <-time.After(5 * time.Second):
		t.Fatal("no delivery")
	}
	return sessionLine{}
}

// none checks that nothing arrives for a short time.
func (r *reader) none(t *testing.T) {
	t.Helper()
	select {
	case l := <-r.lines:
		t.Fatalf("unexpected delivery %+v", l)
	case <-time.After(100 * time.Millisecond):
	}
}

// ended checks that the response ends.
func (r *reader) ended(t *testing.T) {
	t.Helper()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		t.Fatal("the response did not end")
	}
}

func lineName(t *testing.T, l sessionLine) string {
	t.Helper()
	var p struct {
		WorkflowJob struct {
			Name string `json:"name"`
		} `json:"workflow_job"`
		Zen string `json:"zen"`
	}
	if err := json.Unmarshal(l.Payload, &p); err != nil {
		t.Fatal(err)
	}
	if p.Zen != "" {
		return p.Zen
	}
	return p.WorkflowJob.Name
}

// waitFor blocks until a reader is waiting in the relay, which a delivery then
// is not racing with.
func waitForReaders(t *testing.T) {
	t.Helper()
	time.Sleep(50 * time.Millisecond)
}

func TestSessionsSameRunSameReader(t *testing.T) {
	s := newSessionServer(t)
	a, b := s.session(), s.session()
	waitForReaders(t)

	// Interleaved: the first of each is given to a reader, which then keeps it.
	s.job(1, "a1")
	s.job(2, "b1")
	for i := 2; i <= 5; i++ {
		s.job(1, fmt.Sprintf("a%d", i))
		s.job(2, fmt.Sprintf("b%d", i))
	}
	got := map[*reader][]string{}
	sessions := map[*reader]string{}
	for _, r := range []*reader{a, b} {
		for range 5 {
			l := r.next(t)
			got[r] = append(got[r], lineName(t, l))
			if sessions[r] == "" {
				sessions[r] = l.Session
			} else if sessions[r] != l.Session {
				t.Fatalf("a reader was sent sessions %q and %q", sessions[r], l.Session)
			}
		}
		r.none(t)
	}
	if sessions[a] == sessions[b] {
		t.Fatalf("both readers have %v", sessions[a])
	}
	for r, names := range got {
		prefix := "a"
		if sessions[r] == "2" {
			prefix = "b"
		}
		for i, n := range names {
			if want := fmt.Sprintf("%s%d", prefix, i+1); n != want {
				t.Errorf("delivery %d is %q, want %q", i, n, want)
			}
		}
	}

	// The last ends the response, and nothing else.
	s.completed(1)
	s.completed(2)
	for _, r := range []*reader{a, b} {
		l := r.next(t)
		if !l.Last {
			t.Errorf("%+v is not the last", l)
		}
		r.ended(t)
	}
}

// firstOf returns the reader that is sent the next delivery, and the delivery.
func firstOf(t *testing.T, readers ...*reader) (*reader, sessionLine) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		for _, r := range readers {
			select {
			case l := <-r.lines:
				return r, l
			default:
			}
		}
		select {
		case <-deadline:
			t.Fatal("no delivery")
		case <-time.After(5 * time.Millisecond):
		}
	}
}

func TestSessionsUnkeyedToAnyReader(t *testing.T) {
	s := newSessionServer(t)
	x, y := s.session(), s.session()
	waitForReaders(t)

	// Whichever is given run 1 is bound to it.
	s.job(1, "a1")
	a, l := firstOf(t, x, y)
	if l.Session != "1" {
		t.Fatalf("got %+v", l)
	}
	b := y
	if a == y {
		b = x
	}
	// What is not part of a session is for any reader, including one that is bound.
	const pingCount = 40
	for i := 1; i <= pingCount; i++ {
		s.ping(i)
	}
	pings := map[string]int{}
	byReader := map[*reader]int{}
	for range pingCount {
		r, l := firstOf(t, a, b)
		if l.Session != "" {
			t.Errorf("a reader was sent %+v for no session", l)
		}
		pings[lineName(t, l)]++
		byReader[r]++
	}
	if len(pings) != pingCount {
		t.Errorf("got %d different, want each once", len(pings))
	}
	// Not bound to either, which they would be if they were a session.
	if byReader[a] == 0 || byReader[b] == 0 {
		t.Errorf("the readers were sent %d and %d, want some for each", byReader[a], byReader[b])
	}
	// And a session is still only for its reader.
	s.job(2, "b1")
	s.job(1, "a2")
	got := map[string]*reader{}
	for range 2 {
		r, l := firstOf(t, a, b)
		got[lineName(t, l)] = r
	}
	if got["a2"] != a || got["b1"] == a {
		t.Errorf("a2 went to the reader of run 1: %v, b1 did not: %v", got["a2"] == a, got["b1"] != a)
	}
}

// TestSessionsOneShot checks that a reader that does not stream is rejected if
// sessions are enabled, and is otherwise sent a single delivery as it was received.
func TestSessionsOneShot(t *testing.T) {
	s := newSessionServer(t)
	resp, err := http.Get(s.srv.URL + "/api/wait")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("got %v, want %v", resp.StatusCode, http.StatusBadRequest)
	}

	// Without sessions every delivery is relayed as it arrives.
	s = newSessionServer(t, webhooks.WithSessions(nil), webhooks.WithForwardedHeaders("X-GitHub-Event"))
	s.job(1, "a1")
	s.ping(1)
	for _, want := range []struct{ event, name string }{{"workflow_job", "a1"}, {"ping", "ping 1"}} {
		resp, err := http.Get(s.srv.URL + "/api/wait")
		if err != nil {
			t.Fatal(err)
		}
		var payload jsontext.Value
		err = json.UnmarshalRead(resp.Body, &payload)
		resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		l := sessionLine{Delivery: webhooks.Delivery{Headers: resp.Header, Payload: payload}}
		if got := resp.Header.Get("X-GitHub-Event"); got != want.event || lineName(t, l) != want.name {
			t.Errorf("got %q %q, want %q %q", got, lineName(t, l), want.event, want.name)
		}
	}

	// And a reader that streams is sent them all.
	s.job(2, "b1")
	s.ping(2)
	a := s.session()
	for _, want := range []string{"b1", "ping 2"} {
		if got := lineName(t, a.next(t)); got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	a.none(t)
}

func TestSessionsPayloadFormat(t *testing.T) {
	s := newSessionServer(t)
	a := s.session()
	waitForReaders(t)
	s.post("ping", "{\n  \"zen\": \"pretty\",\n  \"n\": 1\n}\n")
	l := a.next(t)
	if string(l.Payload) == "" || lineName(t, l) != "pretty" {
		t.Errorf("got %+v", l)
	}
	req, err := http.NewRequest(http.MethodPost, s.srv.URL+"/api/webhook", strings.NewReader("not json"))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("got %v, want %v", resp.StatusCode, http.StatusBadRequest)
	}
	a.none(t)
}

func TestSessionsExclusiveReads(t *testing.T) {
	s := newSessionServer(t, webhooks.WithExclusiveReads(true))
	a := s.session()
	waitForReaders(t)
	resp, err := http.Get(s.srv.URL + "/api/wait?stream=1")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusConflict {
		t.Errorf("got %v, want 409", resp.Status)
	}
	s.job(1, "a1")
	a.next(t)
}

func TestSessionsConcurrent(t *testing.T) {
	s := newSessionServer(t)
	const runs, perRun, readers = 8, 25, 8
	rs := make([]*reader, readers)
	for i := range rs {
		rs[i] = s.session()
	}
	waitForReaders(t)
	var wg sync.WaitGroup
	for run := 1; run <= runs; run++ {
		wg.Go(func() {
			for i := 1; i <= perRun; i++ {
				s.job(run, fmt.Sprintf("r%d-%d", run, i))
			}
			s.completed(run)
		})
	}
	wg.Wait()
	seen := map[string]bool{}
	for _, r := range rs {
		var session string
		next := 1
		for {
			l := r.next(t)
			if session == "" {
				session = l.Session
			} else if l.Session != session {
				t.Fatalf("a reader had %q and %q", session, l.Session)
			}
			if !l.Last {
				var run, i int
				if _, err := fmt.Sscanf(lineName(t, l), "r%d-%d", &run, &i); err != nil || session != fmt.Sprint(run) || i != next {
					t.Fatalf("got %q for %q, want delivery %d", lineName(t, l), session, next)
				}
				next++
				continue
			}
			break
		}
		if next != perRun+1 {
			t.Errorf("%q had %d deliveries, want %d", session, next-1, perRun)
		}
		seen[session] = true
		r.ended(t)
	}
	if len(seen) != runs {
		t.Errorf("%d sessions were seen, want %d", len(seen), runs)
	}
}

func TestGitHubWorkflowSessionKey(t *testing.T) {
	for _, tc := range []struct {
		name, event, body string
		key               string
		last              bool
	}{
		{"run", "workflow_run", `{"action":"requested","workflow_run":{"id":42}}`, "42", false},
		{"run completed", "workflow_run", `{"action":"completed","workflow_run":{"id":42}}`, "42", true},
		{"job", "workflow_job", `{"action":"queued","workflow_job":{"run_id":42,"id":7}}`, "42", false},
		{"job completed is not the last", "workflow_job", `{"action":"completed","workflow_job":{"run_id":42}}`, "42", false},
		{"same run for both", "workflow_job", `{"workflow_job":{"run_id":42}}`, "42", false},
		{"other event", "ping", `{"zen":"x"}`, "", false},
		{"push", "push", `{"workflow_run":{"id":42}}`, "", false},
		{"no id", "workflow_run", `{"action":"completed","workflow_run":{}}`, "", false},
		{"no run id", "workflow_job", `{"workflow_job":{"id":7}}`, "", false},
		{"not JSON", "workflow_run", `{`, "", false},
		{"no event", "", `{"workflow_run":{"id":42}}`, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := http.Header{}
			if tc.event != "" {
				h.Set("X-GitHub-Event", tc.event)
			}
			key, last := webhooks.GitHubWorkflowSessionKey(h, []byte(tc.body))
			if key != tc.key || last != tc.last {
				t.Errorf("got %q, %v, want %q, %v", key, last, tc.key, tc.last)
			}
		})
	}
}

// TestSessionsNoReader checks that what arrives when there is no reader that
// asked for sessions is not lost: it is relayed to any reader.
func TestSessionsNoReader(t *testing.T) {
	s := newSessionServer(t)
	s.job(1, "a1")
	s.job(2, "b1")
	s.job(1, "a2")
	s.ping(1)

	a := s.session()
	var names []string
	for range 4 {
		names = append(names, lineName(t, a.next(t)))
	}
	if got := strings.Join(names, ","); got != "a1,b1,a2,ping 1" {
		t.Errorf("got %v", got)
	}
	// From now on there is a reader, to which a session is bound.
	s.job(3, "c1")
	if l := a.next(t); l.Session != "3" {
		t.Errorf("got %+v", l)
	}
}

// TestSessionsLeavingReader checks that a session that its reader leaves is
// relayed to another, from then on, and that nothing that had not been sent is lost.
func TestSessionsLeavingReader(t *testing.T) {
	s := newSessionServer(t)
	a := s.session()
	waitForReaders(t)
	s.job(1, "a1")
	a.next(t)
	a.cancel()
	a.ended(t)
	time.Sleep(50 * time.Millisecond)

	// With no reader it is relayed to any reader, which is then bound to
	// what follows.
	s.job(1, "a2")
	b := s.session()
	if l := b.next(t); lineName(t, l) != "a2" {
		t.Errorf("got %+v", l)
	}
	s.job(1, "a3")
	if l := b.next(t); lineName(t, l) != "a3" || l.Session != "1" {
		t.Errorf("got %+v", l)
	}
	s.completed(1)
	if l := b.next(t); !l.Last {
		t.Errorf("got %+v", l)
	}
	b.ended(t)
}

// TestSessionsPolicy checks that sessions are bound to the readers that the
// policy chooses, and that a reader with more than one is sent all of them.
func TestSessionsPolicy(t *testing.T) {
	odd := func(session string, _ int) int { return int(session[len(session)-1]-'0') % 2 }
	s := newSessionServer(t, webhooks.WithSessionPolicy(odd))
	a, b := s.session(), s.session()
	waitForReaders(t)
	for run := 1; run <= 4; run++ {
		s.job(run, fmt.Sprintf("r%d", run))
	}
	got := map[string]*reader{}
	for _, r := range []*reader{a, b} {
		for range 2 {
			got[lineName(t, r.next(t))] = r
		}
	}
	if got["r1"] != got["r3"] || got["r2"] != got["r4"] || got["r1"] == got["r2"] {
		t.Errorf("sessions were not bound as the policy chose: %v", got)
	}
	// A reader that has more than one session ends when it is sent the last of all of them.
	for run := 1; run <= 4; run++ {
		s.completed(run)
	}
	for _, r := range []*reader{a, b} {
		r.next(t)
		r.next(t)
		r.ended(t)
	}
}

func TestHashSessionPolicy(t *testing.T) {
	seen := map[int]bool{}
	for i := range 100 {
		key := fmt.Sprintf("%d", i)
		got := webhooks.HashSessionPolicy(key, 3)
		if got < 0 || got >= 3 || got != webhooks.HashSessionPolicy(key, 3) {
			t.Fatalf("%s: bad index %d", key, got)
		}
		seen[got] = true
	}
	if len(seen) != 3 {
		t.Errorf("only used readers %v", seen)
	}
}

// TestSessionsTimeout checks that a session that never completes does not keep
// the response of its reader open once it has timed out, and that it does
// without a timeout.
func TestSessionsTimeout(t *testing.T) {
	for _, tc := range []struct {
		timeout time.Duration
		ends    bool
	}{
		{0, false},
		{200 * time.Millisecond, true},
	} {
		s := newSessionServer(t, webhooks.WithSessionTimeout(tc.timeout))
		a := s.session()
		waitForReaders(t)
		s.job(1, "a1") // run 1 never completes
		s.job(2, "b1")
		a.next(t)
		a.next(t)
		time.Sleep(300 * time.Millisecond)
		s.completed(2)
		a.next(t)
		select {
		case <-a.done:
			if !tc.ends {
				t.Errorf("timeout %v: the response ended with a session in progress", tc.timeout)
			}
		case <-time.After(time.Second):
			if tc.ends {
				t.Errorf("timeout %v: the response did not end", tc.timeout)
			}
		}
	}
}
