// Copyright 2026 cloudeng llc. All rights reserved.
// Use of this source code is governed by the Apache-2.0
// license that can be found in the LICENSE file.

package testwebapp_test

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"cloudeng.io/webapp/testwebapp"
)

func TestClick(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `
			<html>
				<body>
					<button id="btn1">Button 1</button>
					<div id="result"></div>
					<script>
						document.getElementById('btn1').addEventListener('click', () => {
							const btn2 = document.createElement('button');
							btn2.id = 'btn2';
							btn2.textContent = 'Button 2';
							btn2.addEventListener('click', () => {
								document.getElementById('result').textContent = 'success';
							});
							document.body.appendChild(btn2);
						});
					</script>
				</body>
			</html>
		`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	t.Run("SuccessSequentialClick", func(t *testing.T) {
		ct := testwebapp.NewClickTest([]testwebapp.ClickSpec{
			{
				URL:       srv.URL,
				Selectors: []string{"#btn1", "#btn2"},
			},
		})
		if err := ct.Run(t.Context()); err != nil {
			t.Fatalf("expected success, got %v", err)
		}
	})

	t.Run("FailureElementNotFound", func(t *testing.T) {
		ct := testwebapp.NewClickTest([]testwebapp.ClickSpec{
			{
				URL:       srv.URL,
				Selectors: []string{"#btn1", "#nonexistent"},
			},
		}, testwebapp.WithTimeout(2*time.Second))
		err := ct.Run(t.Context())
		if err == nil {
			t.Fatal("expected failure, got nil")
		}
		if !errors.Is(err, testwebapp.ErrClickElementNotFound) {
			t.Errorf("expected ErrClickElementNotFound, got %v", err)
		}
	})
}
