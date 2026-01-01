package testwebapp

// HealthzTest can be used to validate /healthz endpoints.
import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"cloudeng.io/logging/ctxlog"
)

type HealthzTest struct {
	client          *http.Client
	healthcheckURL  string
	interval        time.Duration
	numHealthChecks int
}

func NewHealthzTest(client *http.Client, healthcheckURL string, interval time.Duration, numHealthChecks int) *HealthzTest {
	return &HealthzTest{
		client:          client,
		healthcheckURL:  healthcheckURL,
		interval:        interval,
		numHealthChecks: numHealthChecks,
	}
}

func (h HealthzTest) Run(ctx context.Context) error {
	for i := 0; i < h.numHealthChecks; i++ {
		ctxlog.Info(ctx, "healthz: checking", "url", h.healthcheckURL, "attempt", i+1)
		req, err := http.NewRequestWithContext(ctx, "GET", h.healthcheckURL, nil)
		if err != nil {
			return fmt.Errorf("healthz: creating request: %w", err)
		}
		resp, err := h.client.Do(req)
		if err != nil {
			return fmt.Errorf("healthz: performing request: %w", err)
		}
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return fmt.Errorf("healthz: reading response body: %w", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("healthz: unexpected status code: %d, body: %s", resp.StatusCode, body)
		}
		if string(body) != "ok\n" {
			return fmt.Errorf("healthz: unexpected body: %q", string(body))
		}
		ctxlog.Info(ctx, "healthz: check successful", "url", h.healthcheckURL, "attempt", i+1)
		time.Sleep(h.interval)
	}
	return nil
}
