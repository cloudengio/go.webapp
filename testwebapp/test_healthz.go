package testwebapp

// HealthzTest can be used to validate /healthz endpoints.
import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"cloudeng.io/logging/ctxlog"
	"cloudeng.io/sync/errgroup"
)

// HealthzTest can be used to validate /healthz endpoints.
type HealthzTest struct {
	client *http.Client
	specs  []HealthzSpec
}

type HealthzSpec struct {
	URL             string        `yaml:"url" json:"url"`
	Interval        time.Duration `yaml:"interval" json:"interval"`
	Timeout         time.Duration `yaml:"timeout" json:"timeout"`
	NumHealthChecks int           `yaml:"num_health_checks" json:"num_health_checks"`
}

func NewHealthzTest(client *http.Client, specs ...HealthzSpec) *HealthzTest {
	return &HealthzTest{
		client: client,
		specs:  specs,
	}
}

func (h HealthzTest) Run(ctx context.Context) error {
	var g errgroup.T
	for _, spec := range h.specs {
		if spec.NumHealthChecks == 0 {
			spec.NumHealthChecks = 1
		}
		if spec.Interval == 0 {
			spec.Interval = time.Second
		}
		if spec.Timeout == 0 {
			spec.Timeout = time.Second
		}
		g.Go(func() error {
			return h.run(ctx, spec)
		})
	}
	return g.Wait()
}

func (h HealthzTest) run(ctx context.Context, spec HealthzSpec) error {
	for i := 0; i < spec.NumHealthChecks; i++ {
		ctxlog.Info(ctx, "healthz: checking", "url", spec.URL, "attempt", i+1)
		reqCtx, reqCancel := context.WithTimeout(ctx, spec.Timeout)
		defer reqCancel()
		req, err := http.NewRequestWithContext(reqCtx, "GET", spec.URL, nil)
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
		ctxlog.Info(ctx, "healthz: check successful", "url", spec.URL, "attempt", i+1)
		if i < spec.NumHealthChecks-1 {
			timer := time.NewTimer(spec.Interval)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				return fmt.Errorf("healthz: %v: %w", spec.URL, ctx.Err())
			}
		}
	}
	return nil
}
