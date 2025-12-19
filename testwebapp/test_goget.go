package testwebapp

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"

	"cloudeng.io/errors"
	"cloudeng.io/webapp/goget"
)

var (
	ErrGoGetUnexpectedError = errors.New("go-get unexpected error")
	ErrGoGetPathNotFound    = errors.New("go-get path not found")
	ErrGoGetNotFound        = errors.New("go-get meta tag not found")
	ErrGoGetContentMismatch = errors.New("go-get meta tag content mismatch")
)

// GoGetTest can be used to validate go-get meta tags for a set of import paths.
type GoGetTest struct {
	tlsClient *http.Client
	specs     []goget.Spec
}

func NewGoGetTest(tlsClient *http.Client, specs ...goget.Spec) *GoGetTest {
	return &GoGetTest{tlsClient: tlsClient, specs: specs}
}

func (g GoGetTest) Run(ctx context.Context) error {
	var errs errors.M
	for _, spec := range g.specs {
		err := g.verify(ctx, spec)
		if err != nil {
			errs.Append(fmt.Errorf("%v: %w", spec, err))
			continue
		}
	}
	return errs.Err()
}

func (g GoGetTest) verify(ctx context.Context, expected goget.Spec) error {
	u := "https://" + expected.ImportPath + "?go-get=1"
	req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
	if err != nil {
		return ErrGoGetUnexpectedError
	}
	return verify(req, g.tlsClient, expected)
}

func verify(req *http.Request, client *http.Client, expected goget.Spec) error {
	resp, err := client.Do(req)
	if err != nil {
		return ErrGoGetUnexpectedError
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		if resp.StatusCode == http.StatusNotFound {
			return ErrGoGetPathNotFound
		}
		return ErrGoGetUnexpectedError
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ErrGoGetUnexpectedError
	}
	bodyStr := string(body)
	if !strings.Contains(bodyStr, `<meta name="go-import" content="`) {
		return ErrGoGetNotFound
	}

	// <meta name="go-import" content="example.com/mod git https://github.com/example/mod">

	expectedTag := fmt.Sprintf(`<meta name="go-import" content="%s"/>`, expected.Content)
	if !strings.Contains(bodyStr, expectedTag) {
		return ErrGoGetContentMismatch
	}
	return nil
}
