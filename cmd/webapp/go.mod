module cloudeng.io/webapp/cmd/webapp

go 1.26

require (
	cloudeng.io/cmdutil v0.0.0-20260312171538-61fcde6ce278
	cloudeng.io/webapp v0.0.0-20251211202122-3206a59d8279
	github.com/go-chi/chi/v5 v5.2.5
)

require (
	cloudeng.io/errors v0.0.14-0.20260312171538-61fcde6ce278 // indirect
	cloudeng.io/file v0.0.0-20260312171538-61fcde6ce278 // indirect
	cloudeng.io/io v0.0.0-20260312171538-61fcde6ce278 // indirect
	cloudeng.io/logging v0.0.0-20260312171538-61fcde6ce278 // indirect
	cloudeng.io/net v0.0.0-20260312171538-61fcde6ce278 // indirect
	cloudeng.io/os v0.0.0-20260331200221-4812cd2111b8 // indirect
	cloudeng.io/sync v0.0.9-0.20260312171538-61fcde6ce278 // indirect
	cloudeng.io/text v0.0.16-0.20260312171538-61fcde6ce278 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/text v0.35.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace cloudeng.io/webapp => ../..
