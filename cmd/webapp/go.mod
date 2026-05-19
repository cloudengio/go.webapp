module cloudeng.io/webapp/cmd/webapp

go 1.26

require (
	cloudeng.io/cmdutil v0.0.0-20260514201128-26a831c78d62
	cloudeng.io/webapp v0.0.0-20251211202122-3206a59d8279
	github.com/go-chi/chi/v5 v5.2.5
)

require (
	cloudeng.io/errors v0.0.14-0.20260312171538-61fcde6ce278 // indirect
	cloudeng.io/file v0.0.0-20260518190654-a057386f3a79 // indirect
	cloudeng.io/io v0.0.0-20260513235126-b955eaa2c893 // indirect
	cloudeng.io/logging v0.0.0-20260518190654-a057386f3a79 // indirect
	cloudeng.io/net v0.0.0-20260518190654-a057386f3a79 // indirect
	cloudeng.io/os v0.0.0-20260518190654-a057386f3a79 // indirect
	cloudeng.io/sync v0.0.11 // indirect
	cloudeng.io/text v0.0.16-0.20260312171538-61fcde6ce278 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace cloudeng.io/webapp => ../..
