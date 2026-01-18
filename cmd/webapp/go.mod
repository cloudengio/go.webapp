module cloudeng.io/webapp/cmd/webapp

go 1.25.5

require (
	cloudeng.io/cmdutil v0.0.0-20260114060639-052fa943c25b
	cloudeng.io/webapp v0.0.0-20251211202122-3206a59d8279
	github.com/go-chi/chi/v5 v5.2.4
)

require (
	cloudeng.io/errors v0.0.14-0.20260118175335-f191a42253cc // indirect
	cloudeng.io/file v0.0.0-20260114060639-052fa943c25b // indirect
	cloudeng.io/io v0.0.0-20260114060639-052fa943c25b // indirect
	cloudeng.io/logging v0.0.0-20260114060639-052fa943c25b // indirect
	cloudeng.io/net v0.0.0-20260114060639-052fa943c25b // indirect
	cloudeng.io/os v0.0.0-20260118175335-f191a42253cc // indirect
	cloudeng.io/sync v0.0.9-0.20260114020737-744f6c0f8e64 // indirect
	cloudeng.io/text v0.0.13 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/text v0.33.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace cloudeng.io/webapp => ../..
