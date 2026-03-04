module cloudeng.io/webapp/cmd/webapp

go 1.26

require (
	cloudeng.io/cmdutil v0.0.0-20260225012014-415f78789833
	cloudeng.io/webapp v0.0.0-20251211202122-3206a59d8279
	github.com/go-chi/chi/v5 v5.2.5
)

require (
	cloudeng.io/errors v0.0.14-0.20260118175335-f191a42253cc // indirect
	cloudeng.io/file v0.0.0-20260225012014-415f78789833 // indirect
	cloudeng.io/io v0.0.0-20260225012014-415f78789833 // indirect
	cloudeng.io/logging v0.0.0-20260303213431-bb1cfd0f49cd // indirect
	cloudeng.io/net v0.0.0-20260225012014-415f78789833 // indirect
	cloudeng.io/os v0.0.0-20260303213431-bb1cfd0f49cd // indirect
	cloudeng.io/sync v0.0.9-0.20260114020737-744f6c0f8e64 // indirect
	cloudeng.io/text v0.0.15 // indirect
	golang.org/x/net v0.51.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace cloudeng.io/webapp => ../..
