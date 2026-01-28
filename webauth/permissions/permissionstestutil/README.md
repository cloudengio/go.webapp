# Package [cloudeng.io/webapp/webauth/permissions/permissionstestutil](https://pkg.go.dev/cloudeng.io/webapp/webauth/permissions/permissionstestutil?tab=doc)

```go
import cloudeng.io/webapp/webauth/permissions/permissionstestutil
```


## Functions
### Func New
```go
func New(roleMethodResourceAction4Tuples ...string) (permissions.Set, error)
```
New creates a new Permissions instance from a list of
role-method-resource-action 4-tuples.

### Func NewMust
```go
func NewMust(roleMethodResourceAction4Tuples ...string) permissions.Set
```
NewMust is like New but panics on error.




