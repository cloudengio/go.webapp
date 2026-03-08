# Package [cloudeng.io/webapp/webauth/permissions](https://pkg.go.dev/cloudeng.io/webapp/webauth/permissions?tab=doc)

```go
import cloudeng.io/webapp/webauth/permissions
```


## Variables
### DefaultMaxComponentsAllowed
```go
DefaultMaxComponentsAllowed = 10

```



## Functions
### Func Allowed
```go
func Allowed(request, requirement Pattern, sep string) bool
```
Allowed returns true if the request is allowed by the requirement.
Both request and requirement must be non-empty, if either has more than
DefaultMaxComponentsAllowed components, the function returns false.
A trailing wildcard component ('<sep>*')in the request is allowed and will
match any requirement that is more "specific", that is, has the request
up and including the last <sep> before the '*' as a prefix. Using : as the
separator, a:b:* is allowed by a:b:c, but not by a:b. Non-trailing wildcards
match one and only one component. That is, a:*:c is allowed by a:b:c but not
by a:b:c:d. Wildcards within components have no effect, that a:x*z:c will
not be allowed by a:xyx:c.



## Types
### Type Action
```go
type Action Pattern
```
Action refers to the action to perform on the resource. For actions,
colons are used as a separator between components.


### Type Pattern
```go
type Pattern string
```
Pattern represents a structured pattern for authorization with support
for wildcards (*). A pattern is a colon separated list of components with
well defined rules for determining if a request is allowed by a given
requirement. Wildcards match entire pattern components and cannot be used
as partial matches. That is, a*b has no effect whereas a:* or a:*:b will,
see the Allowed function for details.


### Type Resource
```go
type Resource Pattern
```
Resource refers to the resource on which the action is performed.
For resources, / is used as a separator between components. By convention,
resources are URI paths.


### Type Set
```go
type Set struct {
	Permissions []Spec
}
```
Set represents a set of permissions, generally used to represent multiple
permissions that have been granted.

### Methods

```go
func (s Set) Satisfies(required Spec) bool
```
Satisfies returns true if at least one of the permissions in the Set is
allowed satisfies the required Spec.


```go
func (s Set) Specs() iter.Seq[Spec]
```
Specs provides an iterator over a permissions set.




### Type Spec
```go
type Spec struct {
	Role     string   `json:"role"`     // The role of the user performing the action
	Method   string   `json:"method"`   // Method to perform on the resource
	Resource Resource `json:"resource"` // The resource on which the action is performed
	Action   Action   `json:"action"`   // The action to perform on the resource
}
```
Spec represents the ability to perform some action on a resource.

### Methods

```go
func (s Spec) String() string
```
String returns a string representation of the Spec.


```go
func (s Spec) Valid() bool
```
Valid returns true if the Spec has all required fields.







