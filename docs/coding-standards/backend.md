# Coding Standard

## Dependency

* Web Framework: net/http
* Web Router: http.ServeMux
* Test Assertion: github.com/alecthomas/assert/v2
* CLI command parser: github.com/alecthomas/kong
* CLI coloring: github.com/fatih/color
* YAML: github.com/goccy/go-yaml

## Coding Style

* Use maps package and slices package as much as possible to reduce for loop
* Use `any` instead of `interface{}`

## Check

* go tool golangci-lint run