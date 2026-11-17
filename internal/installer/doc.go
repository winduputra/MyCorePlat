// Package installer orchestrates the lifecycle of dynamically uploaded tool
// packages: validating a package, building its container image, provisioning
// the per-tool HMAC secret, running the container, and registering the tool in
// the Core database.
//
// The installer is a SEPARATE service from Core on purpose: it is the only
// component that talks to the Docker Engine API, and it is expected to run with
// the minimum privileges required to build and run tool containers. Core never
// receives the Docker socket.
//
// The heavy lifting (Docker, filesystem, database) is hidden behind small
// interfaces defined in this package so the orchestration logic can be unit
// tested without a running Docker daemon or database.
package installer
