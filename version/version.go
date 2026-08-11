// Package version exposes the build version of the application.
package version

// Version is the application version. It is overridden at build time via
// -ldflags "-X adel/version.Version=<version>" (see .goreleaser.yml and the
// Makefile). Unreleased builds keep the "dev" default.
var Version = "dev"
