package main

import (
	"debug/buildinfo"
	"runtime/debug"
	"testing"
)

func TestGoBinaryTarget(t *testing.T) {
	info := &buildinfo.BuildInfo{Settings: []debug.BuildSetting{
		{Key: "CGO_ENABLED", Value: "0"},
		{Key: "GOOS", Value: "windows"},
		{Key: "GOARCH", Value: "amd64"},
	}}
	goos, goarch := goBinaryTarget(info)
	if goos != "windows" || goarch != "amd64" {
		t.Fatalf("goBinaryTarget() = %s/%s, want windows/amd64", goos, goarch)
	}
}

func TestGoBinaryTargetMissingSettings(t *testing.T) {
	goos, goarch := goBinaryTarget(&buildinfo.BuildInfo{})
	if goos != "" || goarch != "" {
		t.Fatalf("goBinaryTarget() = %q/%q, want empty target", goos, goarch)
	}
}
