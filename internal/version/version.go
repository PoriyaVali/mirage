// Package version holds build metadata shared by the measurement commands.
package version

import (
	"fmt"
	"runtime"
)

// Version and Commit are set by release builds with -ldflags -X.
var Version = "dev"
var Commit = "unknown"

func String() string {
	return fmt.Sprintf("%s commit=%s go=%s %s/%s", Version, Commit, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
