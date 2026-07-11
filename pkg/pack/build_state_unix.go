//go:build !windows

package pack

import (
	"fmt"
	"os"
	"syscall"
)

func validateBuildStateOwner(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("build state root is not owned by the current user")
	}
	return nil
}
