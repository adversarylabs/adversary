//go:build windows

package pack

import "os"

func validateBuildStateOwner(info os.FileInfo) error { return nil }
