//go:build !linux && !darwin && !windows

package initproject

import "fmt"

func publishNoReplace(_, _ string) error {
	return fmt.Errorf("atomic no-replace project publication is unsupported on this platform")
}
