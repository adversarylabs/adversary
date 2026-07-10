//go:build !darwin

package archiveutil

import "os"

func PreparePublish(root *os.Root) error   { return Seal(root) }
func ValidatePrepared(root *os.Root) error { return ValidateSealed(root) }
