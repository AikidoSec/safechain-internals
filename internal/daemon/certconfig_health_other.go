//go:build !darwin

package daemon

import "context"

func (d *Daemon) runCertconfigHealthLoop(ctx context.Context) {
	defer d.wg.Done()
}
