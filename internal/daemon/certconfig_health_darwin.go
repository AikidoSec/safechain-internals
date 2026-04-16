//go:build darwin

package daemon

import (
	"context"
	"log"
	"time"

	"github.com/AikidoSec/safechain-internals/internal/certconfig"
	"github.com/AikidoSec/safechain-internals/internal/platform"
	"github.com/AikidoSec/safechain-internals/internal/proxy"
)

// runCertconfigHealthLoop periodically checks whether certificate configuration
// has been applied for the current console user and repairs it if not.
//
// This covers drift after install: shell config files can be overwritten, the
// generated CA bundle can be deleted, or the daemon can restart after the
// initial install already completed.
func (d *Daemon) runCertconfigHealthLoop(ctx context.Context) {
	defer d.wg.Done()

	// The user we last successfully configured. Reset on daemon restart so the
	// first tick always validates the current state.
	var lastHealthyUser string

	check := func() {
		if !proxy.ProxyCAInstalled() {
			// CA not in keychain yet — setup wizard hasn't completed, nothing to do.
			return
		}

		username, _, _, _, err := platform.GetCurrentUser(ctx)
		if err != nil {
			log.Printf("certconfig health: no console user yet: %v", err)
			return
		}

		if username == lastHealthyUser && !certconfig.NeedsRepair(ctx) {
			return // already healthy for this user
		}

		log.Printf("certconfig health: running install for user %q", username)
		if err := certconfig.Install(ctx); err != nil {
			log.Printf("certconfig health: install failed: %v", err)
			return
		}

		lastHealthyUser = username
		log.Printf("certconfig health: configuration healthy for user %q", username)
	}

	// Run once shortly after startup to catch the common login race where the
	// daemon starts a few seconds before the GUI session is ready.
	initialTimer := time.NewTimer(15 * time.Second)
	defer initialTimer.Stop()

	select {
	case <-initialTimer.C:
		check()
	case <-ctx.Done():
		return
	}

	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			check()
		case <-ctx.Done():
			return
		}
	}
}
