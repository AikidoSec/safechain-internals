package ui

import (
	"gioui.org/unit"
)

func ShowBlockedModal(title, subtitle, packageId, windowTitle string, onBypass func()) error {
	return RunBlockedModal(title, subtitle, packageId, windowTitle, unit.Dp(600), unit.Dp(380), onBypass)
}
