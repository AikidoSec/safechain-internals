package ui

import (
	"gioui.org/unit"
)

func ShowBlockedModal(title, subtitle, packageId, windowTitle string, onBypass func()) error {
	return RunBlockedModal(title, subtitle, packageId, title, unit.Dp(550), unit.Dp(350), onBypass)
}
