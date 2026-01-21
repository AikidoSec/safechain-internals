package ui

import (
	"gioui.org/unit"
)

func ShowBlockedModal(text, packageId, title string, onBypass func()) error {
	return RunBlockedModal(text, packageId, title, unit.Dp(550), unit.Dp(350), onBypass)
}
