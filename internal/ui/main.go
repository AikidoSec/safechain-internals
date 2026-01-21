package ui

import (
	"gioui.org/unit"
)

// ShowBlockedModal is a convenience function to display a blocked modal dialog.
// It creates the modal and runs the Gio application.
func ShowBlockedModal(text string, title string, onBypass func()) error {
	isBypassEnabled := onBypass != nil
	modal := CreateBlockedModal(text, isBypassEnabled, onBypass)
	return RunModalApp(modal, title, unit.Dp(550), unit.Dp(350))
}
