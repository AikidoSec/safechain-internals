package ui

import (
	"gioui.org/unit"
)

// ShowBlockedModal is a convenience function to display a blocked modal dialog.
// It creates the modal and runs the Gio application.
func ShowBlockedModal(text string, title string, onBypass func()) error {
	modal := CreateBlockedModal(text, onBypass)
	return RunModalApp(modal, title, unit.Dp(450), unit.Dp(250))
}
