package ui

import (
	"fmt"

	"gioui.org/unit"
)

func ShowBlockedModal(title, subtitle, packageId, packageVersion, packageHumanName, windowTitle string, onBypass func()) error {
	displayName := packageId
	if packageHumanName != "" {
		displayName = packageHumanName
	}
	displayId := displayName
	if packageVersion != "" {
		displayId = fmt.Sprintf("%s@%s", displayName, packageVersion)
	}
	return RunBlockedModal(title, subtitle, displayId, windowTitle, unit.Dp(600), unit.Dp(380), onBypass)
}
