package ui

import (
	"image/color"

	"gioui.org/widget/material"
)

type AikidoTheme struct {
	*material.Theme
	Primary    color.NRGBA
	Background color.NRGBA
	Danger     color.NRGBA
}

// NewAikidoTheme creates a theme with white background and custom primary color
func NewAikidoTheme() *AikidoTheme {
	th := material.NewTheme()

	aikidoTheme := &AikidoTheme{
		Theme:      th,
		Primary:    rgb(0x2196F3), // Material Blue
		Background: rgb(0xFFFFFF), // White background
		Danger:     rgb(0xFF0000),
	}

	th.Palette.Bg = aikidoTheme.Background
	th.Palette.Fg = rgb(0x212121)

	// Primary color + White text on buttons
	th.Palette.ContrastBg = aikidoTheme.Primary
	th.Palette.ContrastFg = rgb(0xFFFFFF)

	return aikidoTheme
}
