package theme

import (
	"image/color"

	"gioui.org/unit"
	"gioui.org/widget/material"
)

type AikidoTheme struct {
	*material.Theme
	Primary            color.NRGBA
	Danger             color.NRGBA
	Background         color.NRGBA
	HeaderBg           color.NRGBA
	FooterBg           color.NRGBA
	PackageBoxBg       color.NRGBA
	SecondaryBtnBg     color.NRGBA
	HeaderBorder       color.NRGBA
	PackageBoxBorder   color.NRGBA
	SecondaryBtnBorder color.NRGBA
	TextPrimary        color.NRGBA
	TextSecondary      color.NRGBA
	ShieldIconColor    color.NRGBA
	AlertTriangleColor color.NRGBA
	ButtonRadius       unit.Dp
}

func NewAikidoTheme() *AikidoTheme {
	th := material.NewTheme()

	aikidoTheme := &AikidoTheme{
		Theme:              th,
		Primary:            rgb(0x6551F3),
		Danger:             rgb(0xFF4A3E),
		Background:         rgb(0xFAFAFA),
		HeaderBg:           rgb(0xFAFAFA),
		FooterBg:           rgb(0xF5F5F6),
		PackageBoxBg:       rgb(0xF5F5F6),
		SecondaryBtnBg:     rgb(0xFFFFFF),
		HeaderBorder:       rgb(0xE5E5E9),
		PackageBoxBorder:   rgb(0xE5E5E9),
		SecondaryBtnBorder: rgb(0xD6D6DC),
		TextPrimary:        rgb(0x010024),
		TextSecondary:      rgb(0x37364D),
		ShieldIconColor:    rgb(0xCC3B32),
		AlertTriangleColor: rgb(0xFF9715),
		ButtonRadius:       unit.Dp(16),
	}

	th.Palette.Bg = aikidoTheme.Background
	th.Palette.Fg = aikidoTheme.TextPrimary
	th.Palette.ContrastBg = aikidoTheme.Primary
	th.Palette.ContrastFg = rgb(0xFFFFFF)

	return aikidoTheme
}

func rgb(c uint32) color.NRGBA {
	return color.NRGBA{
		R: uint8(c >> 16),
		G: uint8(c >> 8),
		B: uint8(c),
		A: 0xFF,
	}
}
