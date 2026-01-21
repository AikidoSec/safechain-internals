package icons

import (
	"image"
	"image/color"

	"gioui.org/f32"
	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/text"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

func LayoutAikidoLogo(gtx layout.Context, size unit.Dp, logoColor color.NRGBA) layout.Dimensions {
	scale := float32(gtx.Dp(size)) / 24.0

	var path clip.Path
	path.Begin(gtx.Ops)

	// M18.9102 4H5V9.02389H18.9102V4Z
	path.MoveTo(f32.Pt(18.9102*scale, 4*scale))
	path.LineTo(f32.Pt(5*scale, 4*scale))
	path.LineTo(f32.Pt(5*scale, 9.02389*scale))
	path.LineTo(f32.Pt(18.9102*scale, 9.02389*scale))
	path.LineTo(f32.Pt(18.9102*scale, 4*scale))
	path.Close()

	paint.FillShape(gtx.Ops, logoColor, clip.Outline{Path: path.End()}.Op())

	// M5 13.736C8.95729 10.0744 14.9529 10.0743 18.9102 13.736V19.9972L18.9075 20L11.9551 12.787L5.00273 20L5 19.9972V13.736Z
	path.Begin(gtx.Ops)
	path.MoveTo(f32.Pt(5*scale, 13.736*scale))
	path.CubeTo(
		f32.Pt(8.95729*scale, 10.0744*scale),
		f32.Pt(14.9529*scale, 10.0743*scale),
		f32.Pt(18.9102*scale, 13.736*scale),
	)
	path.LineTo(f32.Pt(18.9102*scale, 19.9972*scale))
	path.LineTo(f32.Pt(18.9075*scale, 20*scale))
	path.LineTo(f32.Pt(11.9551*scale, 12.787*scale))
	path.LineTo(f32.Pt(5.00273*scale, 20*scale))
	path.LineTo(f32.Pt(5*scale, 19.9972*scale))
	path.LineTo(f32.Pt(5*scale, 13.736*scale))
	path.Close()

	paint.FillShape(gtx.Ops, logoColor, clip.Outline{Path: path.End()}.Op())

	dim := gtx.Dp(size)
	return layout.Dimensions{Size: image.Point{X: dim, Y: dim}}
}

func LayoutAikidoLogoFull(gtx layout.Context, height unit.Dp, primaryColor, textColor color.NRGBA, th *material.Theme) layout.Dimensions {
	return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return LayoutAikidoLogo(gtx, height, primaryColor)
		}),
		layout.Rigid(layout.Spacer{Width: unit.Dp(8)}.Layout),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return LayoutAikidoText(gtx, height, textColor, th)
		}),
	)
}

func LayoutAikidoText(gtx layout.Context, height unit.Dp, textColor color.NRGBA, th *material.Theme) layout.Dimensions {
	fontSize := unit.Sp(float32(height) * 0.9)
	label := material.Label(th, fontSize, "aikido")
	label.Color = textColor
	label.Font.Weight = font.Bold
	label.Alignment = text.Start
	return label.Layout(gtx)
}
