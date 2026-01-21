package icons

import (
	"image"
	"image/color"

	"gioui.org/f32"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
)

func LayoutAlertTriangle(gtx layout.Context, size unit.Dp, iconColor color.NRGBA) layout.Dimensions {
	scale := float32(gtx.Dp(size)) / 24.0
	white := color.NRGBA{R: 255, G: 255, B: 255, A: 255}

	var path clip.Path
	path.Begin(gtx.Ops)

	// Triangle shape
	path.MoveTo(f32.Pt(12*scale, 2*scale))
	path.LineTo(f32.Pt(1*scale, 21*scale))
	path.LineTo(f32.Pt(23*scale, 21*scale))
	path.Close()

	paint.FillShape(gtx.Ops, iconColor, clip.Outline{Path: path.End()}.Op())

	// Exclamation mark - vertical line
	path.Begin(gtx.Ops)
	path.MoveTo(f32.Pt(11*scale, 9*scale))
	path.LineTo(f32.Pt(13*scale, 9*scale))
	path.LineTo(f32.Pt(13*scale, 14*scale))
	path.LineTo(f32.Pt(11*scale, 14*scale))
	path.Close()

	paint.FillShape(gtx.Ops, white, clip.Outline{Path: path.End()}.Op())

	// Exclamation mark - dot
	path.Begin(gtx.Ops)
	path.MoveTo(f32.Pt(11*scale, 16*scale))
	path.LineTo(f32.Pt(13*scale, 16*scale))
	path.LineTo(f32.Pt(13*scale, 18*scale))
	path.LineTo(f32.Pt(11*scale, 18*scale))
	path.Close()

	paint.FillShape(gtx.Ops, white, clip.Outline{Path: path.End()}.Op())

	dim := gtx.Dp(size)
	return layout.Dimensions{Size: image.Point{X: dim, Y: dim}}
}
