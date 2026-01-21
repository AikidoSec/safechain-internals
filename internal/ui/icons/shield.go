package icons

import (
	"image"
	"image/color"
	"math"

	"gioui.org/f32"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
)

func LayoutShieldBlock(gtx layout.Context, size unit.Dp, iconColor color.NRGBA) layout.Dimensions {
	scale := float32(gtx.Dp(size)) / 24.0
	strokeWidth := 2.0 * scale

	var path clip.Path

	// Shield outline
	path.Begin(gtx.Ops)
	path.MoveTo(f32.Pt(12*scale, 2*scale))
	path.LineTo(f32.Pt(4*scale, 5*scale))
	path.LineTo(f32.Pt(4*scale, 11*scale))
	path.CubeTo(
		f32.Pt(4*scale, 16.55*scale),
		f32.Pt(7.42*scale, 21.74*scale),
		f32.Pt(12*scale, 23*scale),
	)
	path.CubeTo(
		f32.Pt(16.58*scale, 21.74*scale),
		f32.Pt(20*scale, 16.55*scale),
		f32.Pt(20*scale, 11*scale),
	)
	path.LineTo(f32.Pt(20*scale, 5*scale))
	path.Close()
	paint.FillShape(gtx.Ops, iconColor, clip.Stroke{Path: path.End(), Width: strokeWidth}.Op())

	// Prohibition circle
	cx, cy := 12*scale, 12*scale
	radius := 5 * scale
	drawCircle(&path, gtx, cx, cy, radius)
	paint.FillShape(gtx.Ops, iconColor, clip.Stroke{Path: path.End(), Width: strokeWidth}.Op())

	// Diagonal line through circle
	path.Begin(gtx.Ops)
	offset := radius * 0.707 // cos(45°)
	path.MoveTo(f32.Pt(cx-offset, cy-offset))
	path.LineTo(f32.Pt(cx+offset, cy+offset))
	paint.FillShape(gtx.Ops, iconColor, clip.Stroke{Path: path.End(), Width: strokeWidth}.Op())

	dim := gtx.Dp(size)
	return layout.Dimensions{Size: image.Point{X: dim, Y: dim}}
}

func drawCircle(path *clip.Path, gtx layout.Context, cx, cy, radius float32) {
	path.Begin(gtx.Ops)
	segments := 32
	for i := 0; i <= segments; i++ {
		angle := float64(i) * 2 * math.Pi / float64(segments)
		x := cx + radius*float32(math.Cos(angle))
		y := cy + radius*float32(math.Sin(angle))
		if i == 0 {
			path.MoveTo(f32.Pt(x, y))
		} else {
			path.LineTo(f32.Pt(x, y))
		}
	}
	path.Close()
}
