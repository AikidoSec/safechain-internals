package icons

import (
	"image"
	"image/color"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
)

func LayoutIndicator(gtx layout.Context, size unit.Dp, bg, border, iconColor color.NRGBA) layout.Dimensions {
	dim := gtx.Dp(size)
	radius := dim / 4

	// Draw background
	rr := clip.RRect{
		Rect: image.Rectangle{Max: image.Point{X: dim, Y: dim}},
		NE:   radius, NW: radius, SE: radius, SW: radius,
	}
	paint.FillShape(gtx.Ops, bg, rr.Op(gtx.Ops))
	paint.FillShape(gtx.Ops, border, clip.Stroke{Path: rr.Path(gtx.Ops), Width: 1}.Op())

	// Draw shield icon centered
	iconSize := unit.Dp(float32(size) * 0.6)
	offset := (dim - gtx.Dp(iconSize)) / 2

	defer op.Offset(image.Point{X: offset, Y: offset}).Push(gtx.Ops).Pop()
	LayoutShieldBlock(gtx, iconSize, iconColor)

	return layout.Dimensions{Size: image.Point{X: dim, Y: dim}}
}
