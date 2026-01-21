package views

import (
	"image"
	"image/color"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
)

func layoutWithBackground(gtx layout.Context, bg, border color.NRGBA, borderBottom bool, content layout.Widget) layout.Dimensions {
	macro := op.Record(gtx.Ops)
	dims := content(gtx)
	call := macro.Stop()

	// Draw background
	rect := image.Rectangle{Max: dims.Size}
	paint.FillShape(gtx.Ops, bg, clip.Rect(rect).Op())

	// Draw border
	if borderBottom {
		borderRect := image.Rectangle{
			Min: image.Point{X: 0, Y: dims.Size.Y - 1},
			Max: dims.Size,
		}
		paint.FillShape(gtx.Ops, border, clip.Rect(borderRect).Op())
	} else {
		borderRect := image.Rectangle{
			Min: image.Point{X: 0, Y: 0},
			Max: image.Point{X: dims.Size.X, Y: 1},
		}
		paint.FillShape(gtx.Ops, border, clip.Rect(borderRect).Op())
	}

	call.Add(gtx.Ops)
	return dims
}

func layoutRoundedBox(gtx layout.Context, bg, border color.NRGBA, radius int, content layout.Widget) layout.Dimensions {
	macro := op.Record(gtx.Ops)
	dims := content(gtx)
	call := macro.Stop()

	rr := clip.RRect{
		Rect: image.Rectangle{Max: dims.Size},
		NE:   radius, NW: radius, SE: radius, SW: radius,
	}
	paint.FillShape(gtx.Ops, bg, rr.Op(gtx.Ops))
	paint.FillShape(gtx.Ops, border, clip.Stroke{Path: rr.Path(gtx.Ops), Width: 1}.Op())

	call.Add(gtx.Ops)
	return dims
}
