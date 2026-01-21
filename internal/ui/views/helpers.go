package views

import (
	"image"
	"image/color"

	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
	"github.com/AikidoSec/safechain-agent/internal/ui/theme"
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

func layoutButtonWithBorder(gtx layout.Context, border color.NRGBA, radius unit.Dp, content layout.Widget) layout.Dimensions {
	macro := op.Record(gtx.Ops)
	dims := content(gtx)
	call := macro.Stop()

	r := gtx.Dp(radius)
	rr := clip.RRect{
		Rect: image.Rectangle{Max: dims.Size},
		NE:   r, NW: r, SE: r, SW: r,
	}
	paint.FillShape(gtx.Ops, border, clip.Stroke{Path: rr.Path(gtx.Ops), Width: 1}.Op())

	call.Add(gtx.Ops)
	return dims
}

func layoutSecondaryButton(gtx layout.Context, th *theme.AikidoTheme, clickable *widget.Clickable, text string, textColor color.NRGBA) layout.Dimensions {
	return layoutButtonWithBorder(gtx, th.SecondaryBtnBorder, th.ButtonRadius, func(gtx layout.Context) layout.Dimensions {
		btn := material.Button(th.Theme, clickable, text)
		btn.Background = th.SecondaryBtnBg
		btn.Color = textColor
		btn.CornerRadius = th.ButtonRadius
		btn.Inset = layout.Inset{
			Top: th.ButtonPaddingY, Bottom: th.ButtonPaddingY,
			Left: th.ButtonPaddingX, Right: th.ButtonPaddingX,
		}
		return btn.Layout(gtx)
	})
}
