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

	"github.com/AikidoSec/safechain-agent/internal/ui/icons"
	"github.com/AikidoSec/safechain-agent/internal/ui/theme"
)

type BlockedView struct {
	Text      string
	PackageId string
	OnOK      func()
	OnBypass  func()

	okBtn     widget.Clickable
	bypassBtn widget.Clickable
}

func NewBlockedView(text, packageId string, onOK, onBypass func()) *BlockedView {
	return &BlockedView{
		Text:      text,
		PackageId: packageId,
		OnOK:      onOK,
		OnBypass:  onBypass,
	}
}

func (v *BlockedView) Layout(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	if v.okBtn.Clicked(gtx) && v.OnOK != nil {
		v.OnOK()
	}
	if v.bypassBtn.Clicked(gtx) && v.OnBypass != nil {
		v.OnBypass()
	}

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return v.layoutHeader(gtx, th)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return v.layoutContent(gtx, th)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return v.layoutFooter(gtx, th)
		}),
	)
}

func (v *BlockedView) layoutHeader(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	return layout.Inset{
		Top: unit.Dp(20), Bottom: unit.Dp(16),
		Left: unit.Dp(22), Right: unit.Dp(22),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return icons.LayoutAikidoLogoFull(gtx, unit.Dp(20), th.Primary, th.TextLogo, th.Theme)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				// Separator line
				height := gtx.Dp(unit.Dp(1))
				rect := image.Rectangle{Max: image.Point{X: gtx.Constraints.Max.X, Y: height}}
				paint.FillShape(gtx.Ops, th.HeaderBorder, clip.Rect(rect).Op())
				return layout.Dimensions{Size: image.Point{X: gtx.Constraints.Max.X, Y: height}}
			}),
		)
	})
}

func (v *BlockedView) layoutContent(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	return layout.Inset{
		Top: unit.Dp(16), Bottom: unit.Dp(24),
		Left: unit.Dp(22), Right: unit.Dp(22),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return icons.LayoutIndicator(gtx, unit.Dp(40), th.IndicatorBg, th.IndicatorBorder, th.ShieldIconColor)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(24)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				label := material.Body1(th.Theme, "SafeChain blocked a potentially malicious npm package:")
				label.Color = th.TextPrimary
				label.TextSize = unit.Sp(16)
				return label.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				label := material.Body2(th.Theme, v.Text)
				label.Color = th.TextSecondary
				label.TextSize = unit.Sp(12)
				return label.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(16)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return v.layoutPackageBox(gtx, th)
			}),
		)
	})
}

func (v *BlockedView) layoutPackageBox(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	return layoutRoundedBox(gtx, th.PackageBoxBg, th.PackageBoxBorder, 8, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Top: unit.Dp(16), Bottom: unit.Dp(16),
			Left: unit.Dp(18), Right: unit.Dp(18),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			label := material.Body1(th.Theme, v.PackageId)
			label.Color = th.TextPrimary
			label.TextSize = unit.Sp(12)
			return label.Layout(gtx)
		})
	})
}

func (v *BlockedView) layoutFooter(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	return layoutWithBackground(gtx, th.FooterBg, th.HeaderBorder, false, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Top: unit.Dp(14), Bottom: unit.Dp(14),
			Left: unit.Dp(22), Right: unit.Dp(22),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if v.OnBypass == nil {
						return layout.Dimensions{}
					}
					return v.layoutBypassButton(gtx, th)
				}),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Dimensions{}
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					btn := material.Button(th.Theme, &v.okBtn, "OK")
					btn.Background = th.Primary
					btn.CornerRadius = th.ButtonRadius
					btn.Inset = layout.Inset{
						Top: th.ButtonPaddingY, Bottom: th.ButtonPaddingY,
						Left: th.ButtonPaddingX, Right: th.ButtonPaddingX,
					}
					return btn.Layout(gtx)
				}),
			)
		})
	})
}

func (v *BlockedView) layoutBypassButton(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	macro := op.Record(gtx.Ops)
	dims := layout.Inset{
		Top: th.ButtonPaddingY, Bottom: th.ButtonPaddingY,
		Left: th.ButtonPaddingX, Right: th.ButtonPaddingX,
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		label := material.Body2(th.Theme, "Request ByPass")
		label.Color = th.RequestBypassColor
		label.TextSize = unit.Sp(12)
		return label.Layout(gtx)
	})
	call := macro.Stop()

	// Draw button background and border
	rr := clip.RRect{
		Rect: image.Rectangle{Max: dims.Size},
		NE:   gtx.Dp(th.ButtonRadius), NW: gtx.Dp(th.ButtonRadius),
		SE:   gtx.Dp(th.ButtonRadius), SW: gtx.Dp(th.ButtonRadius),
	}
	paint.FillShape(gtx.Ops, th.SecondaryBtnBg, rr.Op(gtx.Ops))
	paint.FillShape(gtx.Ops, th.SecondaryBtnBorder, clip.Stroke{Path: rr.Path(gtx.Ops), Width: 1}.Op())

	// Register click area
	defer clip.Rect(image.Rectangle{Max: dims.Size}).Push(gtx.Ops).Pop()
	v.bypassBtn.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Dimensions{Size: dims.Size}
	})

	call.Add(gtx.Ops)
	return dims
}

// Suppress unused import warning
var _ = color.NRGBA{}
