package views

import (
	"image"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/AikidoSec/safechain-agent/internal/ui/icons"
	"github.com/AikidoSec/safechain-agent/internal/ui/theme"
)

type RequestBypassView struct {
	OnCancel  func()
	OnConfirm func()

	cancelBtn  widget.Clickable
	confirmBtn widget.Clickable
}

func NewRequestBypassView(onCancel, onConfirm func()) *RequestBypassView {
	return &RequestBypassView{
		OnCancel:  onCancel,
		OnConfirm: onConfirm,
	}
}

func (v *RequestBypassView) Layout(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	if v.cancelBtn.Clicked(gtx) && v.OnCancel != nil {
		v.OnCancel()
	}
	if v.confirmBtn.Clicked(gtx) && v.OnConfirm != nil {
		v.OnConfirm()
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

func (v *RequestBypassView) layoutHeader(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	return layout.Inset{
		Top: unit.Dp(20), Bottom: unit.Dp(0),
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

func (v *RequestBypassView) layoutContent(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	return layout.Inset{
		Top: unit.Dp(18), Bottom: unit.Dp(24),
		Left: unit.Dp(22), Right: unit.Dp(22),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return icons.LayoutWarningIndicator(gtx, unit.Dp(40), th.IndicatorWarningBg, th.IndicatorWarningBorder, th.AlertTriangleColor)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				label := material.Label(th.Theme, unit.Sp(18), "Are you sure you want to bypass?")
				label.Color = th.TextPrimary
				label.Font.Weight = font.Medium
				return label.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				label := material.Label(th.Theme, unit.Sp(14), "Are you sure you want to bypass SafeChain Ultimate and risk installing malware?")
				label.Color = th.TextSecondary
				return label.Layout(gtx)
			}),
		)
	})
}

func (v *RequestBypassView) layoutFooter(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	return layoutWithBackground(gtx, th.FooterBg, th.HeaderBorder, false, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Top: unit.Dp(14), Bottom: unit.Dp(14),
			Left: unit.Dp(22), Right: unit.Dp(22),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceStart}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Dimensions{}
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return layoutSecondaryButton(gtx, th, &v.cancelBtn, "Cancel", th.TextSecondary)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					btn := material.Button(th.Theme, &v.confirmBtn, "I understand the Risks")
					btn.Background = th.Danger
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
