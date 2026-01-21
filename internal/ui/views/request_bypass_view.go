package views

import (
	"gioui.org/layout"
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
	return layoutWithBackground(gtx, th.HeaderBg, th.HeaderBorder, true, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Top: unit.Dp(20), Bottom: unit.Dp(20),
			Left: unit.Dp(24), Right: unit.Dp(24),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return icons.LayoutAlertTriangle(gtx, unit.Dp(20), th.AlertTriangleColor)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					label := material.Body1(th.Theme, "Are you sure you want to bypass?")
					label.Color = th.TextPrimary
					label.TextSize = unit.Sp(18)
					return label.Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return icons.LayoutAikidoLogo(gtx, unit.Dp(20), th.Primary)
				}),
			)
		})
	})
}

func (v *RequestBypassView) layoutContent(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	return layout.Inset{
		Top: unit.Dp(24), Bottom: unit.Dp(24),
		Left: unit.Dp(24), Right: unit.Dp(24),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		label := material.Body1(th.Theme, "Are you sure you want to bypass SafeChain Ultimate and risk installing malware?")
		label.Color = th.TextSecondary
		return label.Layout(gtx)
	})
}

func (v *RequestBypassView) layoutFooter(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	return layoutWithBackground(gtx, th.FooterBg, th.HeaderBorder, false, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Top: unit.Dp(16), Bottom: unit.Dp(16),
			Left: unit.Dp(24), Right: unit.Dp(24),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceStart}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Dimensions{}
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					btn := material.Button(th.Theme, &v.cancelBtn, "Cancel")
					btn.Background = th.SecondaryBtnBg
					btn.Color = th.TextSecondary
					btn.CornerRadius = th.ButtonRadius
					btn.Inset = layout.Inset{
						Top: th.ButtonPaddingY, Bottom: th.ButtonPaddingY,
						Left: th.ButtonPaddingX, Right: th.ButtonPaddingX,
					}
					return btn.Layout(gtx)
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
