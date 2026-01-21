package views

import (
	"gioui.org/layout"
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
	return layoutWithBackground(gtx, th.HeaderBg, th.HeaderBorder, true, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Top: unit.Dp(20), Bottom: unit.Dp(20),
			Left: unit.Dp(24), Right: unit.Dp(24),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			return layout.Flex{Axis: layout.Horizontal, Alignment: layout.Middle}.Layout(gtx,
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					return icons.LayoutShieldBlock(gtx, unit.Dp(20), th.ShieldIconColor)
				}),
				layout.Rigid(layout.Spacer{Width: unit.Dp(12)}.Layout),
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					label := material.Body1(th.Theme, "Blocked package")
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

func (v *BlockedView) layoutContent(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	return layout.Inset{
		Top: unit.Dp(24), Bottom: unit.Dp(24),
		Left: unit.Dp(24), Right: unit.Dp(24),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				label := material.Body1(th.Theme, v.Text)
				label.Color = th.TextSecondary
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
	return layoutRoundedBox(gtx, th.PackageBoxBg, th.PackageBoxBorder, 12, func(gtx layout.Context) layout.Dimensions {
		return layout.Inset{
			Top: unit.Dp(16), Bottom: unit.Dp(16),
			Left: unit.Dp(18), Right: unit.Dp(18),
		}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
			label := material.Body1(th.Theme, v.PackageId)
			label.Color = th.TextPrimary
			return label.Layout(gtx)
		})
	})
}

func (v *BlockedView) layoutFooter(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
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
					btn := material.Button(th.Theme, &v.okBtn, "OK")
					btn.Background = th.Primary
					btn.CornerRadius = th.ButtonRadius
					return btn.Layout(gtx)
				}),
			)
		})
	})
}
