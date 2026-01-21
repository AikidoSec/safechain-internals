package views

import (
	"image"
	"image/color"

	"gioui.org/font"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"

	"github.com/AikidoSec/safechain-internals/internal/ui/icons"
	"github.com/AikidoSec/safechain-internals/internal/ui/theme"
)

type BlockedView struct {
	Title     string
	Subtitle  string
	PackageId string
	OnOK      func()
	OnBypass  func()

	okBtn     widget.Clickable
	bypassBtn widget.Clickable
}

func NewBlockedView(title, subtitle, packageId string, onOK, onBypass func()) *BlockedView {
	return &BlockedView{
		Title:     title,
		Subtitle:  subtitle,
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

func (v *BlockedView) layoutContent(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	return layout.Inset{
		Top: unit.Dp(18), Bottom: unit.Dp(24),
		Left: unit.Dp(22), Right: unit.Dp(22),
	}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return icons.LayoutIndicator(gtx, unit.Dp(40), th.IndicatorBg, th.IndicatorBorder, th.ShieldIconColor)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(18)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				label := material.Label(th.Theme, unit.Sp(18), v.Title)
				label.Color = th.TextPrimary
				label.Font.Weight = font.Medium
				return label.Layout(gtx)
			}),
			layout.Rigid(layout.Spacer{Height: unit.Dp(8)}.Layout),
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				label := material.Label(th.Theme, unit.Sp(14), v.Subtitle)
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
			return layout.Flex{Axis: layout.Horizontal, Spacing: layout.SpaceStart}.Layout(gtx,
				layout.Flexed(1, func(gtx layout.Context) layout.Dimensions {
					return layout.Dimensions{}
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if v.OnBypass == nil {
						return layout.Dimensions{}
					}
					return v.layoutBypassButton(gtx, th)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					if v.OnBypass == nil {
						return layout.Dimensions{}
					}
					return layout.Spacer{Width: unit.Dp(12)}.Layout(gtx)
				}),
				layout.Rigid(func(gtx layout.Context) layout.Dimensions {
					btn := material.Button(th.Theme, &v.okBtn, "OK")
					btn.Background = th.Primary
					btn.CornerRadius = th.ButtonRadius
					btn.Inset = layout.Inset{
						Top: th.ButtonPaddingY, Bottom: th.ButtonPaddingY,
						Left: unit.Dp(24), Right: unit.Dp(24),
					}
					return btn.Layout(gtx)
				}),
			)
		})
	})
}

func (v *BlockedView) layoutBypassButton(gtx layout.Context, th *theme.AikidoTheme) layout.Dimensions {
	return layoutSecondaryButton(gtx, th, &v.bypassBtn, "Request Bypass", th.RequestBypassColor)
}

// Suppress unused import warning
var _ = color.NRGBA{}
