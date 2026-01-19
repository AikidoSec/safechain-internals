package ui

import (
	"gioui.org/layout"
	"gioui.org/unit"
	"gioui.org/widget"
	"gioui.org/widget/material"
)

type Modal struct {
	Text     string
	OnBypass func()
	Close    func()
	Confirm  bool

	// Persistent clickable widgets
	okBtn     widget.Clickable
	bypassBtn widget.Clickable
	yesBtn    widget.Clickable
	noBtn     widget.Clickable
}

func CreateBlockedModal(text string, onBypass func()) *Modal {
	return &Modal{
		Text:     text,
		OnBypass: onBypass,
	}
}

func (m *Modal) Layout(gtx layout.Context, th *AikidoTheme) layout.Dimensions {
	// Handle button clicks
	if m.okBtn.Clicked(gtx) && m.Close != nil {
		m.Close()
	}

	if m.bypassBtn.Clicked(gtx) {
		m.Confirm = true
	}

	if m.yesBtn.Clicked(gtx) {
		if m.OnBypass != nil {
			m.OnBypass()
		}
		if m.Close != nil {
			m.Close()
		}
	}

	if m.noBtn.Clicked(gtx) {
		m.Confirm = false
	}

	if m.Confirm {
		return m.layoutConfirm(gtx, th)
	}
	return m.layoutMain(gtx, th)
}

func (m *Modal) layoutMain(gtx layout.Context, th *AikidoTheme) layout.Dimensions {
	inset := layout.UniformInset(unit.Dp(16))

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return inset.Layout(gtx, material.Body1(th.Theme, m.Text).Layout)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{
					Axis:    layout.Horizontal,
					Spacing: layout.SpaceEnd,
				}.Layout(gtx,
					layout.Rigid(material.Button(th.Theme, &m.okBtn, "Ok").Layout),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Left: unit.Dp(8)}.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
							btn := material.Button(th.Theme, &m.bypassBtn, "Request Bypass")
							btn.Background = th.Danger
							return btn.Layout(gtx)
						})
					}),
				)
			})
		}),
	)
}

func (m *Modal) layoutConfirm(gtx layout.Context, th *AikidoTheme) layout.Dimensions {
	inset := layout.UniformInset(unit.Dp(16))

	return layout.Flex{Axis: layout.Vertical}.Layout(gtx,
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return inset.Layout(gtx, material.Body1(th.Theme, "Are you sure you want to bypass SafeChain Ultimate and risk installing malware.").Layout)
		}),
		layout.Rigid(func(gtx layout.Context) layout.Dimensions {
			return inset.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
				return layout.Flex{
					Axis:    layout.Horizontal,
					Spacing: layout.SpaceEnd,
				}.Layout(gtx,
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						return layout.Inset{Right: unit.Dp(8)}.Layout(gtx,
							material.Button(th.Theme, &m.noBtn, "Go Back").Layout,
						)
					}),
					layout.Rigid(func(gtx layout.Context) layout.Dimensions {
						btn := material.Button(th.Theme, &m.yesBtn, "I understand the risks")
						btn.Background = th.Danger
						return btn.Layout(gtx)
					}),
				)
			})
		}),
	)
}
