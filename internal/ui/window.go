package ui

import (
	"log"
	"os"

	"gioui.org/app"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

type ModalApp struct {
	theme *material.Theme
	modal *Modal
}

// RunModalApp creates and runs a Gio application with the given modal
func RunModalApp(modal *Modal, title string, width, height unit.Dp) {
	go func() {
		w := new(app.Window)
		w.Option(app.Title(title))
		w.Option(app.Size(width, height))

		if err := runModal(w, modal); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}()
	app.Main()
}

func runModal(w *app.Window, modal *Modal) error {
	th := material.NewTheme()
	a := &ModalApp{
		theme: th,
		modal: modal,
	}

	// Set up modal close handler to close the window
	modal.Close = func() {
		w.Perform(system.ActionClose)
	}

	var ops op.Ops

	for {
		e := w.Event()
		switch e := e.(type) {
		case app.DestroyEvent:
			return e.Err
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			a.Layout(gtx)
			e.Frame(gtx.Ops)
		}
	}
}

func (a *ModalApp) Layout(gtx layout.Context) layout.Dimensions {
	return a.layoutModalOverlay(gtx)
}

func (a *ModalApp) layoutModalOverlay(gtx layout.Context) layout.Dimensions {
	// Semi-transparent background
	defer clip.Rect{Max: gtx.Constraints.Max}.Push(gtx.Ops).Pop()
	paint.ColorOp{Color: rgba(0x000000, 0x88)}.Add(gtx.Ops)
	paint.PaintOp{}.Add(gtx.Ops)

	// Center the modal
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		// Modal background (white box)
		return layout.Stack{}.Layout(gtx,
			layout.Stacked(func(gtx layout.Context) layout.Dimensions {
				// Constrain modal size
				gtx.Constraints.Max.X = gtx.Dp(unit.Dp(400))
				gtx.Constraints.Min.X = gtx.Dp(unit.Dp(350))

				dims := a.modal.Layout(gtx, a.theme)

				// Draw white background for modal
				defer clip.Rect{Max: dims.Size}.Push(gtx.Ops).Pop()
				paint.ColorOp{Color: rgba(0xFFFFFF, 0xFF)}.Add(gtx.Ops)
				paint.PaintOp{}.Add(gtx.Ops)

				return dims
			}),
			layout.Expanded(func(gtx layout.Context) layout.Dimensions {
				// Constrain modal size
				gtx.Constraints.Max.X = gtx.Dp(unit.Dp(400))
				gtx.Constraints.Min.X = gtx.Dp(unit.Dp(350))

				// Render modal content on top
				return a.modal.Layout(gtx, a.theme)
			}),
		)
	})
}
