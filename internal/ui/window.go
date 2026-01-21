package ui

import (
	"image"
	"log"
	"os"

	"gioui.org/app"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
)

type ModalApp struct {
	theme *AikidoTheme
	modal *Modal
}

// RunModalApp creates and runs a Gio application with the given modal
func RunModalApp(modal *Modal, title string, width, height unit.Dp) error {
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
	return nil
}

func runModal(w *app.Window, modal *Modal) error {
	a := &ModalApp{
		theme: NewAikidoTheme(),
		modal: modal,
	}

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
	// Fill background with a slightly darker background than the modal.
	paint.Fill(gtx.Ops, darken(a.theme.Bg, 0.95))

	// Center content
	return layout.Center.Layout(gtx, func(gtx layout.Context) layout.Dimensions {
		return layout.Flex{
			Axis:      layout.Vertical,
			Alignment: layout.Middle,
		}.Layout(gtx,
			// SVG Image
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return layoutAikidoLogo(gtx, unit.Dp(64))
			}),
			// Spacing
			layout.Rigid(layout.Spacer{Height: unit.Dp(5)}.Layout),
			// Modal with rounded corners
			layout.Rigid(func(gtx layout.Context) layout.Dimensions {
				return a.layoutRoundedModal(gtx)
			}),
		)
	})
}

func (a *ModalApp) layoutRoundedModal(gtx layout.Context) layout.Dimensions {
	// Create a macro to capture the modal layout
	macro := op.Record(gtx.Ops)
	dims := a.modal.Layout(gtx, a.theme)
	call := macro.Stop()

	// Draw rounded rectangle background
	rr := image.Rectangle{
		Max: dims.Size,
	}

	radius := 12
	clip.RRect{
		Rect: rr,
		NE:   radius, NW: radius, SE: radius, SW: radius,
	}.Push(gtx.Ops)

	paint.Fill(gtx.Ops, a.theme.Theme.Bg)

	call.Add(gtx.Ops)

	return dims
}
