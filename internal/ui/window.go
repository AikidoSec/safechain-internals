package ui

import (
	"fmt"
	"image"
	"log"
	"os"

	"gioui.org/app"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
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
	var lastSize image.Point

	for {
		e := w.Event()
		switch e := e.(type) {
		case app.DestroyEvent:
			return e.Err
		case app.FrameEvent:
			gtx := app.NewContext(&ops, e)
			dims := a.Layout(gtx)
			fmt.Println("dims: ", dims)
			// Update window size if content size changed
			newSize := image.Point{X: dims.Size.X, Y: dims.Size.Y}
			if newSize != lastSize && newSize.X > 0 && newSize.Y > 0 {
				w.Option(app.Size(
					unit.Dp(float32(newSize.X)/gtx.Metric.PxPerDp),
					unit.Dp(float32(newSize.Y)/gtx.Metric.PxPerDp),
				))
				lastSize = newSize
			}

			e.Frame(gtx.Ops)
		}
	}
}

func (a *ModalApp) Layout(gtx layout.Context) layout.Dimensions {
	return a.modal.Layout(gtx, a.theme)
}
