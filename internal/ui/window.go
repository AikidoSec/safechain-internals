package ui

import (
	"log"
	"os"

	"gioui.org/app"
	"gioui.org/io/system"
	"gioui.org/layout"
	"gioui.org/op"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

type ModalApp struct {
	theme *material.Theme
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
		theme: NewAikidoTheme().Theme,
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
	return a.modal.Layout(gtx, a.theme)
}
