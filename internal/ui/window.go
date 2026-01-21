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

	"github.com/AikidoSec/safechain-agent/internal/ui/theme"
	"github.com/AikidoSec/safechain-agent/internal/ui/views"
)

type BlockedModalApp struct {
	theme         *theme.AikidoTheme
	blockedView   *views.BlockedView
	bypassView    *views.RequestBypassView
	showBypassView bool
	close         func()
}

func RunBlockedModal(text, packageId, title string, width, height unit.Dp, onBypass func()) error {
	go func() {
		w := new(app.Window)
		w.Option(app.Title(title))
		w.Option(app.Size(width, height))

		if err := runBlockedModal(w, text, packageId, onBypass); err != nil {
			log.Fatal(err)
		}
		os.Exit(0)
	}()
	app.Main()
	return nil
}

func runBlockedModal(w *app.Window, text, packageId string, onBypass func()) error {
	th := theme.NewAikidoTheme()

	closeWindow := func() {
		w.Perform(system.ActionClose)
	}

	a := &BlockedModalApp{
		theme: th,
		close: closeWindow,
	}

	a.blockedView = views.NewBlockedView(
		text,
		packageId,
		closeWindow,
		func() {
			if onBypass != nil {
				a.showBypassView = true
			}
		},
	)

	a.bypassView = views.NewRequestBypassView(
		func() {
			a.showBypassView = false
		},
		func() {
			if onBypass != nil {
				onBypass()
			}
			closeWindow()
		},
	)

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

func (a *BlockedModalApp) Layout(gtx layout.Context) layout.Dimensions {
	paint.Fill(gtx.Ops, a.theme.Background)

	return a.layoutRoundedModal(gtx)
}

func (a *BlockedModalApp) layoutRoundedModal(gtx layout.Context) layout.Dimensions {
	gtx.Constraints.Min.Y = 0

	macro := op.Record(gtx.Ops)
	var dims layout.Dimensions
	if a.showBypassView {
		dims = a.bypassView.Layout(gtx, a.theme)
	} else {
		dims = a.blockedView.Layout(gtx, a.theme)
	}
	call := macro.Stop()

	rr := image.Rectangle{Max: dims.Size}
	radius := 12
	clip.RRect{
		Rect: rr,
		NE:   radius, NW: radius, SE: radius, SW: radius,
	}.Push(gtx.Ops)

	paint.Fill(gtx.Ops, a.theme.Background)
	call.Add(gtx.Ops)

	return dims
}
