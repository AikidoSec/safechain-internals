package icons

import (
	"image"
	"image/color"

	"gioui.org/f32"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
)

func LayoutAikidoLogo(gtx layout.Context, size unit.Dp, logoColor color.NRGBA) layout.Dimensions {
	scale := float32(gtx.Dp(size)) / 24.0

	var path clip.Path
	path.Begin(gtx.Ops)

	// M18.9102 4H5V9.02389H18.9102V4Z
	path.MoveTo(f32.Pt(18.9102*scale, 4*scale))
	path.LineTo(f32.Pt(5*scale, 4*scale))
	path.LineTo(f32.Pt(5*scale, 9.02389*scale))
	path.LineTo(f32.Pt(18.9102*scale, 9.02389*scale))
	path.LineTo(f32.Pt(18.9102*scale, 4*scale))
	path.Close()

	paint.FillShape(gtx.Ops, logoColor, clip.Outline{Path: path.End()}.Op())

	// M5 13.736C8.95729 10.0744 14.9529 10.0743 18.9102 13.736V19.9972L18.9075 20L11.9551 12.787L5.00273 20L5 19.9972V13.736Z
	path.Begin(gtx.Ops)
	path.MoveTo(f32.Pt(5*scale, 13.736*scale))
	path.CubeTo(
		f32.Pt(8.95729*scale, 10.0744*scale),
		f32.Pt(14.9529*scale, 10.0743*scale),
		f32.Pt(18.9102*scale, 13.736*scale),
	)
	path.LineTo(f32.Pt(18.9102*scale, 19.9972*scale))
	path.LineTo(f32.Pt(18.9075*scale, 20*scale))
	path.LineTo(f32.Pt(11.9551*scale, 12.787*scale))
	path.LineTo(f32.Pt(5.00273*scale, 20*scale))
	path.LineTo(f32.Pt(5*scale, 19.9972*scale))
	path.LineTo(f32.Pt(5*scale, 13.736*scale))
	path.Close()

	paint.FillShape(gtx.Ops, logoColor, clip.Outline{Path: path.End()}.Op())

	dim := gtx.Dp(size)
	return layout.Dimensions{Size: image.Point{X: dim, Y: dim}}
}

func LayoutAikidoLogoFull(gtx layout.Context, height unit.Dp, primaryColor, secondaryColor color.NRGBA) layout.Dimensions {
	h := float32(gtx.Dp(height))
	scale := h / 20.0
	iconWidth := h
	textWidth := h * 3.1
	spacing := h * 0.4
	totalWidth := iconWidth + spacing + textWidth

	var path clip.Path

	// Draw icon (scaled to fit height)
	iconScale := h / 24.0
	path.Begin(gtx.Ops)
	path.MoveTo(f32.Pt(18.9102*iconScale, 4*iconScale))
	path.LineTo(f32.Pt(5*iconScale, 4*iconScale))
	path.LineTo(f32.Pt(5*iconScale, 9.02389*iconScale))
	path.LineTo(f32.Pt(18.9102*iconScale, 9.02389*iconScale))
	path.Close()
	paint.FillShape(gtx.Ops, primaryColor, clip.Outline{Path: path.End()}.Op())

	path.Begin(gtx.Ops)
	path.MoveTo(f32.Pt(5*iconScale, 13.736*iconScale))
	path.CubeTo(
		f32.Pt(8.95729*iconScale, 10.0744*iconScale),
		f32.Pt(14.9529*iconScale, 10.0743*iconScale),
		f32.Pt(18.9102*iconScale, 13.736*iconScale),
	)
	path.LineTo(f32.Pt(18.9102*iconScale, 19.9972*iconScale))
	path.LineTo(f32.Pt(18.9075*iconScale, 20*iconScale))
	path.LineTo(f32.Pt(11.9551*iconScale, 12.787*iconScale))
	path.LineTo(f32.Pt(5.00273*iconScale, 20*iconScale))
	path.LineTo(f32.Pt(5*iconScale, 19.9972*iconScale))
	path.Close()
	paint.FillShape(gtx.Ops, primaryColor, clip.Outline{Path: path.End()}.Op())

	// Draw "aikido" text
	offsetX := iconWidth + spacing
	drawAikidoText(&path, gtx, offsetX, scale, primaryColor, secondaryColor)

	return layout.Dimensions{Size: image.Point{X: int(totalWidth), Y: int(h)}}
}

func drawAikidoText(path *clip.Path, gtx layout.Context, offsetX, scale float32, primaryColor, secondaryColor color.NRGBA) {
	// "a" letter
	drawLetterA(path, gtx, offsetX, scale, secondaryColor)
	// "i" letter
	drawLetterI(path, gtx, offsetX+8*scale, scale, secondaryColor)
	// "k" letter
	drawLetterK(path, gtx, offsetX+14*scale, scale, secondaryColor)
	// "i" letter
	drawLetterI(path, gtx, offsetX+24*scale, scale, secondaryColor)
	// "d" letter
	drawLetterD(path, gtx, offsetX+30*scale, scale, secondaryColor)
	// "o" letter
	drawLetterO(path, gtx, offsetX+42*scale, scale, secondaryColor)
}

func drawLetterA(path *clip.Path, gtx layout.Context, x, scale float32, c color.NRGBA) {
	path.Begin(gtx.Ops)
	// Simple "a" shape
	cx := x + 3*scale
	cy := 13 * scale
	r := 3 * scale
	drawRoundedRect(path, x, 7*scale, 6*scale, 12*scale, 2*scale)
	paint.FillShape(gtx.Ops, c, clip.Outline{Path: path.End()}.Op())
	// Inner cutout for "a"
	path.Begin(gtx.Ops)
	drawCircleAt(path, cx, cy-2*scale, r*0.6)
	paint.FillShape(gtx.Ops, color.NRGBA{R: 250, G: 250, B: 250, A: 255}, clip.Outline{Path: path.End()}.Op())
}

func drawLetterI(path *clip.Path, gtx layout.Context, x, scale float32, c color.NRGBA) {
	// Dot
	path.Begin(gtx.Ops)
	drawCircleAt(path, x+1.5*scale, 5*scale, 1.5*scale)
	paint.FillShape(gtx.Ops, c, clip.Outline{Path: path.End()}.Op())
	// Stem
	path.Begin(gtx.Ops)
	drawRoundedRect(path, x, 8*scale, 3*scale, 11*scale, 1*scale)
	paint.FillShape(gtx.Ops, c, clip.Outline{Path: path.End()}.Op())
}

func drawLetterK(path *clip.Path, gtx layout.Context, x, scale float32, c color.NRGBA) {
	// Vertical stem
	path.Begin(gtx.Ops)
	drawRoundedRect(path, x, 3*scale, 3*scale, 16*scale, 1*scale)
	paint.FillShape(gtx.Ops, c, clip.Outline{Path: path.End()}.Op())
	// Upper diagonal
	path.Begin(gtx.Ops)
	path.MoveTo(f32.Pt(x+3*scale, 11*scale))
	path.LineTo(f32.Pt(x+8*scale, 6*scale))
	path.LineTo(f32.Pt(x+10*scale, 6*scale))
	path.LineTo(f32.Pt(x+5*scale, 11*scale))
	path.Close()
	paint.FillShape(gtx.Ops, c, clip.Outline{Path: path.End()}.Op())
	// Lower diagonal
	path.Begin(gtx.Ops)
	path.MoveTo(f32.Pt(x+3*scale, 11*scale))
	path.LineTo(f32.Pt(x+5*scale, 11*scale))
	path.LineTo(f32.Pt(x+10*scale, 19*scale))
	path.LineTo(f32.Pt(x+8*scale, 19*scale))
	path.Close()
	paint.FillShape(gtx.Ops, c, clip.Outline{Path: path.End()}.Op())
}

func drawLetterD(path *clip.Path, gtx layout.Context, x, scale float32, c color.NRGBA) {
	// Vertical stem (tall)
	path.Begin(gtx.Ops)
	drawRoundedRect(path, x+6*scale, 3*scale, 3*scale, 16*scale, 1*scale)
	paint.FillShape(gtx.Ops, c, clip.Outline{Path: path.End()}.Op())
	// Bowl
	path.Begin(gtx.Ops)
	drawRoundedRect(path, x, 7*scale, 9*scale, 12*scale, 3*scale)
	paint.FillShape(gtx.Ops, c, clip.Outline{Path: path.End()}.Op())
	// Inner cutout
	path.Begin(gtx.Ops)
	drawCircleAt(path, x+4.5*scale, 13*scale, 2.5*scale)
	paint.FillShape(gtx.Ops, color.NRGBA{R: 250, G: 250, B: 250, A: 255}, clip.Outline{Path: path.End()}.Op())
}

func drawLetterO(path *clip.Path, gtx layout.Context, x, scale float32, c color.NRGBA) {
	// Outer circle
	path.Begin(gtx.Ops)
	drawCircleAt(path, x+5*scale, 13*scale, 5*scale)
	paint.FillShape(gtx.Ops, c, clip.Outline{Path: path.End()}.Op())
	// Inner cutout
	path.Begin(gtx.Ops)
	drawCircleAt(path, x+5*scale, 13*scale, 2.5*scale)
	paint.FillShape(gtx.Ops, color.NRGBA{R: 250, G: 250, B: 250, A: 255}, clip.Outline{Path: path.End()}.Op())
}

func drawRoundedRect(path *clip.Path, x, y, w, h, r float32) {
	path.MoveTo(f32.Pt(x+r, y))
	path.LineTo(f32.Pt(x+w-r, y))
	path.QuadTo(f32.Pt(x+w, y), f32.Pt(x+w, y+r))
	path.LineTo(f32.Pt(x+w, y+h-r))
	path.QuadTo(f32.Pt(x+w, y+h), f32.Pt(x+w-r, y+h))
	path.LineTo(f32.Pt(x+r, y+h))
	path.QuadTo(f32.Pt(x, y+h), f32.Pt(x, y+h-r))
	path.LineTo(f32.Pt(x, y+r))
	path.QuadTo(f32.Pt(x, y), f32.Pt(x+r, y))
	path.Close()
}

func drawCircleAt(path *clip.Path, cx, cy, r float32) {
	segments := 24
	for i := 0; i <= segments; i++ {
		angle := float64(i) * 2 * 3.14159 / float64(segments)
		x := cx + r*float32(cos(angle))
		y := cy + r*float32(sin(angle))
		if i == 0 {
			path.MoveTo(f32.Pt(x, y))
		} else {
			path.LineTo(f32.Pt(x, y))
		}
	}
	path.Close()
}

func cos(x float64) float64 {
	return float64(f32Cos(float32(x)))
}

func sin(x float64) float64 {
	return float64(f32Sin(float32(x)))
}

func f32Cos(x float32) float32 {
	// Taylor series approximation
	x = mod(x, 2*3.14159)
	if x < 0 {
		x += 2 * 3.14159
	}
	sign := float32(1)
	if x > 3.14159 {
		x -= 3.14159
		sign = -1
	}
	if x > 3.14159/2 {
		x = 3.14159 - x
		sign *= -1
	}
	x2 := x * x
	return sign * (1 - x2/2 + x2*x2/24 - x2*x2*x2/720)
}

func f32Sin(x float32) float32 {
	return f32Cos(x - 3.14159/2)
}

func mod(x, y float32) float32 {
	return x - y*float32(int(x/y))
}
