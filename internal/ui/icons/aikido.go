package icons

import (
	"image"
	"image/color"

	"gioui.org/f32"
	"gioui.org/layout"
	"gioui.org/op/clip"
	"gioui.org/op/paint"
	"gioui.org/unit"
	"gioui.org/widget/material"
)

func LayoutAikidoLogo(gtx layout.Context, size unit.Dp, logoColor color.NRGBA) layout.Dimensions {
	scale := float32(gtx.Dp(size)) / 20.0

	var path clip.Path
	path.Begin(gtx.Ops)

	// Logo top bar: M16.6003 0H0V6.27804H16.6003V0Z
	path.MoveTo(f32.Pt(16.6003*scale, 0*scale))
	path.LineTo(f32.Pt(0*scale, 0*scale))
	path.LineTo(f32.Pt(0*scale, 6.27804*scale))
	path.LineTo(f32.Pt(16.6003*scale, 6.27804*scale))
	path.Close()

	paint.FillShape(gtx.Ops, logoColor, clip.Outline{Path: path.End()}.Op())

	// Logo bottom V: M0 12.1665C4.7226 7.59074 11.8777 7.59073 16.6003 12.1665V19.9907L16.5971 19.9942L8.30015 10.9805L0.00325453 19.9942L0 19.9907V12.1665Z
	path.Begin(gtx.Ops)
	path.MoveTo(f32.Pt(0*scale, 12.1665*scale))
	path.CubeTo(
		f32.Pt(4.7226*scale, 7.59074*scale),
		f32.Pt(11.8777*scale, 7.59073*scale),
		f32.Pt(16.6003*scale, 12.1665*scale),
	)
	path.LineTo(f32.Pt(16.6003*scale, 19.9907*scale))
	path.LineTo(f32.Pt(16.5971*scale, 19.9942*scale))
	path.LineTo(f32.Pt(8.30015*scale, 10.9805*scale))
	path.LineTo(f32.Pt(0.00325453*scale, 19.9942*scale))
	path.LineTo(f32.Pt(0*scale, 19.9907*scale))
	path.LineTo(f32.Pt(0*scale, 12.1665*scale))
	path.Close()

	paint.FillShape(gtx.Ops, logoColor, clip.Outline{Path: path.End()}.Op())

	dim := gtx.Dp(size)
	logoWidth := int(16.6003 * scale)
	return layout.Dimensions{Size: image.Point{X: logoWidth, Y: dim}}
}

// LayoutAikidoLogoFull renders the complete Aikido logo with text using vector paths
// SVG viewBox: 0 0 83 20
func LayoutAikidoLogoFull(gtx layout.Context, height unit.Dp, primaryColor, textColor color.NRGBA, th *material.Theme) layout.Dimensions {
	scale := float32(gtx.Dp(height)) / 20.0
	width := int(83.0 * scale)
	heightPx := gtx.Dp(height)

	var path clip.Path

	// Logo top bar (primary color)
	path.Begin(gtx.Ops)
	path.MoveTo(f32.Pt(16.6003*scale, 0*scale))
	path.LineTo(f32.Pt(0*scale, 0*scale))
	path.LineTo(f32.Pt(0*scale, 6.27804*scale))
	path.LineTo(f32.Pt(16.6003*scale, 6.27804*scale))
	path.Close()
	paint.FillShape(gtx.Ops, primaryColor, clip.Outline{Path: path.End()}.Op())

	// Logo bottom V (primary color)
	path.Begin(gtx.Ops)
	path.MoveTo(f32.Pt(0*scale, 12.1665*scale))
	path.CubeTo(
		f32.Pt(4.7226*scale, 7.59074*scale),
		f32.Pt(11.8777*scale, 7.59073*scale),
		f32.Pt(16.6003*scale, 12.1665*scale),
	)
	path.LineTo(f32.Pt(16.6003*scale, 19.9907*scale))
	path.LineTo(f32.Pt(16.5971*scale, 19.9942*scale))
	path.LineTo(f32.Pt(8.30015*scale, 10.9805*scale))
	path.LineTo(f32.Pt(0.00325453*scale, 19.9942*scale))
	path.LineTo(f32.Pt(0*scale, 19.9907*scale))
	path.LineTo(f32.Pt(0*scale, 12.1665*scale))
	path.Close()
	paint.FillShape(gtx.Ops, primaryColor, clip.Outline{Path: path.End()}.Op())

	// Letter "a" - outer shape (text color)
	path.Begin(gtx.Ops)
	drawLetterA(gtx, &path, scale)
	paint.FillShape(gtx.Ops, textColor, clip.Outline{Path: path.End()}.Op())

	// First "i" (text color)
	path.Begin(gtx.Ops)
	drawLetterI1(gtx, &path, scale)
	paint.FillShape(gtx.Ops, textColor, clip.Outline{Path: path.End()}.Op())

	// Letter "k" (text color)
	path.Begin(gtx.Ops)
	drawLetterK(gtx, &path, scale)
	paint.FillShape(gtx.Ops, textColor, clip.Outline{Path: path.End()}.Op())

	// Second "i" (text color)
	path.Begin(gtx.Ops)
	drawLetterI2(gtx, &path, scale)
	paint.FillShape(gtx.Ops, textColor, clip.Outline{Path: path.End()}.Op())

	// Letter "d" (text color)
	path.Begin(gtx.Ops)
	drawLetterD(gtx, &path, scale)
	paint.FillShape(gtx.Ops, textColor, clip.Outline{Path: path.End()}.Op())

	// Letter "o" (text color)
	path.Begin(gtx.Ops)
	drawLetterO(gtx, &path, scale)
	paint.FillShape(gtx.Ops, textColor, clip.Outline{Path: path.End()}.Op())

	return layout.Dimensions{Size: image.Point{X: width, Y: heightPx}}
}

// drawLetterA draws the letter "a" path
func drawLetterA(_ layout.Context, path *clip.Path, scale float32) {
	// Outer path
	path.MoveTo(f32.Pt(36.0847*scale, 13.9462*scale))
	path.LineTo(f32.Pt(35.7289*scale, 13.9462*scale))
	path.CubeTo(f32.Pt(35.3928*scale, 13.9462*scale), f32.Pt(35.1358*scale, 13.8824*scale), f32.Pt(34.9579*scale, 13.7336*scale))
	path.CubeTo(f32.Pt(34.7799*scale, 13.5848*scale), f32.Pt(34.6811*scale, 13.2872*scale), f32.Pt(34.6811*scale, 12.8194*scale))
	path.LineTo(f32.Pt(34.6811*scale, 9.01382*scale))
	path.CubeTo(f32.Pt(34.6811*scale, 7.69567*scale), f32.Pt(34.3055*scale, 6.63266*scale), f32.Pt(33.574*scale, 5.8035*scale))
	path.CubeTo(f32.Pt(32.8425*scale, 4.97435*scale), f32.Pt(31.6365*scale, 4.5704*scale), f32.Pt(29.9758*scale, 4.5704*scale))
	path.CubeTo(f32.Pt(28.4733*scale, 4.5704*scale), f32.Pt(27.3069*scale, 4.93183*scale), f32.Pt(26.4963*scale, 5.63342*scale))
	path.CubeTo(f32.Pt(25.6858*scale, 6.35627*scale), f32.Pt(25.1915*scale, 7.33425*scale), f32.Pt(25.0531*scale, 8.58861*scale))
	path.LineTo(f32.Pt(27.6825*scale, 8.58861*scale))
	path.CubeTo(f32.Pt(27.8605*scale, 7.33425*scale), f32.Pt(28.6117*scale, 6.7177*scale), f32.Pt(29.8968*scale, 6.7177*scale))
	path.CubeTo(f32.Pt(30.6678*scale, 6.7177*scale), f32.Pt(31.2213*scale, 6.9303*scale), f32.Pt(31.5179*scale, 7.35551*scale))
	path.CubeTo(f32.Pt(31.8144*scale, 7.78072*scale), f32.Pt(31.9726*scale, 8.37601*scale), f32.Pt(31.9726*scale, 9.14138*scale))
	path.LineTo(f32.Pt(31.9726*scale, 9.46029*scale))
	path.LineTo(f32.Pt(29.8374*scale, 9.46029*scale))
	path.CubeTo(f32.Pt(28.157*scale, 9.46029*scale), f32.Pt(26.872*scale, 9.77919*scale), f32.Pt(26.0021*scale, 10.4383*scale))
	path.CubeTo(f32.Pt(25.1322*scale, 11.0973*scale), f32.Pt(24.6973*scale, 11.9903*scale), f32.Pt(24.6973*scale, 13.1171*scale))
	path.CubeTo(f32.Pt(24.6973*scale, 14.2651*scale), f32.Pt(25.0927*scale, 15.1155*scale), f32.Pt(25.8835*scale, 15.6683*scale))
	path.CubeTo(f32.Pt(26.6743*scale, 16.2423*scale), f32.Pt(27.6034*scale, 16.5187*scale), f32.Pt(28.6908*scale, 16.5187*scale))
	path.CubeTo(f32.Pt(30.3712*scale, 16.5187*scale), f32.Pt(31.6167*scale, 15.8809*scale), f32.Pt(32.3878*scale, 14.584*scale))
	path.CubeTo(f32.Pt(32.5657*scale, 15.2006*scale), f32.Pt(32.8622*scale, 15.6471*scale), f32.Pt(33.2774*scale, 15.8809*scale))
	path.CubeTo(f32.Pt(33.6926*scale, 16.136*scale), f32.Pt(34.3055*scale, 16.2636*scale), f32.Pt(35.1556*scale, 16.2636*scale))
	path.LineTo(f32.Pt(36.0847*scale, 16.2636*scale))
	path.LineTo(f32.Pt(36.0847*scale, 13.9462*scale))
	path.Close()

	// Inner hole of "a"
	path.MoveTo(f32.Pt(29.3037*scale, 14.3714*scale))
	path.CubeTo(f32.Pt(28.7106*scale, 14.3714*scale), f32.Pt(28.2559*scale, 14.2226*scale), f32.Pt(27.9395*scale, 13.9462*scale))
	path.CubeTo(f32.Pt(27.6034*scale, 13.6698*scale), f32.Pt(27.4453*scale, 13.3084*scale), f32.Pt(27.4453*scale, 12.8619*scale))
	path.CubeTo(f32.Pt(27.4453*scale, 11.8202*scale), f32.Pt(28.3547*scale, 11.2887*scale), f32.Pt(30.1933*scale, 11.2887*scale))
	path.LineTo(f32.Pt(32.0121*scale, 11.2887*scale))
	path.CubeTo(f32.Pt(32.0121*scale, 12.3517*scale), f32.Pt(31.7551*scale, 13.1383*scale), f32.Pt(31.2213*scale, 13.6273*scale))
	path.CubeTo(f32.Pt(30.6876*scale, 14.1163*scale), f32.Pt(30.0549*scale, 14.3714*scale), f32.Pt(29.3037*scale, 14.3714*scale))
	path.Close()
}

// drawLetterI1 draws the first "i" (dot and stem)
func drawLetterI1(_ layout.Context, path *clip.Path, scale float32) {
	// Dot: M37.7831 0.871094V3.61368H40.4916V0.871094H37.7831Z
	path.MoveTo(f32.Pt(37.7831*scale, 0.871094*scale))
	path.LineTo(f32.Pt(37.7831*scale, 3.61368*scale))
	path.LineTo(f32.Pt(40.4916*scale, 3.61368*scale))
	path.LineTo(f32.Pt(40.4916*scale, 0.871094*scale))
	path.Close()

	// Stem: M37.7831 4.82552V16.2636H40.4916V4.82552H37.7831Z
	path.MoveTo(f32.Pt(37.7831*scale, 4.82552*scale))
	path.LineTo(f32.Pt(37.7831*scale, 16.2636*scale))
	path.LineTo(f32.Pt(40.4916*scale, 16.2636*scale))
	path.LineTo(f32.Pt(40.4916*scale, 4.82552*scale))
	path.Close()
}

// drawLetterK draws the letter "k"
func drawLetterK(_ layout.Context, path *clip.Path, scale float32) {
	// M42.7987 0.871094V16.2636H45.5071V12.9682L46.891 11.4375L49.9554 16.2636H53.1581L48.7296 9.33272L52.7627 4.82552H49.4216L45.5071 9.24768V0.871094H42.7987Z
	path.MoveTo(f32.Pt(42.7987*scale, 0.871094*scale))
	path.LineTo(f32.Pt(42.7987*scale, 16.2636*scale))
	path.LineTo(f32.Pt(45.5071*scale, 16.2636*scale))
	path.LineTo(f32.Pt(45.5071*scale, 12.9682*scale))
	path.LineTo(f32.Pt(46.891*scale, 11.4375*scale))
	path.LineTo(f32.Pt(49.9554*scale, 16.2636*scale))
	path.LineTo(f32.Pt(53.1581*scale, 16.2636*scale))
	path.LineTo(f32.Pt(48.7296*scale, 9.33272*scale))
	path.LineTo(f32.Pt(52.7627*scale, 4.82552*scale))
	path.LineTo(f32.Pt(49.4216*scale, 4.82552*scale))
	path.LineTo(f32.Pt(45.5071*scale, 9.24768*scale))
	path.LineTo(f32.Pt(45.5071*scale, 0.871094*scale))
	path.Close()
}

// drawLetterI2 draws the second "i" (dot and stem)
func drawLetterI2(_ layout.Context, path *clip.Path, scale float32) {
	// Dot: M54.4447 0.871094V3.61368H57.1532V0.871094H54.4447Z
	path.MoveTo(f32.Pt(54.4447*scale, 0.871094*scale))
	path.LineTo(f32.Pt(54.4447*scale, 3.61368*scale))
	path.LineTo(f32.Pt(57.1532*scale, 3.61368*scale))
	path.LineTo(f32.Pt(57.1532*scale, 0.871094*scale))
	path.Close()

	// Stem: M54.4447 4.82552V16.2636H57.1532V4.82552H54.4447Z
	path.MoveTo(f32.Pt(54.4447*scale, 4.82552*scale))
	path.LineTo(f32.Pt(54.4447*scale, 16.2636*scale))
	path.LineTo(f32.Pt(57.1532*scale, 16.2636*scale))
	path.LineTo(f32.Pt(57.1532*scale, 4.82552*scale))
	path.Close()
}

// drawLetterD draws the letter "d"
func drawLetterD(_ layout.Context, path *clip.Path, scale float32) {
	// Outer shape
	path.MoveTo(f32.Pt(69.8169*scale, 0.871094*scale))
	path.LineTo(f32.Pt(67.1084*scale, 0.871094*scale))
	path.LineTo(f32.Pt(67.1084*scale, 6.50509*scale))
	path.CubeTo(f32.Pt(66.3769*scale, 5.20821*scale), f32.Pt(65.25*scale, 4.5704*scale), f32.Pt(63.7673*scale, 4.5704*scale))
	path.CubeTo(f32.Pt(62.3636*scale, 4.5704*scale), f32.Pt(61.217*scale, 5.10191*scale), f32.Pt(60.3669*scale, 6.18619*scale))
	path.CubeTo(f32.Pt(59.5168*scale, 7.27047*scale), f32.Pt(59.0818*scale, 8.73743*scale), f32.Pt(59.0818*scale, 10.5446*scale))
	path.CubeTo(f32.Pt(59.0818*scale, 12.3517*scale), f32.Pt(59.5168*scale, 13.7974*scale), f32.Pt(60.3669*scale, 14.8817*scale))
	path.CubeTo(f32.Pt(61.217*scale, 15.966*scale), f32.Pt(62.3636*scale, 16.5187*scale), f32.Pt(63.7673*scale, 16.5187*scale))
	path.CubeTo(f32.Pt(65.25*scale, 16.5187*scale), f32.Pt(66.3769*scale, 15.8809*scale), f32.Pt(67.1084*scale, 14.584*scale))
	path.LineTo(f32.Pt(67.1084*scale, 16.2636*scale))
	path.LineTo(f32.Pt(69.8169*scale, 16.2636*scale))
	path.LineTo(f32.Pt(69.8169*scale, 0.871094*scale))
	path.Close()

	// Inner bowl of "d"
	path.MoveTo(f32.Pt(64.4988*scale, 14.2014*scale))
	path.CubeTo(f32.Pt(63.6091*scale, 14.2014*scale), f32.Pt(62.9567*scale, 13.8612*scale), f32.Pt(62.502*scale, 13.1596*scale))
	path.CubeTo(f32.Pt(62.0473*scale, 12.4793*scale), f32.Pt(61.8298*scale, 11.6076*scale), f32.Pt(61.8298*scale, 10.5446*scale))
	path.CubeTo(f32.Pt(61.8298*scale, 9.48155*scale), f32.Pt(62.0473*scale, 8.60987*scale), f32.Pt(62.502*scale, 7.90828*scale))
	path.CubeTo(f32.Pt(62.9567*scale, 7.20669*scale), f32.Pt(63.6091*scale, 6.86652*scale), f32.Pt(64.4988*scale, 6.86652*scale))
	path.CubeTo(f32.Pt(65.3687*scale, 6.86652*scale), f32.Pt(66.0408*scale, 7.20669*scale), f32.Pt(66.5351*scale, 7.86576*scale))
	path.CubeTo(f32.Pt(67.0096*scale, 8.54609*scale), f32.Pt(67.2468*scale, 9.43902*scale), f32.Pt(67.2468*scale, 10.5446*scale))
	path.CubeTo(f32.Pt(67.2468*scale, 11.6501*scale), f32.Pt(67.0096*scale, 12.543*scale), f32.Pt(66.5351*scale, 13.2021*scale))
	path.CubeTo(f32.Pt(66.0408*scale, 13.8612*scale), f32.Pt(65.3687*scale, 14.2014*scale), f32.Pt(64.4988*scale, 14.2014*scale))
	path.Close()
}

// drawLetterO draws the letter "o"
func drawLetterO(_ layout.Context, path *clip.Path, scale float32) {
	// Outer shape
	path.MoveTo(f32.Pt(76.8334*scale, 16.5187*scale))
	path.CubeTo(f32.Pt(78.494*scale, 16.5187*scale), f32.Pt(79.7989*scale, 15.9872*scale), f32.Pt(80.7676*scale, 14.9029*scale))
	path.CubeTo(f32.Pt(81.7165*scale, 13.8187*scale), f32.Pt(82.191*scale, 12.373*scale), f32.Pt(82.191*scale, 10.5446*scale))
	path.CubeTo(f32.Pt(82.191*scale, 8.71617*scale), f32.Pt(81.7165*scale, 7.27047*scale), f32.Pt(80.7676*scale, 6.18619*scale))
	path.CubeTo(f32.Pt(79.7989*scale, 5.10191*scale), f32.Pt(78.494*scale, 4.5704*scale), f32.Pt(76.8334*scale, 4.5704*scale))
	path.CubeTo(f32.Pt(75.1529*scale, 4.5704*scale), f32.Pt(73.8481*scale, 5.10191*scale), f32.Pt(72.8992*scale, 6.18619*scale))
	path.CubeTo(f32.Pt(71.9502*scale, 7.27047*scale), f32.Pt(71.4757*scale, 8.71617*scale), f32.Pt(71.4757*scale, 10.5446*scale))
	path.CubeTo(f32.Pt(71.4757*scale, 12.373*scale), f32.Pt(71.9502*scale, 13.8187*scale), f32.Pt(72.8992*scale, 14.9029*scale))
	path.CubeTo(f32.Pt(73.8481*scale, 15.9872*scale), f32.Pt(75.1529*scale, 16.5187*scale), f32.Pt(76.8334*scale, 16.5187*scale))
	path.Close()

	// Inner hole of "o"
	path.MoveTo(f32.Pt(76.8334*scale, 14.2014*scale))
	path.CubeTo(f32.Pt(75.9833*scale, 14.2014*scale), f32.Pt(75.3506*scale, 13.8824*scale), f32.Pt(74.8959*scale, 13.2446*scale))
	path.CubeTo(f32.Pt(74.4412*scale, 12.6281*scale), f32.Pt(74.2237*scale, 11.7139*scale), f32.Pt(74.2237*scale, 10.5446*scale))
	path.CubeTo(f32.Pt(74.2237*scale, 9.37524*scale), f32.Pt(74.4412*scale, 8.46105*scale), f32.Pt(74.8959*scale, 7.82324*scale))
	path.CubeTo(f32.Pt(75.3506*scale, 7.18543*scale), f32.Pt(75.9833*scale, 6.86652*scale), f32.Pt(76.8334*scale, 6.86652*scale))
	path.CubeTo(f32.Pt(77.6835*scale, 6.86652*scale), f32.Pt(78.3161*scale, 7.18543*scale), f32.Pt(78.7708*scale, 7.82324*scale))
	path.CubeTo(f32.Pt(79.2255*scale, 8.46105*scale), f32.Pt(79.443*scale, 9.37524*scale), f32.Pt(79.443*scale, 10.5446*scale))
	path.CubeTo(f32.Pt(79.443*scale, 11.7139*scale), f32.Pt(79.2255*scale, 12.6281*scale), f32.Pt(78.7708*scale, 13.2446*scale))
	path.CubeTo(f32.Pt(78.3161*scale, 13.8824*scale), f32.Pt(77.6835*scale, 14.2014*scale), f32.Pt(76.8334*scale, 14.2014*scale))
	path.Close()
}
