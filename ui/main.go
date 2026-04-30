package main

import (
	"embed"
	"endpoint-protection-ui/appserver"
	"endpoint-protection-ui/daemon"
	"flag"
	"log"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/assets/DefaultTemplate.svg
var iconDefault []byte

//go:embed build/assets/NotifTemplate.svg
var iconNotif []byte

//go:embed build/assets/WarningTemplate.svg
var iconWarning []byte

type FocusEventPayload struct {
	EventId   string `json:"eventId"`
	EventType string `json:"eventType"`
}

// closeInstallWindow hides the certificate install webview; set in newWindowManager.
var closeInstallWindow func()

var setInstallWindowOnTop func(bool)
var openDashboardToEvent func(eventId, eventType string)
var closeTrayNotification func()
var showTrayNotification func()
var setTrayIcon func(kind trayIconKind)
var resetTrayIconIfNotif func()

type trayIconKind int32

const (
	trayIconKindDefault trayIconKind = iota
	trayIconKindNotif
	trayIconKindWarning
)

type SetupStatePayload struct {
	SetupRequired bool `json:"setupRequired"`
}

func init() {
	application.RegisterEvent[daemon.BlockEvent]("blocked")
	application.RegisterEvent[daemon.BlockEvent]("blocked_updated")
	application.RegisterEvent[daemon.TlsTerminationFailedEvent]("tls_termination_failed")
	application.RegisterEvent[daemon.PermissionsResponse]("permissions_updated")
	application.RegisterEvent[FocusEventPayload]("focus_event")
	application.RegisterEvent[SetupStatePayload]("setup_state")
}

// --- CLI flags -----------------------------------------------------------

type appFlags struct {
	daemonURL string
	token     string
	uiURL     string
	logFile   string
}

func parseFlags() appFlags {
	f := appFlags{}
	flag.StringVar(&f.daemonURL, "daemon_url", "", "Daemon API base URL (required)")
	flag.StringVar(&f.token, "token", "", "Daemon API auth token (required)")
	flag.StringVar(&f.uiURL, "ui_url", "", "Address the UI app server listens on (required)")
	flag.StringVar(&f.logFile, "log_file", "", "Path to the log file")
	flag.Parse()

	var missing []string
	if f.daemonURL == "" {
		missing = append(missing, "-daemon_url")
	}
	if f.token == "" {
		missing = append(missing, "-token")
	}
	if f.uiURL == "" {
		missing = append(missing, "-ui_url")
	}
	if len(missing) > 0 {
		log.Fatalf("missing required flag(s): %s", strings.Join(missing, ", "))
	}
	return f
}

func applyFlags(f appFlags) {
	if f.logFile != "" {
		setupLogging(f.logFile)
		log.Println("Logging to file:", f.logFile)
	}
	daemon.SetConfig(f.daemonURL, f.token)
	appserver.SetListenAddr(f.uiURL)
}

// --- Wails application ---------------------------------------------------

var daemonSvc = &DaemonService{}

func newApp() *application.App {
	return application.New(application.Options{
		Name:        "Aikido Endpoint Protection",
		Description: "Aikido Endpoint Protection",
		Services: []application.Service{
			application.NewService(daemonSvc),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ActivationPolicy: application.ActivationPolicyAccessory,
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
	})
}

// --- Window management ---------------------------------------------------

func mainWindowOpts() application.WebviewWindowOptions {
	return application.WebviewWindowOptions{
		Name:             "main",
		Title:            "Aikido Endpoint Protection",
		Width:            700,
		Height:           550,
		Hidden:           true,
		URL:              "/",
		BackgroundColour: application.NewRGB(255, 255, 255),
		AlwaysOnTop:      false,
		Windows: application.WindowsWindow{
			HiddenOnTaskbar: true,
		},
		HideOnEscape: true,
		Mac: application.MacWindow{
			CollectionBehavior: application.MacWindowCollectionBehaviorMoveToActiveSpace,
		},
	}
}

// windowManager handles the main window lifecycle: hiding on close instead of
// quitting the app, and re-creating the window if it was destroyed.
type windowManager struct {
	app           *application.App
	window        *application.WebviewWindow
	installWindow *application.WebviewWindow
	notifWindow   *application.WebviewWindow
	installMu     sync.Mutex
}

func installWindowOpts() application.WebviewWindowOptions {
	return application.WebviewWindowOptions{
		Name:             "install",
		Title:            "Aikido Endpoint Protection - System Setup",
		Width:            920,
		Height:           680,
		Hidden:           true,
		DisableResize:    true,
		URL:              "/#/install",
		AlwaysOnTop:      true,
		BackgroundColour: application.NewRGB(255, 255, 255),
		Windows: application.WindowsWindow{
			HiddenOnTaskbar: true,
		},
		Mac: application.MacWindow{
			CollectionBehavior: application.MacWindowCollectionBehaviorMoveToActiveSpace,
		},
	}
}

func trayNotifWindowOpts() application.WebviewWindowOptions {
	return application.WebviewWindowOptions{
		Name:           "tray-notification",
		Width:          360,
		Height:         160,
		Hidden:         true,
		Frameless:      true,
		DisableResize:  true,
		AlwaysOnTop:    true,
		URL:            "/#/tray-notification",
		BackgroundType: application.BackgroundTypeTransparent,
		Windows: application.WindowsWindow{
			HiddenOnTaskbar: true,
		},
		Mac: application.MacWindow{
			CollectionBehavior: application.MacWindowCollectionBehaviorMoveToActiveSpace,
		},
	}
}

func newWindowManager(app *application.App) *windowManager {
	wm := &windowManager{app: app}
	wm.window = app.Window.NewWithOptions(mainWindowOpts())
	wm.installWindow = app.Window.NewWithOptions(installWindowOpts())
	wm.notifWindow = app.Window.NewWithOptions(trayNotifWindowOpts())
	wm.interceptClose(wm.window)
	wm.interceptClose(wm.installWindow)
	closeInstallWindow = func() {
		wm.setCertificateInstallWindowVisible(false)
	}
	setInstallWindowOnTop = func(onTop bool) {
		wm.installMu.Lock()
		defer wm.installMu.Unlock()
		w, ok := wm.app.Window.GetByName("install")
		if !ok || w == nil {
			return
		}
		if win, _ := w.(*application.WebviewWindow); win != nil {
			win.SetAlwaysOnTop(onTop)
		}
	}
	return wm
}

func (wm *windowManager) setCertificateInstallWindowVisible(show bool) {
	wm.installMu.Lock()
	defer wm.installMu.Unlock()
	w, ok := wm.app.Window.GetByName("install")
	if !ok || w == nil {
		return
	}
	win, _ := w.(*application.WebviewWindow)
	if win == nil {
		return
	}
	if show {
		win.SetURL("/#/install")
		win.Show()
		win.Focus()
	} else {
		win.Hide()
	}
}

func (wm *windowManager) interceptClose(w *application.WebviewWindow) {
	w.RegisterHook(events.Common.WindowClosing, func(event *application.WindowEvent) {
		event.Cancel()
		w.Hide()
	})
}

func (wm *windowManager) showDashboard() {
	w, ok := wm.app.Window.GetByName("main")
	if !ok || w == nil {
		wm.window = wm.app.Window.NewWithOptions(mainWindowOpts())
		wm.interceptClose(wm.window)
	} else {
		wm.window, _ = w.(*application.WebviewWindow)
	}
	wm.window.Show()
	wm.window.Focus()
}

// --- Text wrapping -------------------------------------------------------

const menuMaxWidth = 50

func wrapText(text string, maxWidth int) []string {
	var lines []string
	for len(text) > maxWidth {
		i := strings.LastIndex(text[:maxWidth], " ")
		if i <= 0 {
			i = maxWidth
		}
		lines = append(lines, text[:i])
		text = strings.TrimLeft(text[i:], " ")
	}
	if len(text) > 0 {
		lines = append(lines, text)
	}
	return lines
}

// --- System tray ---------------------------------------------------------

const maxStatusLines = 4

func setupSystemTray(app *application.App, showDashboard func(), notifWindow *application.WebviewWindow) chan<- appserver.ProxyStatusBody {
	systray := app.SystemTray.New()
	systray.SetTooltip("Aikido Endpoint Protection")

	var currentIcon atomic.Int32
	applyIcon := func(icon []byte) {
		if runtime.GOOS == "darwin" {
			systray.SetTemplateIcon(icon)
		} else {
			systray.SetIcon(icon)
		}
	}
	var setupHidden atomic.Bool
	setupHidden.Store(true)

	setTrayIcon = func(kind trayIconKind) {
		if kind == trayIconKindNotif && trayIconKind(currentIcon.Load()) == trayIconKindWarning {
			return
		}
		currentIcon.Store(int32(kind))
		switch kind {
		case trayIconKindNotif:
			applyIcon(iconNotif)
		case trayIconKindWarning:
			applyIcon(iconWarning)
		default:
			applyIcon(iconDefault)
		}
	}
	resetTrayIconIfNotif = func() {
		if trayIconKind(currentIcon.Load()) != trayIconKindNotif {
			return
		}
		if !setupHidden.Load() {
			setTrayIcon(trayIconKindWarning)
		} else {
			setTrayIcon(trayIconKindDefault)
		}
	}

	setTrayIcon(trayIconKindDefault)
	systray.AttachWindow(notifWindow)

	menu := application.NewMenu()
	statusLines := make([]*application.MenuItem, maxStatusLines)
	statusLines[0] = menu.Add("Aikido Network Extension: checking…")
	statusLines[0].SetEnabled(false)
	for i := 1; i < maxStatusLines; i++ {
		statusLines[i] = menu.Add("")
		statusLines[i].SetEnabled(false)
		statusLines[i].SetHidden(true)
	}
	menu.AddSeparator()
	setupItem := menu.Add("⚠ System Setup Required...")
	setupItem.SetHidden(true)
	setupItem.OnClick(func(_ *application.Context) {
		go func() {
			if err := daemon.SetupStart(); err != nil {
				log.Printf("setup start: %v", err)
			}
		}()
	})
	menu.AddSeparator()
	menu.Add("Open Dashboard").OnClick(func(_ *application.Context) {
		app.Event.Emit("focus_event", FocusEventPayload{EventId: ""})
		if resetTrayIconIfNotif != nil {
			resetTrayIconIfNotif()
		}
		showDashboard()
	})
	systray.SetMenu(menu)

	hideNotifAndOpenMenu := func() {
		if notifWindow.IsVisible() {
			notifWindow.Hide()
		}
		systray.OpenMenu()
	}
	systray.OnClick(hideNotifAndOpenMenu)
	systray.OnRightClick(hideNotifAndOpenMenu)

	showTrayNotification = func() {
		if notifWindow.IsVisible() {
			return
		}
		systray.PositionWindow(notifWindow, 2)
		systray.WindowDebounce(200 * time.Millisecond)
		notifWindow.Show()
	}

	go func() {
		time.Sleep(5 * time.Second)
		for {
			ok, err := daemon.SetupCheck()
			if err != nil {
				log.Printf("setup check: %v", err)
			}
			shouldHide := ok || err != nil
			if shouldHide != setupHidden.Load() {
				setupHidden.Store(shouldHide)
				setupItem.SetHidden(shouldHide)
				menu.Update()
				if !shouldHide {
					setTrayIcon(trayIconKindWarning)
				} else if trayIconKind(currentIcon.Load()) == trayIconKindWarning {
					setTrayIcon(trayIconKindDefault)
				}
				app.Event.Emit("setup_state", SetupStatePayload{SetupRequired: !shouldHide})
			}
			time.Sleep(10 * time.Second)
		}
	}()

	statusCh := make(chan appserver.ProxyStatusBody, 8)
	go func() {
		for ev := range statusCh {
			prefix := "🔴 "
			if ev.Running {
				prefix = "🟢 "
			}
			lines := wrapText(prefix+"Aikido Network Extension: "+ev.StdoutMessage, menuMaxWidth)
			for i, item := range statusLines {
				if i < len(lines) {
					item.SetLabel(lines[i])
					item.SetHidden(false)
				} else {
					item.SetLabel("")
					item.SetHidden(true)
				}
			}
			menu.Update()
		}
	}()
	return statusCh
}

// --- App server (receives events from daemon) ----------------------------

func handleBlockedEventCreated(app *application.App, ev daemon.BlockEvent) {
	log.Println("Blocked event:", ev)
	app.Event.Emit("blocked", ev)
	if setTrayIcon != nil {
		setTrayIcon(trayIconKindNotif)
	}
	if showTrayNotification != nil {
		showTrayNotification()
	}
}

func handleBlockedEventUpdate(app *application.App, ev daemon.BlockEvent) {
	log.Println("Blocked event updated:", ev)
	app.Event.Emit("blocked_updated", ev)
	if setTrayIcon != nil {
		setTrayIcon(trayIconKindNotif)
	}
	if showTrayNotification != nil {
		showTrayNotification()
	}
}

func startAppServer(app *application.App, wm *windowManager, statusCh chan<- appserver.ProxyStatusBody) {
	srv := appserver.New()
	srv.SetHandlers(
		func(ev appserver.ProxyStatusBody) { statusCh <- ev },
		func(ev daemon.BlockEvent) { handleBlockedEventCreated(app, ev) },
		func(ev daemon.BlockEvent) { handleBlockedEventUpdate(app, ev) },
		func(ev daemon.TlsTerminationFailedEvent) {
			log.Println("TLS termination failed event:", ev)
			app.Event.Emit("tls_termination_failed", ev)
		},
		func(ev daemon.PermissionsResponse) {
			log.Println("Permissions updated")
			app.Event.Emit("permissions_updated", ev)
		},
		func(steps []string) {
			if len(steps) > 0 {
				daemonSvc.SetSetupSteps(steps)
				wm.setCertificateInstallWindowVisible(true)
			}
		},
	)
	srv.Start()
}

// --- Entry point ---------------------------------------------------------

func main() {
	flags := parseFlags()
	applyFlags(flags)

	app := newApp()

	wm := newWindowManager(app)

	statusCh := setupSystemTray(app, wm.showDashboard, wm.notifWindow)
	startAppServer(app, wm, statusCh)

	openDashboardToEvent = func(eventId, eventType string) {
		if wm.notifWindow != nil {
			wm.notifWindow.Hide()
		}
		if resetTrayIconIfNotif != nil {
			resetTrayIconIfNotif()
		}
		wm.showDashboard()
		go func() {
			app.Event.Emit("focus_event", FocusEventPayload{EventId: eventId, EventType: eventType})
		}()
	}

	closeTrayNotification = func() {
		if wm.notifWindow != nil {
			wm.notifWindow.Hide()
		}
		if resetTrayIconIfNotif != nil {
			resetTrayIconIfNotif()
		}
	}

	// On macOS, clicking the app bundle while running triggers a default Wails
	// listener that shows ALL hidden windows. Register a hook (runs before
	// listeners and can cancel them) to show only the main window instead.
	app.Event.RegisterApplicationEventHook(events.Mac.ApplicationShouldHandleReopen, func(event *application.ApplicationEvent) {
		wm.showDashboard()
		event.Cancel()
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
