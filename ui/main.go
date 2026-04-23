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
	"github.com/wailsapp/wails/v3/pkg/services/notifications"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed build/imageTemplate.png
var icon []byte

type FocusEventPayload struct {
	EventId   string `json:"eventId"`
	EventType string `json:"eventType"`
}

// closeInstallWindow hides the certificate install webview; set in newWindowManager.
var closeInstallWindow func()

var setInstallWindowOnTop func(bool)

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

// --- Notifications -------------------------------------------------------

func setupNotifications() *notifications.NotificationService {
	notifier := notifications.New()
	notifier.RegisterNotificationCategory(notifications.NotificationCategory{
		ID:      "aikido-blocked",
		Actions: []notifications.NotificationAction{{ID: "OPEN", Title: "Open"}},
	})
	authorized, _ := notifier.CheckNotificationAuthorization()
	if !authorized {
		go func() {
			ok, _ := notifier.RequestNotificationAuthorization()
			log.Println("Notifications authorized:", ok)
		}()
		return notifier
	}
	log.Println("Notifications authorized:", authorized)
	return notifier
}

// --- Wails application ---------------------------------------------------

var daemonSvc = &DaemonService{}

func newApp(notifier *notifications.NotificationService) *application.App {
	return application.New(application.Options{
		Name:        "Aikido Endpoint Protection",
		Description: "Aikido Endpoint Protection",
		Services: []application.Service{
			application.NewService(notifier),
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

func newWindowManager(app *application.App) *windowManager {
	wm := &windowManager{app: app}
	wm.window = app.Window.NewWithOptions(mainWindowOpts())
	wm.installWindow = app.Window.NewWithOptions(installWindowOpts())
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

func setupSystemTray(app *application.App, showDashboard func()) chan<- appserver.ProxyStatusBody {
	systray := app.SystemTray.New()
	systray.SetTooltip("Aikido Endpoint Protection")
	if runtime.GOOS == "darwin" {
		systray.SetTemplateIcon(icon)
	} else {
		systray.SetIcon(icon)
	}

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
		showDashboard()
	})
	systray.SetMenu(menu)
	if runtime.GOOS == "windows" {
		systray.OnClick(systray.OpenMenu)
	}

	var setupHidden atomic.Bool
	setupHidden.Store(true)
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

func handleBlockedEventCreated(app *application.App, notifier *notifications.NotificationService, ev daemon.BlockEvent) {
	log.Println("Blocked event:", ev)
	app.Event.Emit("blocked", ev)
	if authorized, _ := notifier.CheckNotificationAuthorization(); authorized {
		notifier.SendNotificationWithActions(notifications.NotificationOptions{
			ID:         "block-" + ev.ID,
			Title:      "Aikido Endpoint Protection blocked an event",
			Body:       ev.Artifact.Product + ": " + ev.Artifact.PackageName,
			CategoryID: "aikido-blocked",
			Data:       map[string]interface{}{"eventId": ev.ID, "eventType": "block"},
		})
	}
}

func handleBlockedEventUpdate(app *application.App, ev daemon.BlockEvent) {
	log.Println("Blocked event updated:", ev)
	app.Event.Emit("blocked_updated", ev)
}

func startAppServer(app *application.App, wm *windowManager, statusCh chan<- appserver.ProxyStatusBody, notifier *notifications.NotificationService) {
	srv := appserver.New()
	srv.SetHandlers(
		func(ev appserver.ProxyStatusBody) { statusCh <- ev },
		func(ev daemon.BlockEvent) { handleBlockedEventCreated(app, notifier, ev) },
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

	notifier := setupNotifications()
	app := newApp(notifier)

	wm := newWindowManager(app)

	statusCh := setupSystemTray(app, wm.showDashboard)
	startAppServer(app, wm, statusCh, notifier)

	// On macOS, clicking the app bundle while running triggers a default Wails
	// listener that shows ALL hidden windows. Register a hook (runs before
	// listeners and can cancel them) to show only the main window instead.
	app.Event.RegisterApplicationEventHook(events.Mac.ApplicationShouldHandleReopen, func(event *application.ApplicationEvent) {
		wm.showDashboard()
		event.Cancel()
	})

	notifier.OnNotificationResponse(func(result notifications.NotificationResult) {
		if result.Error != nil {
			return
		}
		eventId, _ := result.Response.UserInfo["eventId"].(string)
		if eventId == "" {
			return
		}
		eventType, _ := result.Response.UserInfo["eventType"].(string)
		wm.showDashboard()
		go func() {
			time.Sleep(500 * time.Millisecond)
			app.Event.Emit("focus_event", FocusEventPayload{EventId: eventId, EventType: eventType})
		}()
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
