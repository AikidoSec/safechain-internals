package main

import (
	"embed"
	"endpoint-protection-ui/appserver"
	"endpoint-protection-ui/daemon"
	"flag"
	"log"
	"runtime"
	"strings"
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

func init() {
	application.RegisterEvent[daemon.BlockEvent]("blocked")
	application.RegisterEvent[daemon.TlsTerminationFailedEvent]("tls_termination_failed")
	application.RegisterEvent[daemon.PermissionsResponse]("permissions_updated")
	application.RegisterEvent[FocusEventPayload]("focus_event")
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
	flag.StringVar(&f.daemonURL, "daemon_url", "", "Daemon API base URL (default http://127.0.0.1:7878)")
	flag.StringVar(&f.token, "token", "", "Daemon API auth token (default devtoken)")
	flag.StringVar(&f.uiURL, "ui_url", "", "Address the UI app server listens on (default 127.0.0.1:9876)")
	flag.StringVar(&f.logFile, "log_file", "", "Path to the log file")
	flag.Parse()
	return f
}

func applyFlags(f appFlags) {
	if f.logFile != "" {
		setupLogging(f.logFile)
		log.Println("Logging to file:", f.logFile)
	}
	if f.daemonURL != "" || f.token != "" {
		daemon.SetConfig(f.daemonURL, f.token)
	}
	if f.uiURL != "" {
		appserver.SetListenAddr(f.uiURL)
	}
}

// --- Notifications -------------------------------------------------------

func setupNotifications() (notifier *notifications.NotificationService, authorized bool) {
	notifier = notifications.New()
	notifier.RegisterNotificationCategory(notifications.NotificationCategory{
		ID:      "aikido-blocked",
		Actions: []notifications.NotificationAction{{ID: "OPEN", Title: "Open"}},
	})
	authorized, _ = notifier.CheckNotificationAuthorization()
	if !authorized {
		authorized, _ = notifier.RequestNotificationAuthorization()
	}
	log.Println("Notifications authorized:", authorized)
	return
}

// --- Wails application ---------------------------------------------------

func newApp(notifier *notifications.NotificationService) *application.App {
	return application.New(application.Options{
		Name:        "Aikido Endpoint Protection",
		Description: "Aikido Endpoint Protection",
		Services: []application.Service{
			application.NewService(notifier),
			application.NewService(&DaemonService{}),
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
		AlwaysOnTop:      true,
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
	app    *application.App
	window *application.WebviewWindow
}

func newWindowManager(app *application.App) *windowManager {
	wm := &windowManager{app: app}
	wm.window = app.Window.NewWithOptions(mainWindowOpts())
	wm.interceptClose(wm.window)
	return wm
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
	statusLines[0] = menu.Add("Aikido Proxy: checking…")
	statusLines[0].SetEnabled(false)
	for i := 1; i < maxStatusLines; i++ {
		statusLines[i] = menu.Add("")
		statusLines[i].SetEnabled(false)
		statusLines[i].SetHidden(true)
	}
	menu.AddSeparator()
	menu.Add("Open Dashboard").OnClick(func(_ *application.Context) {
		app.Event.Emit("focus_event", FocusEventPayload{EventId: ""})
		showDashboard()
	})
	systray.SetMenu(menu)
	if runtime.GOOS == "windows" {
		systray.OnClick(systray.OpenMenu)
	}

	statusCh := make(chan appserver.ProxyStatusBody, 8)
	go func() {
		for ev := range statusCh {
			prefix := "🔴 "
			if ev.Running {
				prefix = "🟢 "
			}
			lines := wrapText(prefix+"Aikido Proxy: "+ev.StdoutMessage, menuMaxWidth)
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

func startAppServer(app *application.App, statusCh chan<- appserver.ProxyStatusBody, notifier *notifications.NotificationService, notifAuthorized bool) {
	srv := appserver.New()
	srv.SetHandlers(
		func(ev appserver.ProxyStatusBody) { statusCh <- ev },
		func(ev daemon.BlockEvent) {
			log.Println("Blocked event:", ev)
			app.Event.Emit("blocked", ev)
			if notifAuthorized {
				notifier.SendNotificationWithActions(notifications.NotificationOptions{
					ID:         "block-" + ev.ID,
					Title:      "Aikido Endpoint Protection blocked an event",
					Body:       ev.Artifact.Product + ": " + ev.Artifact.PackageName,
					CategoryID: "aikido-blocked",
					Data:       map[string]interface{}{"eventId": ev.ID, "eventType": "block"},
				})
			}
		},
		func(ev daemon.TlsTerminationFailedEvent) {
			log.Println("TLS termination failed event:", ev)
			app.Event.Emit("tls_termination_failed", ev)
			if notifAuthorized {
				body := "SNI: " + ev.SNI
				if ev.App != "" {
					body += " (" + ev.App + ")"
				}
				notifier.SendNotificationWithActions(notifications.NotificationOptions{
					ID:         "tls-fail-" + ev.ID,
					Title:      "TLS termination failed",
					Body:       body,
					CategoryID: "aikido-blocked",
					Data:       map[string]interface{}{"eventId": ev.ID, "eventType": "tls"},
				})
			}
		},
		func(ev daemon.PermissionsResponse) {
			log.Println("Permissions updated")
			app.Event.Emit("permissions_updated", ev)
		},
	)
	srv.Start()
}

// --- Entry point ---------------------------------------------------------

func main() {
	flags := parseFlags()
	applyFlags(flags)

	notifier, notifAuthorized := setupNotifications()
	app := newApp(notifier)
	wm := newWindowManager(app)

	statusCh := setupSystemTray(app, wm.showDashboard)
	startAppServer(app, statusCh, notifier, notifAuthorized)

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
