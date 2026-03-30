package main

import (
	"embed"
	"endpoint-protection-ui/appserver"
	"endpoint-protection-ui/daemon"
	"flag"
	"log"
	"runtime"
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
	EventId string `json:"eventId"`
}

func init() {
	application.RegisterEvent[daemon.BlockEvent]("blocked")
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

// --- System tray ---------------------------------------------------------

func setupSystemTray(app *application.App, showDashboard func()) chan<- appserver.ProxyStatusBody {
	systray := app.SystemTray.New()
	systray.SetTooltip("Aikido Endpoint Protection")
	if runtime.GOOS == "darwin" {
		systray.SetTemplateIcon(icon)
	} else {
		systray.SetIcon(icon)
	}

	menu := application.NewMenu()
	statusItem := menu.Add("Aikido Proxy: checking…")
	statusItem.SetEnabled(false)
	menu.AddSeparator()
	menu.Add("Open Dashboard").OnClick(func(_ *application.Context) {
		// unset the focus event to reset the UI
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
			if ev.Running {
				statusItem.SetLabel("🟢 Aikido Proxy: \n" + ev.StdoutMessage)
			} else {
				statusItem.SetLabel("🔴 Aikido Proxy: \n" + ev.StdoutMessage)
			}
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
					Data:       map[string]interface{}{"eventId": ev.ID},
				})
			}
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
		wm.showDashboard()
		go func() {
			time.Sleep(500 * time.Millisecond)
			app.Event.Emit("focus_event", FocusEventPayload{EventId: eventId})
		}()
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
