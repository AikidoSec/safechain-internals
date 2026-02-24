package main

import (
	"changeme/appserver"
	"changeme/daemon"
	"embed"
	_ "embed"
	"flag"
	"log"
	"time"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/services/notifications"
)

// Wails uses Go's `embed` package to embed the frontend files into the binary.
// Any files in the frontend/dist folder will be embedded into the binary and
// made available to the frontend.
// See https://pkg.go.dev/embed for more information.

//go:embed all:frontend/dist
var assets embed.FS

// FocusEventPayload is emitted when the user opens the dashboard from a block notification.
type FocusEventPayload struct {
	EventId string `json:"eventId"`
}

func init() {
	// Register a custom event whose associated data type is string.
	// This is not required, but the binding generator will pick up registered events
	// and provide a strongly typed JS/TS API for them.
	application.RegisterEvent[daemon.BlockedEvent]("blocked")
	application.RegisterEvent[FocusEventPayload]("focus_event")
}

// App icon used for system tray (and matches build/appicon.png used for .app and notifications).
//
//go:embed build/appicon.png
var icon []byte

// getMainWindow returns the named window if it still exists (nil if closed/destroyed).
func getMainWindow(app *application.App) *application.WebviewWindow {
	w, ok := app.Window.GetByName("main")
	if !ok || w == nil {
		return nil
	}
	ww, _ := w.(*application.WebviewWindow)
	return ww
}

// main function serves as the application's entry point. It initializes the application, creates a window,
// and starts a goroutine that emits a time-based event every second. It subsequently runs the application and
// logs any error that might occur.
func main() {
	// Command-line flags (e.g. when started by a daemon: ./app -daemon_url=https://... -token=... -ui_url=127.0.0.1:9876)
	daemonURL := flag.String("daemon_url", "", "Daemon API base URL (default http://127.0.0.1:7878)")
	token := flag.String("token", "", "Daemon API auth token (default devtoken)")
	uiURL := flag.String("ui_url", "", "Address the UI app server listens on (default 127.0.0.1:9876). Daemon calls POST <ui_url>/v1/proxy-status and POST <ui_url>/v1/blocked")
	flag.Parse()

	if *daemonURL != "" || *token != "" {
		daemon.SetConfig(*daemonURL, *token)
	}
	if *uiURL != "" {
		appserver.SetListenAddr(*uiURL)
	}

	// Notifications for blocked events (Open action)
	notifier := notifications.New()
	notifier.RegisterNotificationCategory(notifications.NotificationCategory{
		ID:      "aikido-blocked",
		Actions: []notifications.NotificationAction{{ID: "OPEN", Title: "Open"}},
	})
	authorized, _ := notifier.CheckNotificationAuthorization()
	if !authorized {
		authorized, _ = notifier.RequestNotificationAuthorization()
	}
	notifAuthorized := authorized
	//dockService := dock.NewWithOptions(dock.BadgeOptions{})

	// Create a new Wails application by providing the necessary options.
	// Variables 'Name' and 'Description' are for application metadata.
	// 'Assets' configures the asset server with the 'FS' variable pointing to the frontend files.
	// 'Bind' is a list of Go struct instances. The frontend has access to the methods of these instances.
	// 'Mac' options tailor the application when running an macOS.
	app := application.New(application.Options{
		Name:        "safechain-ultimate-ui",
		Description: "A demo of using raw HTML & CSS",
		Services: []application.Service{
			application.NewService(&DaemonService{}),
			//	application.NewService(dockService),
		},
		Assets: application.AssetOptions{
			Handler: application.AssetFileServerFS(assets),
		},
		Mac: application.MacOptions{
			ActivationPolicy: application.ActivationPolicyAccessory,
			ApplicationShouldTerminateAfterLastWindowClosed: false,
		},
	})

	// Create a new window with the necessary options.
	// 'Title' is the title of the window.
	// 'Mac' options tailor the window when running on macOS.
	// 'BackgroundColour' is the background colour of the window.
	// 'URL' is the URL that will be loaded into the webview.
	mainWindowOpts := application.WebviewWindowOptions{
		Name:             "main",
		Title:            "Endpoint Protection",
		Width:            700,
		Height:           550,
		Hidden:           true,
		URL:              "/",
		BackgroundColour: application.NewRGB(255, 255, 255),
		AlwaysOnTop:      true,
		Windows: application.WindowsWindow{
			HiddenOnTaskbar: true,
		},
		Mac: application.MacWindow{},
	}
	mainWindow := app.Window.NewWithOptions(mainWindowOpts)
	showDashboard := func() {
		w := getMainWindow(app)
		if w == nil {
			log.Println("new window")
			mainWindow = app.Window.NewWithOptions(mainWindowOpts)
			w = mainWindow

		} else {
			log.Println("existing window")
			mainWindow = w
		}
		w.Show()
		w.Focus()
	}

	// System Tray Icon and Menu
	systray := app.SystemTray.New()
	systray.SetTooltip("Aikido Safechain")
	systray.SetIcon(icon)
	statusLabel := "Aikido Proxy: checking…"
	menu := application.NewMenu()
	statusItem := menu.Add(statusLabel)
	statusItem.SetEnabled(false)
	menu.AddSeparator()
	menu.Add("Open Dashboard").OnClick(func(_ *application.Context) {
		showDashboard()
	})
	systray.SetMenu(menu)

	statusCh := make(chan string, 8)
	go func() {
		for label := range statusCh {
			statusItem.SetLabel(label)
		}
	}()
	srv := appserver.New()
	srv.SetHandlers(
		func(displayLabel string) { statusCh <- displayLabel },
		func(ev daemon.BlockedEvent) {
			app.Event.Emit("blocked", ev)
			if notifAuthorized {
				notifier.SendNotificationWithActions(notifications.NotificationOptions{
					ID:         "block-" + ev.ID,
					Title:      "Aikido Safechain blocked an event",
					Body:       ev.Product + ": " + ev.PackageName,
					CategoryID: "aikido-blocked",
					Data:       map[string]interface{}{"eventId": ev.ID},
				})
			}
		},
	)

	srv.Start()
	// Notification response: any click on our block notification (body or "Open" button).
	// Re-apply accessory activation policy on the main thread so the app does not show in the dock.
	notifier.OnNotificationResponse(func(result notifications.NotificationResult) {
		if result.Error != nil {
			return
		}
		eventId, _ := result.Response.UserInfo["eventId"].(string)
		if eventId == "" {
			return
		}
		showDashboard()

		go func() {
			time.Sleep(500 * time.Millisecond)
			//application.InvokeAsync(keepDockHidden)
			app.Event.Emit("focus_event", FocusEventPayload{EventId: eventId})
		}()
	})

	// Run the application. This blocks until the application has been exited.
	err := app.Run()
	//dockService.HideAppIcon()

	// If an error occurred while running the application, log it and exit.
	if err != nil {
		log.Fatal(err)
	}
}
