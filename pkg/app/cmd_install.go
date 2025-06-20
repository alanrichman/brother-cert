package app

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"time"

	"github.com/gregtwallace/brother-cert/pkg/printer"
)

// cmdInstallCertAndReset executes a series of commands against a brother printer
// to install the specified ssl key and cert. it then deletes the old cert and
// resets the printer so it will load the newly installed key/cert
func (app *app) cmdInstallCertAndReset(_ context.Context, args []string) error {
	// extra args == error
	if len(args) != 0 {
		return fmt.Errorf("main: failed, %w (%d)", ErrExtraArgs, len(args))
	}

	// must have hostname and password
	if app.config.hostname == nil || *app.config.hostname == "" {
		return errors.New("main: hostname must be specified")
	}
	if app.config.password == nil || *app.config.password == "" {
		return errors.New("main: hostname must be specified")
	}

	// use http?
	useHttp := false
	if app.config.http != nil && *app.config.http {
		app.stdLogger.Println("WARNING: --http flag set, insecure http connection will be used")
		useHttp = true
	}

	// insecure https?
	insecureHttps := false
	if app.config.insecureHttps != nil && *app.config.insecureHttps {
		app.stdLogger.Println("WARNING: --insecure flag set, insecure https connections will be accepted")
		insecureHttps = true
	}

	// load key and cert
	keyPem, certPem, err := app.config.keyCertPemCfg.GetPemBytes("main")
	if err != nil {
		return err
	}

	// make printer (which includes login)
	printerCfg := printer.Config{
		Hostname:      *app.config.hostname,
		Password:      *app.config.password,
		UseHttp:       useHttp,
		InsecureHttps: insecureHttps,
		UserAgent:     fmt.Sprintf("brother-cert/%s (%s; %s)", appVersion, runtime.GOOS, runtime.GOARCH),
	}

	print, err := printer.NewPrinter(printerCfg)
	if err != nil {
		return err
	}
	app.stdLogger.Println("main: connected to printer")

	// get current ssl cert id
	oldCertId, oldCertName, err := print.GetCurrentCertID()
	if err != nil {
		return err
	}
	app.stdLogger.Printf("main: current printer cert is %s (id: %d)", oldCertName, oldCertId)

	// install new key/cert
	app.stdLogger.Println("main: uploading new cert...")
	newCertId, err := print.UploadNewCert(keyPem, certPem)
	if err != nil {
		return err
	}
	app.stdLogger.Printf("main: new printer cert installed (but not yet activated) (id: %d)", newCertId)

	// activate new key/cert
	app.stdLogger.Printf("main: activating cert (id: %d) and rebooting... please wait 60 seconds...", newCertId)
	err = print.SetActiveCert(newCertId)
	if err != nil {
		return err
	}

	// IF deleting old cert (i.e. old id != 0 (0 cant be deleted, its "Preset"))
	if oldCertId != 0 {
		// wait for reboot to finish
		time.Sleep(60 * time.Second)
		app.stdLogger.Printf("main: reboot should be complete")

		// use https now (even if user originally said not to, since cert is installed)
		printerCfg.UseHttp = false

		// must login again due to the restart
		print, err = printer.NewPrinter(printerCfg)
		if err != nil {
			return errors.New("main: failed to reconnect to printer")
		}
		app.stdLogger.Println("main: reconnected to printer")

		// do delete of old cert
		app.stdLogger.Printf("main: deleting old cert (id: %d) ...", oldCertId)
		err = print.DeleteCert(oldCertId)
		if err != nil {
			return fmt.Errorf("main: failed to delete cert (id: %d) (%w)", oldCertId, err)
		}

		app.stdLogger.Printf("main: old cert (id: %d) deleted", oldCertId)
	}

	return nil
}
