package web

import (
	"errors"
	"fmt"
	"net/http"
	nurl "net/url"
	"os"
	"strings"
	"time"

	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	ps "github.com/mitchellh/go-ps"
)

var (
	ErrTimedOut = errors.New("timed out waiting for input")
)

// WebConb
type WebConfig struct {
	datadir string
	// timeout value in seconds
	timeout   int32
	headless  bool
	leakless  bool
	noSandbox bool
}

func NewWebConf(datadir string) *WebConfig {
	return &WebConfig{
		datadir:  datadir,
		headless: false,
		timeout:  120,
	}
}

func (wc *WebConfig) WithTimeout(timeoutSeconds int32) *WebConfig {
	wc.timeout = timeoutSeconds
	return wc
}

func (wc *WebConfig) WithHeadless() *WebConfig {
	wc.headless = true
	return wc
}

func (wc *WebConfig) WithNoSandbox() *WebConfig {
	wc.noSandbox = true
	return wc
}

type Web struct {
	conf     *WebConfig
	launcher *launcher.Launcher
	browser  *rod.Browser
}

// New returns an initialised instance of Web struct
func New(conf *WebConfig) *Web {

	l := launcher.New().
		Devtools(false).
		Headless(conf.headless).
		UserDataDir(conf.datadir).
		NoSandbox(conf.noSandbox).
		Leakless(conf.leakless)

	url := l.MustLaunch()

	browser := rod.New().
		ControlURL(url).
		MustConnect().NoDefaultDevice()

	return &Web{
		conf:     conf,
		launcher: l,
		browser:  browser,
	}
}

func (web *Web) WithConfig(conf *WebConfig) *Web {
	web.conf = conf
	return web
}

// GetSamlLogin performs a saml login for a given
func (web *Web) GetSamlLogin(conf credentialexchange.CredentialConfig) (string, error) {

	// close browser even on error
	// should cover most cases even with leakless: false
	defer web.MustClose()

	web.browser.MustPage(conf.ProviderUrl)

	router := web.browser.HijackRequests()
	defer router.MustStop()

	capturedSaml := make(chan string)

	router.MustAdd(fmt.Sprintf("%s*", conf.AcsUrl), func(ctx *rod.Hijack) {
		if ctx.Request.Method() == "POST" || ctx.Request.Method() == "GET" {
			cp := ctx.Request.Body()
			capturedSaml <- cp
		}
	})

	go router.Run()

	// forever loop wait for either a successfully
	// extracted SAMLResponse
	//
	// Timesout after a specified timeout - default 120s
	for {
		select {
		case saml := <-capturedSaml:
			saml = strings.Split(saml, "SAMLResponse=")[1]
			saml = strings.Split(saml, "&")[0]
			return nurl.QueryUnescape(saml)
		case <-time.After(time.Duration(web.conf.timeout) * time.Second):
			return "", fmt.Errorf("%w", ErrTimedOut)
		// listen for closing of browser
		// gracefully clean up
		case browserEvent := <-web.browser.Event():
			if browserEvent != nil && browserEvent.Method == "Inspector.detached" {
				return "", fmt.Errorf("%w", ErrTimedOut)
			}
		}
	}
}

// GetSSOCredentials
func (web *Web) GetSSOCredentials(conf credentialexchange.CredentialConfig) (string, error) {

	defer web.MustClose()

	web.browser.MustPage(conf.ProviderUrl)

	router := web.browser.HijackRequests()

	defer router.MustStop()

	capturedCreds, loadedUserInfo := make(chan string), make(chan bool)

	router.MustAdd(conf.SsoUserEndpoint, func(ctx *rod.Hijack) {
		ctx.MustLoadResponse()
		if ctx.Request.Method() == "GET" {
			ctx.Response.SetHeader(
				"Content-Type", "text/html; charset=utf-8",
				"Content-Location", conf.SsoCredFedEndpoint,
				"Location", conf.SsoCredFedEndpoint)
			ctx.Response.Payload().ResponseCode = http.StatusMovedPermanently
			loadedUserInfo <- true
		}
	})

	router.MustAdd(conf.SsoCredFedEndpoint, func(ctx *rod.Hijack) {
		_ = ctx.LoadResponse(http.DefaultClient, true)
		if ctx.Request.Method() == "GET" {
			cp := ctx.Response.Body()
			capturedCreds <- cp
		}
	})

	go router.Run()

	// forever loop wait for either a successfully
	// extracted Creds
	//
	// Timesout after a specified timeout - default 120s
	for {
		select {
		case <-loadedUserInfo:
			// empty case to ensure user endpoint sets correct clientside cookies
		case creds := <-capturedCreds:
			return creds, nil
		case <-time.After(time.Duration(web.conf.timeout) * time.Second):
			return "", fmt.Errorf("%w", ErrTimedOut)
		// listen for closing of browser
		// gracefully clean up
		case browserEvent := <-web.browser.Event():
			if browserEvent != nil && browserEvent.Method == "Inspector.detached" {
				return "", fmt.Errorf("%w", ErrTimedOut)
			}
		}
	}
}

func (web *Web) MustClose() {
	err := web.browser.Close()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to close browser instance: %s", err)
	}
	// launcher.Kill performs the PID lookup and kills it
	web.launcher.Kill()
}

func (web *Web) ForceKill(datadir string) error {
	errs := []error{}

	if err := checkRodProcess(); err != nil {
		errs = append(errs, err)
	}
	// once processes have been killed
	// we can remove the datadir
	if err := os.RemoveAll(datadir); err != nil {
		errs = append(errs, err)
	}

	if len(errs) > 0 {
		return fmt.Errorf("%v", errs[:])
	}
	return nil
}

// checkRodProcess gets a list running process
// kills any hanging rod browser process from any previous improprely closed sessions
func checkRodProcess() error {
	pids := make([]int, 0)
	ps, err := ps.Processes()
	if err != nil {
		return err
	}
	for _, v := range ps {
		// grab all chromium processes
		// on windows the name will be reported as `chrome.exe`
		if strings.Contains(strings.ToLower(v.Executable()), "chrom") {
			fmt.Fprintf(os.Stderr, "Found process: (%d) and its parent (%d)\n", v.Pid(), v.PPid())
			pids = append(pids, v.Pid())
		}
	}
	for _, pid := range pids {
		if proc, _ := os.FindProcess(pid); proc != nil {
			fmt.Fprintf(os.Stderr, "Process to be killed as part of clean up: %d\n", pid)
			proc.Kill()
		}
	}
	return nil
}
