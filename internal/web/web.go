package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	nurl "net/url"
	"os"
	"strings"
	"time"

	"github.com/DevLabFoundry/aws-cli-auth/internal/credentialexchange"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/defaults"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/utils"
)

var (
	ErrTimedOut = errors.New("timed out waiting for input or user closed aws-cli-auth browser instance")
)

// WebConfig
type WebConfig struct {
	// CustomChromeExecutable can point to a chromium like browser executable
	// e.g. chrome, chromium, brave, edge, (any other chromium based browser)
	CustomChromeExecutable string
	// BrowserWSEndpoint connects to an already-running browser via its CDP WebSocket URL
	// instead of launching a new one. Takes precedence over rod's native -rod=url=<ws> flag.
	// Useful in WSL: start Chrome on the Windows host with
	//   chrome.exe --remote-debugging-port=9222
	// then obtain the URL from http://localhost:9222/json/version (webSocketDebuggerUrl)
	// and either pass -rod=url=<url> to go test or call WithBrowserWSEndpoint(<url>).
	BrowserWSEndpoint string
	datadir           string
	// timeout value in seconds
	timeout   int32
	headless  bool
	leakless  bool
	noSandbox bool
}

func NewWebConf(datadir string) *WebConfig {
	wsEndpoint := os.Getenv("ROD_BROWSER_WS_URL")
	return &WebConfig{
		datadir:           datadir,
		headless:          false,
		timeout:           120,
		BrowserWSEndpoint: wsEndpoint,
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

func (wc *WebConfig) WithCustomExecutable(browserPath string) *WebConfig {
	wc.CustomChromeExecutable = browserPath
	return wc
}

// WithBrowserWSEndpoint connects to an already-running browser via its CDP WebSocket URL
// rather than launching a new one. See WebConfig.BrowserWSEndpoint for details.
// Alternatively pass -rod=url=<ws> to go test to use rod's native flag.
func (wc *WebConfig) WithBrowserWSEndpoint(wsURL string) *WebConfig {
	wc.BrowserWSEndpoint = wsURL
	return wc
}

type Web struct {
	conf     *WebConfig
	launcher *launcher.Launcher
	browser  *rod.Browser
	ctx      context.Context
}

// New returns an initialised instance of Web struct
func New(ctx context.Context, conf *WebConfig) (*Web, error) {
	// Prefer an explicitly configured endpoint, then rod's native defaults.URL
	// (set via -rod=url=<ws> when running go test).
	wsEndpoint := conf.BrowserWSEndpoint
	if wsEndpoint == "" {
		wsEndpoint = defaults.URL
	}

	var l *launcher.Launcher
	var controlURL string

	if wsEndpoint != "" {
		// Connect to an already-running browser (e.g. Chrome on the Windows host
		// when running inside WSL). No local launcher is needed.
		controlURL = wsEndpoint
	} else {
		var err error
		l = BuildLauncher(ctx, conf)
		controlURL, err = l.Launch()
		if err != nil {
			return nil, err
		}
	}

	browser := rod.New().
		ControlURL(controlURL).
		MustConnect().NoDefaultDevice()

	return &Web{
		conf:     conf,
		launcher: l,
		browser:  browser,
		ctx:      ctx,
	}, nil
}

func BuildLauncher(ctx context.Context, conf *WebConfig) *launcher.Launcher {
	l := launcher.New()
	// common set up
	l.Devtools(false).
		UserDataDir(conf.datadir).
		Headless(conf.headless).
		NoSandbox(conf.noSandbox).
		Leakless(conf.leakless)

	if conf.CustomChromeExecutable != "" {
		return l.Bin(conf.CustomChromeExecutable)
	}
	// try default locations if custom location is not specified and default location exists
	if defaultExecPath, found := launcher.LookPath(); conf.CustomChromeExecutable == "" && defaultExecPath != "" && found {
		return l.Bin(defaultExecPath)
	}
	return l
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

	page := web.browser.MustPage(conf.ProviderUrl)
	defer page.MustClose()

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

	go func() {
		<-web.ctx.Done()
		web.MustClose()
	}()

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
	go func() {
		<-web.ctx.Done()
		web.MustClose()
	}()

	// close browser even on error
	// should cover most cases even with leakless: false
	defer web.MustClose()

	page := web.browser.MustPage(conf.ProviderUrl)
	defer page.MustClose()

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
	// We do not want to clean up the user directory
	// this ensures that the browser remembers the credentials
	// and anything else done during the sign up process - e.g. extension installation
	// web.launcher.Cleanup()

	// Only close the browser if we launched it ourselves.
	// When connected to an existing browser (launcher == nil, e.g. via ROD_BROWSER_WS_URL
	// or -rod=url=...), calling browser.Close() would destroy the remote browser window.
	if web.launcher != nil {
		_ = web.browser.Close()
		utils.Sleep(0.5)
		web.launcher.Kill()
		// remove process just in case
		// os.Process is cross platform safe way to remove a process
		if osprocess, err := os.FindProcess(web.launcher.PID()); err == nil && osprocess != nil {
			_ = osprocess.Kill()
		}
	}
}
