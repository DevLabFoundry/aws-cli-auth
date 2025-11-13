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
	datadir                string
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

func (wc *WebConfig) WithCustomExecutable(browserPath string) *WebConfig {
	wc.CustomChromeExecutable = browserPath
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
	l := BuildLauncher(ctx, conf)

	url, err := l.Launch()
	if err != nil {
		return nil, err
	}
	browser := rod.New().
		ControlURL(url).
		MustConnect().NoDefaultDevice()

	web := &Web{
		conf:     conf,
		launcher: l,
		browser:  browser,
		ctx:      ctx,
	}

	return web, nil
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
		fmt.Fprintf(os.Stderr, "browser: %s\n", conf.CustomChromeExecutable)
		return l.Bin(conf.CustomChromeExecutable)
	}
	// try default locations if custom location is not specified and default location exists
	if defaultExecPath, found := launcher.LookPath(); conf.CustomChromeExecutable == "" && defaultExecPath != "" && found {
		fmt.Fprintf(os.Stderr, "browser: %s\n", defaultExecPath)
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
	web.launcher.Kill()
	web.launcher.Cleanup()
	// swallows errors here - until a structured logger
	_ = web.browser.Close()
	utils.Sleep(0.5)
	// remove process just in case
	// os.Process is cross platform safe way to remove a process
	if osprocess, err := os.FindProcess(web.launcher.PID()); err == nil && osprocess != nil {
		_ = osprocess.Kill()
	}
}
