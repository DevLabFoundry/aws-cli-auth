package web

import (
	"fmt"
	nurl "net/url"
	"os"
	"strings"
	"time"

	"github.com/dnitsch/aws-cli-auth/internal/credentialexchange"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	ps "github.com/mitchellh/go-ps"
)

type WebConfig struct {
	datadir  string
	timeout  int32
	headless bool
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
		Leakless(true)

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

// GetSamlLogin performs a saml login for a given
func (web *Web) GetSamlLogin(conf credentialexchange.SamlConfig) (string, error) {

	// do not clean up userdata
	defer web.browser.MustClose()

	web.browser.MustPage(conf.ProviderUrl)

	router := web.browser.HijackRequests()
	defer router.MustStop()

	capturedSaml := make(chan string)

	router.MustAdd(fmt.Sprintf("%s*", conf.AcsUrl), func(ctx *rod.Hijack) {
		// TODO: support both REDIRECT AND POST
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
			return "", fmt.Errorf("timed out")
		}
	}
}

func (web *Web) ClearCache() error {
	errs := []error{}

	if err := os.RemoveAll(web.conf.datadir); err != nil {
		errs = append(errs, err)
	}
	if err := checkRodProcess(); err != nil {
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
		if strings.Contains(v.Executable(), "Chromium") {
			pids = append(pids, v.Pid())
		}
	}
	for _, pid := range pids {
		fmt.Fprintf(os.Stderr, "Process to be killed as part of clean up: %d", pid)
		if proc, _ := os.FindProcess(pid); proc != nil {
			proc.Kill()
		}
	}
	return nil
}
