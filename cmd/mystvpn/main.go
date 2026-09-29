// Command mystvpn provides the Mysterium VPN command-line interface.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/auth"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/config"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/proxy"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/state"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/wireguard"
)

var version = "dev"

const countriesPerRow = 10

var commands = []string{
	"auth",
	"countries",
	"connect",
	"refresh",
	"status",
	"disconnect",
	"logout",
	"help",
	"version",
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin *os.File, stdout, stderr io.Writer) int {
	return runWithConfig(args, stdin, stdout, stderr, config.Load())
}

func runWithConfig(args []string, stdin *os.File, stdout, stderr io.Writer, cfg config.Config) int {
	return runWithDependencies(args, stdin, stdout, stderr, cfg, wireguard.WGQuickRunner{})
}

func runWithDependencies(args []string, stdin *os.File, stdout, stderr io.Writer, cfg config.Config, tunnelRunner wireguard.TunnelRunner) int {
	if len(args) == 0 {
		writeUsage(stdout)
		return 0
	}
	if !isCommand(args[0]) {
		fmt.Fprintf(stderr, "mystvpn: unknown command %q\n", args[0])
		return 2
	}

	switch args[0] {
	case "auth":
		return runAuth(args[1:], cfg, stdout, stderr)
	case "countries":
		return runCountries(args[1:], cfg, stdout, stderr)
	case "connect":
		return runConnect(args[1:], cfg, stdout, stderr, tunnelRunner)
	case "refresh":
		return runRefresh(args[1:], cfg, stdout, stderr, tunnelRunner)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "disconnect":
		return runDisconnect(args[1:], cfg, stdout, stderr, tunnelRunner)
	case "logout":
		return runLogout(args[1:], cfg, stdout, stderr, tunnelRunner)
	case "help":
		if len(args) != 1 {
			fmt.Fprintf(stderr, "mystvpn help: unexpected argument %q\n", args[1])
			return 2
		}
		writeUsage(stdout)
		return 0
	case "version":
		if len(args) != 1 {
			fmt.Fprintf(stderr, "mystvpn version: unexpected argument %q\n", args[1])
			return 2
		}
		fmt.Fprintf(stdout, "mystvpn %s\n", version)
		return 0
	}

	return 2
}

func runConnect(args []string, cfg config.Config, stdout, stderr io.Writer, tunnelRunner wireguard.TunnelRunner) int {
	flags := flag.NewFlagSet("connect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	countryValue := flags.String("country", "", "country code")
	ipTypeValue := flags.String("ip-type", "", "IP address type")
	flags.Usage = func() {}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, `mystvpn connect: help flags are not supported; use "mystvpn help"`)
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "mystvpn connect: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	if strings.TrimSpace(*countryValue) == "" {
		fmt.Fprintln(stderr, "mystvpn connect: --country is required")
		return 2
	}
	country, err := proxy.ParseCountry(*countryValue)
	if err != nil {
		fmt.Fprintf(stderr, "mystvpn connect: %v\n", err)
		return 2
	}
	if *ipTypeValue == "" {
		fmt.Fprintln(stderr, "mystvpn connect: --ip-type is required")
		return 2
	}
	ipType, err := proxy.ParseIPType(*ipTypeValue)
	if err != nil {
		fmt.Fprintf(stderr, "mystvpn connect: %v\n", err)
		return 2
	}
	sessionStore, err := state.NewDefaultStore()
	if err != nil {
		fmt.Fprintln(stderr, "mystvpn connect: could not initialize local session state")
		return 1
	}

	var activeSession *state.Session
	var keyPair wireguard.KeyPair
	session, err := sessionStore.Load()
	if err == nil {
		if !validateActiveConnection("connect", stderr, session) {
			return 1
		}
		activeSession = &session
		keyPair = wireguard.KeyPair{PublicKey: session.PublicKey, PrivateKey: session.PrivateKey}
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, "mystvpn connect: could not load local session state")
		return 1
	} else {
		keyStore, err := wireguard.NewDefaultKeyStore()
		if err != nil {
			fmt.Fprintln(stderr, "mystvpn connect: could not initialize WireGuard key storage")
			return 1
		}
		keyPair, err = keyStore.LoadOrCreate()
		if err != nil {
			fmt.Fprintln(stderr, "mystvpn connect: could not prepare WireGuard keypair")
			return 1
		}
	}

	return establishConnection("connect", cfg, stdout, stderr, tunnelRunner, sessionStore, activeSession, keyPair, country, ipType)
}

func runRefresh(args []string, cfg config.Config, stdout, stderr io.Writer, tunnelRunner wireguard.TunnelRunner) int {
	if !acceptsNoArguments("refresh", args, stderr) {
		return 2
	}

	sessionStore, err := state.NewDefaultStore()
	if err != nil {
		fmt.Fprintln(stderr, "mystvpn refresh: could not initialize local session state")
		return 1
	}
	session, err := sessionStore.Load()
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, "no active session")
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "mystvpn refresh: could not load local session state")
		return 1
	}
	country, err := proxy.ParseCountry(session.Country)
	if err != nil {
		fmt.Fprintln(stderr, "mystvpn refresh: invalid local session state")
		return 1
	}
	ipType, err := proxy.ParseIPType(session.IPType)
	if err != nil {
		fmt.Fprintln(stderr, "mystvpn refresh: invalid local session state")
		return 1
	}
	if !validateActiveConnection("refresh", stderr, session) {
		return 1
	}

	keyPair := wireguard.KeyPair{PublicKey: session.PublicKey, PrivateKey: session.PrivateKey}
	return establishConnection("refresh", cfg, stdout, stderr, tunnelRunner, sessionStore, &session, keyPair, country, ipType)
}

func establishConnection(command string, cfg config.Config, stdout, stderr io.Writer, tunnelRunner wireguard.TunnelRunner, sessionStore *state.Store, activeSession *state.Session, keyPair wireguard.KeyPair, country string, ipType proxy.IPType) int {
	apiClient, err := client.New(cfg.APIURL, cfg.Timeout, cfg.Debug)
	if err != nil {
		fmt.Fprintf(stderr, "mystvpn %s: request failed\n", command)
		return 1
	}
	authService, err := newAuthService(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "mystvpn %s: authentication failed\n", command)
		return 1
	}
	if err := authService.ConfigureClient(apiClient); err != nil {
		writeSessionRequestError(stderr, command, err)
		return 1
	}

	response, err := proxy.Connect(context.Background(), apiClient, proxy.ConnectRequest{
		PublicKey:       keyPair.PublicKey,
		Country:         country,
		IPType:          ipType,
		OSType:          proxy.OSTypeLinux,
		ResetConnection: true,
	})
	if err != nil {
		writeSessionRequestError(stderr, command, err)
		return 1
	}

	configPath := ""
	if activeSession == nil {
		configDirectory, err := wireguard.DefaultConfigDirectory()
		if err != nil {
			fmt.Fprintf(stderr, "mystvpn %s: could not initialize WireGuard config storage\n", command)
			return 1
		}
		configPath, err = wireguard.WriteConfig(configDirectory, response.WGConfig, keyPair.PrivateKey)
		if err != nil {
			fmt.Fprintf(stderr, "mystvpn %s: invalid WireGuard configuration\n", command)
			return 1
		}
	} else {
		configPath = activeSession.ConfigPath
		if err := tunnelRunner.Down(context.Background(), configPath); err != nil {
			fmt.Fprintf(stderr, "mystvpn %s: %v\n", command, err)
			return 1
		}
		if err := wireguard.UpdateConfig(configPath, response.WGConfig, keyPair.PrivateKey); err != nil {
			clearSessionFiles(sessionStore, configPath)
			fmt.Fprintf(stderr, "mystvpn %s: invalid WireGuard configuration\n", command)
			return 1
		}
	}

	session := state.Session{
		SessionID:  response.ID,
		PublicKey:  keyPair.PublicKey,
		PrivateKey: keyPair.PrivateKey,
		Country:    response.Country,
		IPType:     string(response.IPType),
		ExitIP:     response.ExitIP,
		City:       response.City,
		ConfigPath: configPath,
		Timestamp:  time.Now().UTC(),
	}
	if session.Country == "" {
		session.Country = country
	}
	if session.IPType == "" {
		session.IPType = string(ipType)
	}
	if err := sessionStore.Save(session); err != nil {
		clearSessionFiles(sessionStore, configPath)
		fmt.Fprintf(stderr, "mystvpn %s: could not save local session state\n", command)
		return 1
	}
	if err := tunnelRunner.Up(context.Background(), configPath); err != nil {
		clearSessionFiles(sessionStore, configPath)
		fmt.Fprintf(stderr, "mystvpn %s: %v\n", command, err)
		return 1
	}

	fmt.Fprintf(stdout, "exit_ip: %s\n", session.ExitIP)
	fmt.Fprintf(stdout, "country: %s\n", session.Country)
	fmt.Fprintf(stdout, "city: %s\n", session.City)
	return 0
}

func validateActiveConnection(command string, stderr io.Writer, session state.Session) bool {
	if strings.TrimSpace(session.PublicKey) == "" || strings.TrimSpace(session.PrivateKey) == "" {
		fmt.Fprintf(stderr, "mystvpn %s: invalid local session state\n", command)
		return false
	}
	if err := wireguard.ValidateConfigPath(session.ConfigPath); err != nil {
		fmt.Fprintf(stderr, "mystvpn %s: invalid local WireGuard config\n", command)
		return false
	}
	return true
}

func runStatus(args []string, stdout, stderr io.Writer) int {
	if !acceptsNoArguments("status", args, stderr) {
		return 2
	}

	sessionStore, err := state.NewDefaultStore()
	if err != nil {
		fmt.Fprintln(stderr, "mystvpn status: could not initialize local session state")
		return 1
	}
	session, err := sessionStore.Load()
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stdout, "connected: no")
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "mystvpn status: could not load local session state")
		return 1
	}

	fmt.Fprintln(stdout, "connected: yes")
	fmt.Fprintf(stdout, "IP address: %s\n", session.ExitIP)
	fmt.Fprintf(stdout, "country: %s\n", session.Country)
	fmt.Fprintf(stdout, "city: %s\n", session.City)
	return 0
}

func runDisconnect(args []string, cfg config.Config, stdout, stderr io.Writer, tunnelRunner wireguard.TunnelRunner) int {
	if !acceptsNoArguments("disconnect", args, stderr) {
		return 2
	}

	sessionStore, err := state.NewDefaultStore()
	if err != nil {
		fmt.Fprintln(stderr, "mystvpn disconnect: could not initialize local session state")
		return 1
	}
	session, err := sessionStore.Load()
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, "no active session")
		return 1
	}
	if err != nil {
		fmt.Fprintln(stderr, "mystvpn disconnect: could not load local session state")
		return 1
	}
	if !disconnectSession("disconnect", cfg, stderr, tunnelRunner, sessionStore, session) {
		return 1
	}

	fmt.Fprintln(stdout, "Disconnected successfully")
	return 0
}

func disconnectSession(command string, cfg config.Config, stderr io.Writer, tunnelRunner wireguard.TunnelRunner, sessionStore *state.Store, session state.Session) bool {
	if strings.TrimSpace(session.PublicKey) == "" {
		fmt.Fprintf(stderr, "mystvpn %s: invalid local session state\n", command)
		return false
	}
	if err := wireguard.ValidateConfigPath(session.ConfigPath); err != nil {
		fmt.Fprintf(stderr, "mystvpn %s: invalid local WireGuard config\n", command)
		return false
	}

	apiClient, err := client.New(cfg.APIURL, cfg.Timeout, cfg.Debug)
	if err != nil {
		fmt.Fprintf(stderr, "mystvpn %s: request failed\n", command)
		return false
	}
	authService, err := newAuthService(cfg)
	if err != nil {
		fmt.Fprintf(stderr, "mystvpn %s: authentication failed\n", command)
		return false
	}
	if err := authService.ConfigureClient(apiClient); err != nil {
		writeSessionRequestError(stderr, command, err)
		return false
	}
	if err := proxy.Disconnect(context.Background(), apiClient, session.PublicKey); err != nil {
		writeSessionRequestError(stderr, command, err)
		return false
	}
	if err := tunnelRunner.Down(context.Background(), session.ConfigPath); err != nil {
		fmt.Fprintf(stderr, "mystvpn %s: %v\n", command, err)
		return false
	}

	removeErr := wireguard.RemoveConfig(session.ConfigPath)
	clearErr := sessionStore.Clear()
	if removeErr != nil || clearErr != nil {
		fmt.Fprintf(stderr, "mystvpn %s: could not clear local session state\n", command)
		return false
	}
	return true
}

func acceptsNoArguments(command string, args []string, stderr io.Writer) bool {
	if len(args) == 0 {
		return true
	}
	fmt.Fprintf(stderr, "mystvpn %s: unexpected argument %q\n", command, args[0])
	return false
}

func clearSessionFiles(sessionStore *state.Store, configPath string) {
	_ = sessionStore.Clear()
	_ = wireguard.RemoveConfig(configPath)
}

func writeSessionRequestError(output io.Writer, command string, err error) {
	var authStatusErr *auth.HTTPStatusError
	if errors.As(err, &authStatusErr) {
		fmt.Fprintf(output, "mystvpn %s: HTTP status %d\n", command, authStatusErr.StatusCode)
		return
	}
	var apiErr *client.APIError
	if errors.As(err, &apiErr) {
		fmt.Fprintf(output, "mystvpn %s: HTTP status %d\n", command, apiErr.StatusCode)
		return
	}
	if errors.Is(err, auth.ErrTokenNotFound) {
		fmt.Fprintf(output, "mystvpn %s: authentication required; run \"mystvpn auth\" first\n", command)
		return
	}
	fmt.Fprintf(output, "mystvpn %s: request failed\n", command)
}

func writeConnectRequestError(output io.Writer, err error) {
	writeSessionRequestError(output, "connect", err)
}

func runCountries(args []string, cfg config.Config, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("countries", flag.ContinueOnError)
	flags.SetOutput(stderr)
	ipTypeValue := flags.String("ip-type", "", "IP address type")
	flags.Usage = func() {}

	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprintln(stderr, `mystvpn countries: help flags are not supported; use "mystvpn help"`)
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "mystvpn countries: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	if *ipTypeValue == "" {
		fmt.Fprintln(stderr, "mystvpn countries: --ip-type is required")
		return 2
	}
	ipType, err := proxy.ParseIPType(*ipTypeValue)
	if err != nil {
		fmt.Fprintf(stderr, "mystvpn countries: %v\n", err)
		return 2
	}

	apiClient, err := client.New(cfg.APIURL, cfg.Timeout, cfg.Debug)
	if err != nil {
		writeCountriesError(stderr, err)
		return 1
	}
	authService, err := newAuthService(cfg)
	if err != nil {
		writeCountriesError(stderr, err)
		return 1
	}
	if err := authService.ConfigureClient(apiClient); err != nil {
		writeCountriesError(stderr, err)
		return 1
	}

	connectionConfig, err := proxy.GetConnectionConfig(context.Background(), apiClient, ipType)
	if err != nil {
		writeCountriesError(stderr, err)
		return 1
	}
	writeCountries(stdout, connectionConfig.Countries)
	return 0
}

func writeCountries(output io.Writer, countries []string) {
	sortedCountries := append([]string(nil), countries...)
	sort.Strings(sortedCountries)

	fmt.Fprintf(output, "Available countries (%d):\n", len(sortedCountries))
	if len(sortedCountries) == 0 {
		return
	}
	fmt.Fprintln(output)

	for index, country := range sortedCountries {
		if index > 0 {
			if index%countriesPerRow == 0 {
				fmt.Fprintln(output)
			} else {
				fmt.Fprint(output, "  ")
			}
		}
		fmt.Fprint(output, country)
	}
	fmt.Fprintln(output)
}

func writeCountriesError(output io.Writer, err error) {
	var authStatusErr *auth.HTTPStatusError
	if errors.As(err, &authStatusErr) {
		fmt.Fprintf(output, "mystvpn countries: HTTP status %d\n", authStatusErr.StatusCode)
		return
	}
	var apiErr *client.APIError
	if errors.As(err, &apiErr) {
		fmt.Fprintf(output, "mystvpn countries: HTTP status %d\n", apiErr.StatusCode)
		return
	}
	if errors.Is(err, auth.ErrTokenNotFound) {
		fmt.Fprintln(output, `mystvpn countries: authentication required; run "mystvpn auth" first`)
		return
	}
	fmt.Fprintln(output, "mystvpn countries: request failed")
}

func runAuth(args []string, cfg config.Config, stdout, stderr io.Writer) int {
	if !acceptsNoArguments("auth", args, stderr) {
		return 2
	}
	if cfg.AuthPollInterval <= 0 {
		fmt.Fprintln(stderr, "mystvpn auth: invalid poll interval")
		return 1
	}
	if cfg.AuthTimeout <= 0 {
		fmt.Fprintln(stderr, "mystvpn auth: invalid authentication timeout")
		return 1
	}

	service, err := newAuthService(cfg)
	if err != nil {
		writeAuthenticationError(stderr, err)
		return 1
	}
	result, err := service.Start(context.Background())
	if err != nil {
		writeAuthenticationError(stderr, err)
		return 1
	}

	fmt.Fprintln(stdout, "Open this URL in your browser to authenticate:")
	fmt.Fprintln(stdout, result.AuthorizationURL)
	fmt.Fprintln(stdout, "Waiting for authentication approval...")
	pollContext, cancel := context.WithTimeout(context.Background(), cfg.AuthTimeout)
	defer cancel()
	if err := service.Poll(pollContext); err != nil {
		_ = service.Cancel()
		if errors.Is(err, auth.ErrAuthenticationTimedOut) {
			fmt.Fprintln(stderr, "mystvpn auth: authentication timed out")
			return 1
		}
		if errors.Is(err, auth.ErrActivationInvalid) {
			fmt.Fprintln(stderr, "mystvpn auth: activation expired or was rejected")
			return 1
		}
		writeAuthenticationError(stderr, err)
		return 1
	}

	fmt.Fprintln(stdout, "Authentication successful.")
	return 0
}
func writeAuthenticationError(output io.Writer, err error) {
	var statusErr *auth.HTTPStatusError
	if errors.As(err, &statusErr) {
		fmt.Fprintf(output, "mystvpn auth: HTTP status %d\n", statusErr.StatusCode)
		return
	}
	fmt.Fprintln(output, "mystvpn auth: authentication failed")
}

func runLogout(args []string, cfg config.Config, stdout, stderr io.Writer, tunnelRunner wireguard.TunnelRunner) int {
	if len(args) != 0 {
		fmt.Fprintf(stderr, "mystvpn logout: unexpected argument %q\n", args[0])
		return 2
	}

	sessionStore, err := state.NewDefaultStore()
	if err != nil {
		fmt.Fprintln(stderr, "mystvpn logout: could not initialize local session state")
		return 1
	}
	if session, err := sessionStore.Load(); err == nil {
		if !disconnectSession("logout", cfg, stderr, tunnelRunner, sessionStore, session) {
			return 1
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stderr, "mystvpn logout: could not load local session state")
		return 1
	}

	store, err := auth.NewDefaultFileStore()
	if err != nil {
		fmt.Fprintf(stderr, "mystvpn logout: %v\n", err)
		return 1
	}
	if err := store.ClearTokens(); err != nil {
		fmt.Fprintf(stderr, "mystvpn logout: %v\n", err)
		return 1
	}
	if err := store.ClearPendingAuth(); err != nil {
		fmt.Fprintf(stderr, "mystvpn logout: %v\n", err)
		return 1
	}

	fmt.Fprintln(stdout, "Logout successful.")
	return 0
}

func newAuthService(cfg config.Config) (*auth.Service, error) {
	store, err := auth.NewDefaultFileStore()
	if err != nil {
		return nil, err
	}
	authClient, err := client.New(cfg.APIURL, cfg.Timeout, cfg.Debug)
	if err != nil {
		return nil, err
	}
	return auth.NewService(authClient, store, auth.Options{
		ClientID:         cfg.AuthClientID,
		AuthorizationURL: cfg.AuthorizationURL,
		PollInterval:     cfg.AuthPollInterval,
		AuthTimeout:      cfg.AuthTimeout,
	}), nil
}

func isCommand(name string) bool {
	for _, command := range commands {
		if name == command {
			return true
		}
	}
	return false
}

func writeUsage(output io.Writer) {
	fmt.Fprintln(output, "mystvpn - Mysterium VPN CLI for Linux")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Usage:")
	fmt.Fprintln(output, "  mystvpn <command>")
	fmt.Fprintln(output)
	fmt.Fprintln(output, "Commands:")
	for _, command := range commands {
		if command == "auth" {
			fmt.Fprintln(output, "  auth")
			continue
		}
		if command == "countries" {
			fmt.Fprintln(output, "  countries --ip-type <residential|hosting>")
			continue
		}
		if command == "connect" {
			fmt.Fprintln(output, "  connect --country <code> --ip-type <residential|hosting>")
			continue
		}
		fmt.Fprintf(output, "  %s\n", command)
	}
}
