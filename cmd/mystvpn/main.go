// Command mystvpn provides the Mysterium VPN command-line interface.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
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
	if path, requested := helpRequest(args); requested {
		return runHelp(path, stdout, stderr)
	}
	if !isCommand(args[0]) {
		writeError(stderr, "mystvpn: unknown command %q; use \"mystvpn help\" to list commands", args[0])
		return 2
	}

	switch args[0] {
	case "config":
		return runConfig(args[1:], stdout, stderr)
	case "auth":
		return runAuth(args[1:], cfg, stdout, stderr)
	case "countries":
		return runCountries(args[1:], cfg, stdout, stderr)
	case "cities":
		return runCities(args[1:], cfg, stdout, stderr)
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
	case "version":
		if len(args) != 1 {
			writeError(stderr, "mystvpn version: unexpected argument %q\n", args[1])
			return 2
		}
		fmt.Fprintf(stdout, "mystvpn %s\n", version)
		return 0
	}

	return 2
}

func runConnect(args []string, cfg config.Config, stdout, stderr io.Writer, tunnelRunner wireguard.TunnelRunner) int {
	flags := flag.NewFlagSet("connect", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	countryValue := flags.String("country", "", "country code")
	cityValue := flags.String("city", "", "city or state identifier (empty for any)")
	ipTypeValue := flags.String("ip-type", "", "IP address type")
	profileName := flags.String("profile", "", "profile to use for this connection (defaults to active)")
	flags.Usage = func() {}

	if err := flags.Parse(args); err != nil {
		writeError(stderr, "mystvpn connect: %v; use \"mystvpn help connect\" for usage", err)
		return 2
	}
	if flags.NArg() != 0 {
		writeError(stderr, "mystvpn connect: unexpected argument %q\n", flags.Arg(0))
		return 2
	}
	store, err := config.NewDefaultStore()
	if err != nil {
		writeError(stderr, "mystvpn connect: %v\n", err)
		return 1
	}
	document, err := store.LoadDocument()
	if err != nil {
		writeError(stderr, "mystvpn connect: %v\n", err)
		return 1
	}
	settings, err := document.Effective(*profileName)
	if err != nil {
		writeError(stderr, "mystvpn connect: %v\n", err)
		return 2
	}
	// Only omitted flags inherit defaults. An empty city explicitly removes
	// city/state targeting; required settings still reject empty values.
	provided := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	if !provided["country"] {
		*countryValue = settings.Country
	}
	if !provided["city"] {
		*cityValue = settings.City
	}
	target := settings
	target.City = *cityValue
	if err := target.Normalize(); err != nil {
		writeError(stderr, "mystvpn connect: %v", err)
		return 2
	}
	if !provided["ip-type"] {
		*ipTypeValue = settings.IPType
	}
	if strings.TrimSpace(*countryValue) == "" {
		writeError(stderr, "mystvpn connect: --country is required")
		return 2
	}
	country, err := proxy.ParseCountry(*countryValue)
	if err != nil {
		writeError(stderr, "mystvpn connect: %v\n", err)
		return 2
	}
	if *ipTypeValue == "" {
		writeError(stderr, "mystvpn connect: --ip-type is required")
		return 2
	}
	ipType, err := proxy.ParseIPType(*ipTypeValue)
	if err != nil {
		writeError(stderr, "mystvpn connect: %v\n", err)
		return 2
	}
	sessionStore, err := state.NewDefaultStore()
	if err != nil {
		writeError(stderr, "mystvpn connect: could not initialize local session state: %v", err)
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
		writeError(stderr, "mystvpn connect: could not load local session state: %v", err)
		return 1
	} else {
		keyStore, err := wireguard.NewDefaultKeyStore()
		if err != nil {
			writeError(stderr, "mystvpn connect: could not initialize WireGuard key storage: %v", err)
			return 1
		}
		keyPair, err = keyStore.LoadOrCreate()
		if err != nil {
			writeError(stderr, "mystvpn connect: could not prepare WireGuard keypair: %v", err)
			return 1
		}
	}

	return establishConnection("connect", cfg, stdout, stderr, tunnelRunner, sessionStore, activeSession, keyPair, country, target.City, ipType)
}

func runRefresh(args []string, cfg config.Config, stdout, stderr io.Writer, tunnelRunner wireguard.TunnelRunner) int {
	if !acceptsNoArguments("refresh", args, stderr) {
		return 2
	}

	sessionStore, err := state.NewDefaultStore()
	if err != nil {
		writeError(stderr, "mystvpn refresh: could not initialize local session state: %v", err)
		return 1
	}
	session, err := sessionStore.Load()
	if errors.Is(err, os.ErrNotExist) {
		writeError(stderr, `mystvpn refresh: no active session; run "mystvpn connect" first`)
		return 1
	}
	if err != nil {
		writeError(stderr, "mystvpn refresh: could not load local session state: %v", err)
		return 1
	}
	configStore, err := config.NewDefaultStore()
	if err != nil {
		writeError(stderr, "mystvpn refresh: %v\n", err)
		return 1
	}
	settings, err := configStore.Load()
	if err != nil {
		writeError(stderr, "mystvpn refresh: %v\n", err)
		return 1
	}
	if !validateActiveConnection("refresh", stderr, session) {
		return 1
	}

	keyPair := wireguard.KeyPair{PublicKey: session.PublicKey, PrivateKey: session.PrivateKey}
	return establishConnection("refresh", cfg, stdout, stderr, tunnelRunner, sessionStore, &session, keyPair, settings.Country, settings.City, proxy.IPType(settings.IPType))
}

func establishConnection(command string, cfg config.Config, stdout, stderr io.Writer, tunnelRunner wireguard.TunnelRunner, sessionStore *state.Store, activeSession *state.Session, keyPair wireguard.KeyPair, country, city string, ipType proxy.IPType) int {
	apiClient, err := client.New(cfg.APIURL, cfg.Timeout, cfg.Debug)
	if err != nil {
		writeError(stderr, "mystvpn %s: could not initialize the HTTP client; check the API URL and timeout", command)
		return 1
	}
	authService, err := newAuthService(cfg)
	if err != nil {
		writeRequestError(stderr, command, err)
		return 1
	}
	if err := authService.ConfigureClient(apiClient); err != nil {
		writeSessionRequestError(stderr, command, err)
		return 1
	}

	if city != "" {
		locations, err := proxy.GetConnectionLocations(context.Background(), apiClient, ipType)
		if err != nil {
			writeError(stderr, "mystvpn %s: could not validate city/state %q in %s for IP type %s: %s", command, city, country, ipType, requestErrorMessage(command, err))
			return 1
		}
		if !cityTargetAvailable(locations, country, city) {
			writeError(stderr, "mystvpn %s: city/state %q is not currently available in %s for IP type %s for your account; run \"mystvpn cities --country %s --ip-type %s\" to choose another target, then update the profile's city setting or override it with --city; use \"mystvpn connect --city=\" for country-wide targeting", command, city, country, ipType, country, ipType)
			return 2
		}
	}

	response, err := proxy.Connect(context.Background(), apiClient, proxy.ConnectRequest{
		PublicKey:       keyPair.PublicKey,
		Country:         country,
		City:            city,
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
			writeError(stderr, "mystvpn %s: could not initialize WireGuard config storage: %v", command, err)
			return 1
		}
		configPath, err = wireguard.WriteConfig(configDirectory, response.WGConfig, keyPair.PrivateKey)
		if err != nil {
			writeError(stderr, "mystvpn %s: could not write WireGuard configuration: %v", command, err)
			return 1
		}
	} else {
		configPath = activeSession.ConfigPath
		if err := tunnelRunner.Down(context.Background(), configPath); err != nil && !errors.Is(err, wireguard.ErrTunnelAlreadyDown) {
			writeTunnelCommandError(stderr, command, configPath, err)
			return 1
		}
		if err := wireguard.UpdateConfig(configPath, response.WGConfig, keyPair.PrivateKey); err != nil {
			clearSessionFiles(sessionStore, configPath)
			writeError(stderr, "mystvpn %s: could not write WireGuard configuration: %v", command, err)
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
	if session.City == "" {
		session.City = city
	}
	if session.IPType == "" {
		session.IPType = string(ipType)
	}
	if err := sessionStore.Save(session); err != nil {
		clearSessionFiles(sessionStore, configPath)
		writeError(stderr, "mystvpn %s: could not save local session state: %v", command, err)
		return 1
	}
	if err := tunnelRunner.Up(context.Background(), configPath); err != nil {
		clearSessionFiles(sessionStore, configPath)
		writeTunnelCommandError(stderr, command, configPath, err)
		return 1
	}

	if command == "refresh" {
		writeSuccess(stdout, "VPN connection refreshed.")
	} else {
		writeSuccess(stdout, "Connected to VPN.")
	}
	fmt.Fprintln(stdout)
	writeConnectionDetails(stdout, session, false)
	return 0
}

func validateActiveConnection(command string, stderr io.Writer, session state.Session) bool {
	if strings.TrimSpace(session.PublicKey) == "" || strings.TrimSpace(session.PrivateKey) == "" {
		writeError(stderr, "mystvpn %s: invalid local session state\n", command)
		return false
	}
	if err := wireguard.ValidateConfigPath(session.ConfigPath); err != nil {
		writeError(stderr, "mystvpn %s: invalid local WireGuard config: %v", command, err)
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
		writeError(stderr, "mystvpn status: could not initialize local session state: %v", err)
		return 1
	}
	session, err := sessionStore.Load()
	if errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(stdout, "Connected:  no")
		return 0
	}
	if err != nil {
		writeError(stderr, "mystvpn status: could not load local session state: %v", err)
		return 1
	}

	writeConnectionDetails(stdout, session, true)
	return 0
}

func runDisconnect(args []string, cfg config.Config, stdout, stderr io.Writer, tunnelRunner wireguard.TunnelRunner) int {
	if !acceptsNoArguments("disconnect", args, stderr) {
		return 2
	}

	sessionStore, err := state.NewDefaultStore()
	if err != nil {
		writeError(stderr, "mystvpn disconnect: could not initialize local session state: %v", err)
		return 1
	}
	session, err := sessionStore.Load()
	if errors.Is(err, os.ErrNotExist) {
		writeError(stderr, `mystvpn disconnect: no active session; run "mystvpn connect" first`)
		return 1
	}
	if err != nil {
		writeError(stderr, "mystvpn disconnect: could not load local session state: %v", err)
		return 1
	}
	if !disconnectSession("disconnect", cfg, stderr, tunnelRunner, sessionStore, session) {
		return 1
	}

	writeSuccess(stdout, "Disconnected successfully.")
	return 0
}

func disconnectSession(command string, cfg config.Config, stderr io.Writer, tunnelRunner wireguard.TunnelRunner, sessionStore *state.Store, session state.Session) bool {
	if strings.TrimSpace(session.PublicKey) == "" {
		writeError(stderr, "mystvpn %s: invalid local session state\n", command)
		return false
	}
	if err := wireguard.ValidateConfigPath(session.ConfigPath); err != nil {
		writeError(stderr, "mystvpn %s: invalid local WireGuard config: %v", command, err)
		return false
	}

	apiClient, err := client.New(cfg.APIURL, cfg.Timeout, cfg.Debug)
	if err != nil {
		writeError(stderr, "mystvpn %s: could not initialize the HTTP client; check the API URL and timeout", command)
		return false
	}
	authService, err := newAuthService(cfg)
	if err != nil {
		writeRequestError(stderr, command, err)
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
		writeTunnelCommandError(stderr, command, session.ConfigPath, err)
		return false
	}

	removeErr := wireguard.RemoveConfig(session.ConfigPath)
	clearErr := sessionStore.Clear()
	if removeErr != nil || clearErr != nil {
		writeError(stderr, "mystvpn %s: could not clear local session state: %v", command, errors.Join(removeErr, clearErr))
		return false
	}
	return true
}

func acceptsNoArguments(command string, args []string, stderr io.Writer) bool {
	if len(args) == 0 {
		return true
	}
	writeError(stderr, "mystvpn %s: unexpected argument %q\n", command, args[0])
	return false
}

func clearSessionFiles(sessionStore *state.Store, configPath string) {
	_ = sessionStore.Clear()
	_ = wireguard.RemoveConfig(configPath)
}

func writeTunnelCommandError(output io.Writer, command, configPath string, err error) {
	hint := "check that WireGuard and its networking dependencies are installed"
	details := strings.ToLower(err.Error())
	if strings.Contains(details, "permission denied") || strings.Contains(details, "operation not permitted") || strings.Contains(details, "must be root") {
		hint = "run with sudo (or as root), using the same operating-system user that signed in"
	}
	writeError(output, "mystvpn %s: %v (config_path=%q); %s", command, err, configPath, hint)
}

func writeSessionRequestError(output io.Writer, command string, err error) {
	writeRequestError(output, command, err)
}

func writeConnectRequestError(output io.Writer, err error) {
	writeSessionRequestError(output, "connect", err)
}

func runCountries(args []string, cfg config.Config, stdout, stderr io.Writer) int {
	return runLocationListing("countries", args, cfg, stdout, stderr)
}

func runCities(args []string, cfg config.Config, stdout, stderr io.Writer) int {
	return runLocationListing("cities", args, cfg, stdout, stderr)
}

func runLocationListing(command string, args []string, cfg config.Config, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	ipTypeValue := flags.String("ip-type", "", "IP address type")
	var countryValue *string
	if command == "cities" {
		countryValue = flags.String("country", "", "country code (default: active profile)")
	}
	flags.Usage = func() {}

	if err := flags.Parse(args); err != nil {
		writeError(stderr, "mystvpn %s: %v; use \"mystvpn help %s\" for usage", command, err, command)
		return 2
	}
	if flags.NArg() != 0 {
		writeError(stderr, "mystvpn %s: unexpected argument %q\n", command, flags.Arg(0))
		return 2
	}
	provided := make(map[string]bool)
	flags.Visit(func(f *flag.Flag) { provided[f.Name] = true })
	if !provided["ip-type"] || (command == "cities" && !provided["country"]) {
		store, err := config.NewDefaultStore()
		if err != nil {
			writeError(stderr, "mystvpn %s: %v", command, err)
			return 1
		}
		document, err := store.LoadDocument()
		if err != nil {
			writeError(stderr, "mystvpn %s: %v", command, err)
			return 1
		}
		for _, key := range []string{"ip_type", "country"} {
			flagName := "ip-type"
			target := ipTypeValue
			if key == "country" {
				if command != "cities" {
					continue
				}
				flagName, target = "country", countryValue
			}
			if provided[flagName] {
				continue
			}
			value, err := document.EffectiveValue("", key)
			if err != nil {
				writeError(stderr, "mystvpn %s: %v", command, err)
				return 2
			}
			*target = value.(string)
		}
	}
	ipType, err := proxy.ParseIPType(*ipTypeValue)
	if err != nil {
		writeError(stderr, "mystvpn %s: %v\n", command, err)
		return 2
	}

	country := ""
	if countryValue != nil {
		country, err = proxy.ParseCountry(*countryValue)
		if err != nil {
			writeError(stderr, "mystvpn %s: %v", command, err)
			return 2
		}
	}

	apiClient, err := client.New(cfg.APIURL, cfg.Timeout, cfg.Debug)
	if err != nil {
		writeRequestError(stderr, command, err)
		return 1
	}
	authService, err := newAuthService(cfg)
	if err != nil {
		writeRequestError(stderr, command, err)
		return 1
	}
	if err := authService.ConfigureClient(apiClient); err != nil {
		writeRequestError(stderr, command, err)
		return 1
	}

	if command == "cities" {
		locations, err := proxy.GetConnectionLocations(context.Background(), apiClient, ipType)
		if err != nil {
			writeRequestError(stderr, command, err)
			return 1
		}
		writeCities(stdout, locations, country, ipType)
		return 0
	}

	connectionConfig, err := proxy.GetConnectionConfig(context.Background(), apiClient, ipType)
	if err != nil {
		writeRequestError(stderr, command, err)
		return 1
	}
	writeCountries(stdout, connectionConfig.Countries, ipType)
	return 0
}

func writeCountriesError(output io.Writer, err error) {
	writeRequestError(output, "countries", err)
}

func runAuth(args []string, cfg config.Config, stdout, stderr io.Writer) int {
	if !acceptsNoArguments("auth", args, stderr) {
		return 2
	}
	if cfg.AuthPollInterval <= 0 {
		writeError(stderr, "mystvpn auth: invalid poll interval")
		return 1
	}
	if cfg.AuthTimeout <= 0 {
		writeError(stderr, "mystvpn auth: invalid authentication timeout")
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
			writeError(stderr, `mystvpn auth: authentication timed out; run "mystvpn auth" again and approve the browser prompt before it expires`)
			return 1
		}
		if errors.Is(err, auth.ErrActivationInvalid) {
			writeError(stderr, `mystvpn auth: activation expired or was rejected; run "mystvpn auth" again to request a new approval link`)
			return 1
		}
		writeAuthenticationError(stderr, err)
		return 1
	}

	writeSuccess(stdout, "Authentication successful.")
	return 0
}
func writeAuthenticationError(output io.Writer, err error) {
	writeRequestError(output, "auth", err)
}

func runLogout(args []string, cfg config.Config, stdout, stderr io.Writer, tunnelRunner wireguard.TunnelRunner) int {
	if len(args) != 0 {
		writeError(stderr, "mystvpn logout: unexpected argument %q\n", args[0])
		return 2
	}

	sessionStore, err := state.NewDefaultStore()
	if err != nil {
		writeError(stderr, "mystvpn logout: could not initialize local session state: %v", err)
		return 1
	}
	if session, err := sessionStore.Load(); err == nil {
		if !disconnectSession("logout", cfg, stderr, tunnelRunner, sessionStore, session) {
			return 1
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		writeError(stderr, "mystvpn logout: could not load local session state: %v", err)
		return 1
	}

	store, err := auth.NewDefaultFileStore()
	if err != nil {
		writeError(stderr, "mystvpn logout: %v\n", err)
		return 1
	}
	if err := store.ClearTokens(); err != nil {
		writeError(stderr, "mystvpn logout: %v\n", err)
		return 1
	}
	if err := store.ClearPendingAuth(); err != nil {
		writeError(stderr, "mystvpn logout: %v\n", err)
		return 1
	}

	writeSuccess(stdout, "Logout successful.")
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
		ClientID:           cfg.AuthClientID,
		ActivationClientID: cfg.ActivationClientID,
		AuthorizationURL:   cfg.AuthorizationURL,
		PollInterval:       cfg.AuthPollInterval,
		AuthTimeout:        cfg.AuthTimeout,
	}), nil
}

func isCommand(name string) bool {
	for _, command := range helpTopics {
		if name == command.name {
			return true
		}
	}
	return false
}
