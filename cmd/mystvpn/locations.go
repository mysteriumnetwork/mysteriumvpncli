package main

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/proxy"
	"github.com/mysteriumnetwork/mysteriumvpncli/internal/state"
)

func writeCities(output io.Writer, locations []proxy.ConnectionLocation, country string, ipType proxy.IPType) {
	var cities []string
	for _, location := range locations {
		if countryCode(location.Country) != country || (location.IsAvailable != nil && !*location.IsAvailable) {
			continue
		}
		for _, city := range location.Cities {
			if city.IsAvailable == nil || *city.IsAvailable {
				cities = append(cities, city.City)
			}
		}
	}
	sort.Strings(cities)
	writeSuccess(output, "Available cities/states (%d) in %s for IP type: %s", len(cities), country, ipType)
	if len(cities) == 0 {
		return
	}
	fmt.Fprintln(output)
	if len(cities) == 1 {
		fmt.Fprintln(output, cities[0])
		return
	}
	// Read down the first column, then the second, matching the countries list.
	rows := (len(cities) + 1) / 2
	leftWidth := 0
	for _, city := range cities[:rows] {
		leftWidth = max(leftWidth, utf8.RuneCountInString(city))
	}
	for i, city := range cities[:rows] {
		if i+rows < len(cities) {
			fmt.Fprintf(output, "%-*s    %s\n", leftWidth, city, cities[i+rows])
		} else {
			fmt.Fprintln(output, city)
		}
	}
}

func cityTargetAvailable(locations []proxy.ConnectionLocation, country, city string) bool {
	for _, location := range locations {
		if countryCode(location.Country) != country || (location.IsAvailable != nil && !*location.IsAvailable) {
			continue
		}
		for _, candidate := range location.Cities {
			if candidate.City == city && (candidate.IsAvailable == nil || *candidate.IsAvailable) {
				return true
			}
		}
	}
	return false
}

func countryCode(value string) string {
	return strings.ToUpper(strings.TrimSpace(value))
}

func countryName(code string) string {
	if name, known := proxy.CountryName(code); known {
		return name
	}
	return "Unknown country"
}

// Connect, refresh, and status share the same labels and value alignment.
// Display the saved assignment, including its IP type, rather than the profile
// defaults, which may have changed since the connection was established.
func writeConnectionDetails(output io.Writer, session state.Session, includeStatus bool) {
	location := "Unknown country"
	if code := countryCode(session.Country); code != "" {
		location = fmt.Sprintf("%s (%s)", code, countryName(code))
	}
	ipType := session.IPType
	if ipType == "" {
		ipType = "unknown"
	}
	table := tabwriter.NewWriter(output, 0, 4, 2, ' ', 0)
	if includeStatus {
		fmt.Fprintln(table, "Connected:\tyes")
	}
	fmt.Fprintf(table, "IP address:\t%s\n", session.ExitIP)
	fmt.Fprintf(table, "IP type:\t%s\n", ipType)
	fmt.Fprintf(table, "Country:\t%s\n", location)
	fmt.Fprintf(table, "City:\t%s\n", session.City)
	if includeStatus {
		duration := "unknown"
		if !session.Timestamp.IsZero() {
			duration = max(0, time.Since(session.Timestamp)).Truncate(time.Second).String()
		}
		fmt.Fprintf(table, "Duration:\t%s\n", duration)
	}
	_ = table.Flush()
}

func writeCountries(output io.Writer, countries []string, ipType proxy.IPType) {
	codes := make([]string, len(countries))
	for i, code := range countries {
		codes[i] = countryCode(code)
	}
	sort.Strings(codes)
	writeSuccess(output, "Available countries (%d) for IP type: %s", len(codes), ipType)
	if len(codes) == 0 {
		return
	}
	fmt.Fprintln(output)
	writeCountryTable(output, codes)
}

// Read down the first group, then the second. Size the first group from its
// longest name so the second stays aligned, including accented characters.
func writeCountryTable(output io.Writer, codes []string) {
	const codeWidth = 6 // CODE, followed by two spaces.
	const groupGap = "    "
	if len(codes) <= 1 {
		fmt.Fprintln(output, "CODE  COUNTRY")
		for _, code := range codes {
			fmt.Fprintf(output, "%-4s  %s\n", code, countryName(code))
		}
		return
	}
	rows := (len(codes) + 1) / 2
	leftWidth := len("COUNTRY")
	for _, code := range codes[:rows] {
		leftWidth = max(leftWidth, utf8.RuneCountInString(countryName(code)))
	}
	fmt.Fprintf(output, "%-*s%s%s\n", codeWidth+leftWidth, "CODE  COUNTRY", groupGap, "CODE  COUNTRY")
	for i := 0; i < rows; i++ {
		left := fmt.Sprintf("%-4s  %s", codes[i], countryName(codes[i]))
		if i+rows < len(codes) {
			right := fmt.Sprintf("%-4s  %s", codes[i+rows], countryName(codes[i+rows]))
			fmt.Fprintf(output, "%-*s%s%s\n", codeWidth+leftWidth, left, groupGap, right)
		} else {
			fmt.Fprintln(output, left)
		}
	}
}
