package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

func TestGetConnectionLocationsExceedingOneMiB(t *testing.T) {
	const cityCount = 2000
	city := `{"city":"berlin","is_available":true,"translations":{"en":"` + strings.Repeat("Berlin ", 80) + `"}}`
	body := `[{"country":"DE","cities":[` + strings.TrimSuffix(strings.Repeat(city+",", cityCount), ",") + `]}]`
	if len(body) <= 1<<20 {
		t.Fatal("regression fixture must exceed the old 1 MiB limit")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/connection/config/locations" || r.URL.Query().Get("ip_type") != "residential" || r.Header.Get("Authorization") != "Bearer test-token" {
			t.Errorf("unexpected locations request: %s", r.URL)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	apiClient, err := client.New(server.URL, time.Second, false)
	if err != nil {
		t.Fatal(err)
	}
	apiClient.SetAccessToken("test-token")
	locations, err := GetConnectionLocations(context.Background(), apiClient, IPTypeResidential)
	if err != nil {
		t.Fatal(err)
	}
	if len(locations) != 1 || len(locations[0].Cities) != cityCount || locations[0].Cities[cityCount-1].City != "berlin" {
		t.Fatal("large location catalogue was not fully decoded")
	}
}
