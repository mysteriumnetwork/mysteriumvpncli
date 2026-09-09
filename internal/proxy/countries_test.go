package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"github.com/mysteriumnetwork/mysteriumvpncli/internal/client"
)

func TestParseIPType(t *testing.T) {
	for _, value := range []string{"residential", "hosting"} {
		got, err := ParseIPType(value)
		if err != nil {
			t.Fatalf("ParseIPType(%q) error = %v", value, err)
		}
		if string(got) != value {
			t.Errorf("ParseIPType(%q) = %q", value, got)
		}
	}

	if _, err := ParseIPType("mobile"); err == nil {
		t.Error("ParseIPType(mobile) error = nil, want validation error")
	}
}

func TestParseCountry(t *testing.T) {
	tests := []struct {
		value string
		want  string
		valid bool
	}{
		{value: "de", want: "DE", valid: true},
		{value: " CA ", want: "CA", valid: true},
		{value: "", valid: false},
		{value: "D", valid: false},
		{value: "DEU", valid: false},
		{value: "D1", valid: false},
	}

	for _, test := range tests {
		got, err := ParseCountry(test.value)
		if test.valid && (err != nil || got != test.want) {
			t.Errorf("ParseCountry(%q) = %q, %v; want %q", test.value, got, err, test.want)
		}
		if !test.valid && err == nil {
			t.Errorf("ParseCountry(%q) error = nil", test.value)
		}
	}
}

func TestGetConnectionConfig(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", request.Method)
		}
		if request.URL.Path != "/api/v1/connection/config" {
			t.Errorf("path = %q, want /api/v1/connection/config", request.URL.Path)
		}
		if got := request.URL.Query().Get("ip_type"); got != "residential" {
			t.Errorf("ip_type = %q, want residential", got)
		}
		if got := request.Header.Get("Authorization"); got != "Bearer auth-value" {
			t.Errorf("Authorization = %q, want bearer token", got)
		}

		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{
			"countries":["DE","MX","PA","SE","BR","CA"],
			"top_countries":["SE","CA"],
			"ignored":"value"
		}`))
	}))
	defer server.Close()

	apiClient, err := client.New(server.URL+"/api/v1", time.Second, false)
	if err != nil {
		t.Fatalf("client.New() error = %v", err)
	}
	apiClient.SetToken("auth-value")

	config, err := GetConnectionConfig(context.Background(), apiClient, IPTypeResidential)
	if err != nil {
		t.Fatalf("GetConnectionConfig() error = %v", err)
	}
	if want := []string{"DE", "MX", "PA", "SE", "BR", "CA"}; !reflect.DeepEqual(config.Countries, want) {
		t.Errorf("Countries = %v, want %v", config.Countries, want)
	}
	if want := []string{"SE", "CA"}; !reflect.DeepEqual(config.TopCountries, want) {
		t.Errorf("TopCountries = %v, want %v", config.TopCountries, want)
	}
}
