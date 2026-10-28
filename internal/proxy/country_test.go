package proxy

import "testing"

func TestCountryName(t *testing.T) {
	for _, test := range []struct {
		code, want string
	}{
		{"DE", "Germany"}, {" gb ", "United Kingdom"}, {"US", "United States"},
		{"AX", "Åland Islands"}, {"CI", "Côte d’Ivoire"},
		{"CD", "Democratic Republic of the Congo"},
		{"ZZ", ""}, {"DF", ""}, {"", ""},
	} {
		name, known := CountryName(test.code)
		if name != test.want || known != (test.want != "") {
			t.Errorf("CountryName(%q) = %q, %v; want %q", test.code, name, known, test.want)
		}
	}
}

func TestCountryCatalogCoversAssignedCodes(t *testing.T) {
	if len(countryNames) != 249 {
		t.Fatalf("catalog has %d entries, want 249 assigned codes", len(countryNames))
	}
	for code, name := range countryNames {
		if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' || name == "" {
			t.Errorf("invalid catalog entry %q: %q", code, name)
		}
		if parsed, err := ParseCountry(code); err != nil || parsed != code {
			t.Errorf("named country %q fails validation: %v", code, err)
		}
	}
}
