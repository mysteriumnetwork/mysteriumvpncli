package client

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

const domainCooldown = 30 * time.Minute

type domainRecord struct {
	Preferred string               `json:"preferred,omitempty"`
	Failed    map[string]time.Time `json:"failed_until,omitempty"`
}

// DomainState remembers availability locally, without looking up a public IP.
// Construct one per process and share it among clients.
type DomainState struct {
	mu      sync.Mutex
	path    string
	records map[string]domainRecord
	now     func() time.Time
}

func NewDomainState(path string) *DomainState {
	s := &DomainState{path: path, records: make(map[string]domainRecord), now: time.Now}
	if data, err := os.ReadFile(path); err == nil && len(data) <= 1<<20 {
		_ = json.Unmarshal(data, &s.records)
	}
	if s.records == nil {
		s.records = make(map[string]domainRecord)
	}
	return s
}

func (s *DomainState) order(origin string, hosts []string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.records[origin]
	now := s.now()
	result := append([]string(nil), hosts...)
	primary := hosts[0]
	rank := func(host string) int {
		if now.Before(record.Failed[host]) {
			return 3
		}
		// Probe the primary again once its cooldown expires.
		if host == primary {
			return 0
		}
		if host == record.Preferred {
			return 1
		}
		return 2
	}
	sort.SliceStable(result, func(i, j int) bool { return rank(result[i]) < rank(result[j]) })
	return result
}

func (s *DomainState) record(origin, host string, success bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	record := s.records[origin]
	if record.Failed == nil {
		record.Failed = make(map[string]time.Time)
	}
	for host, until := range record.Failed {
		if !s.now().Before(until) {
			delete(record.Failed, host)
		}
	}
	if success {
		record.Preferred = host
		delete(record.Failed, host)
	} else {
		record.Failed[host] = s.now().Add(domainCooldown)
	}
	s.records[origin] = record
	if s.path == "" {
		return
	}
	data, err := json.Marshal(s.records)
	if err != nil || os.MkdirAll(filepath.Dir(s.path), 0700) != nil {
		return
	}
	file, err := os.CreateTemp(filepath.Dir(s.path), ".domain-state-*")
	if err != nil {
		return
	}
	defer os.Remove(file.Name())
	if _, err = file.Write(data); err != nil {
		file.Close()
		return
	}
	if file.Close() != nil {
		return
	}
	_ = os.Rename(file.Name(), s.path)
}

func (s *DomainState) known(origin string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.records[origin]
	return ok
}
