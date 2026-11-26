package handshake

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// Memory keeps the shape that last connected, so that the next connection
// starts with it, and saves it in a file so that a restart of the program
// (the app restarts it after a failure) does too. The zero value remembers
// in memory only.
type Memory struct {
	mu   sync.Mutex
	last *Shape
	file string
}

// Load makes file the place the shape is kept and reads what it holds. A
// missing, unreadable or invalid file is no memory and not an error worth
// more than the returned one, which the caller may log.
func (m *Memory) Load(file string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.file = file
	data, err := os.ReadFile(file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	var s Shape
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if !s.valid() {
		return nil
	}
	m.last = &s
	return nil
}

// Last returns the remembered shape, nil when there is none.
func (m *Memory) Last() *Shape {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last == nil {
		return nil
	}
	s := *m.last
	return &s
}

// Remember keeps s as the shape that worked. It reports whether that
// changed what was remembered, and any error from saving it (the shape is
// remembered in memory regardless).
func (m *Memory) Remember(s Shape) (changed bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.last != nil && *m.last == s {
		return false, nil
	}
	m.last = &s
	if m.file == "" {
		return true, nil
	}
	return true, writeFile(m.file, s)
}

// Forget drops the remembered shape (the file stays until a new one
// replaces it).
func (m *Memory) Forget() {
	m.mu.Lock()
	m.last = nil
	m.mu.Unlock()
}

// writeFile replaces file with s, whole or not at all.
func writeFile(file string, s Shape) error {
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(file)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(file)+".*.tmp")
	if err != nil {
		return err
	}
	name := tmp.Name()
	_, err = tmp.Write(data)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(name, 0o600)
	}
	if err == nil {
		err = os.Rename(name, file)
	}
	if err != nil {
		_ = os.Remove(name)
	}
	return err
}
