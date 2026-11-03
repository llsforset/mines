package litebeacon

import "net/http"

// Serve handles a check-in when the request path was registered for a C
// implant. It returns false when this request belongs to another listener.
func Serve(w http.ResponseWriter, r *http.Request) bool {
	if r.URL == nil || !knownPath(r.URL.Path) {
		return false
	}
	store, secrets, err := consoleStore()
	if err != nil {
		notFound(w)
		return true
	}
	if r.Method != http.MethodPost {
		notFound(w)
		return true
	}
	handleCheckin(w, r, store, secrets)
	return true
}

func consoleStore() (*Store, *SecretRegistry, error) {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	return defaultManager()
}
