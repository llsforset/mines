package litebeacon

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"

	"github.com/bishopfox/sliver/server/assets"
)

const defaultIntervalSec = 180

var (
	mgrMutex   sync.Mutex
	mgrStore   *Store
	mgrSecrets *SecretRegistry
	mgrLis     *Listener
	mgrURL     string
	mgrPath    = DefaultPath
)

func defaultManager() (*Store, *SecretRegistry, error) {
	if mgrStore == nil {
		secrets, err := LoadSecrets(SecretsPath(assets.GetRootAppDir()))
		if err != nil {
			return nil, nil, err
		}
		mgrStore = NewStore()
		mgrSecrets = secrets
	}
	return mgrStore, mgrSecrets, nil
}

// StartDefault starts (or replaces) the singleton console-managed listener.
func StartDefault(host string, port int, path, externalURL string) (string, error) {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	_, _, err := defaultManager()
	if err != nil {
		return "", err
	}
	if mgrLis != nil {
		_ = mgrLis.Stop()
		mgrLis = nil
	}
	if host == "" {
		host = "0.0.0.0"
	}
	// port == 0 让系统分配临时端口（测试用）；控制台表单默认给 8443
	lis, err := Start(ListenerConfig{Host: host, Port: port, Path: path}, mgrStore, mgrSecrets)
	if err != nil {
		return "", err
	}
	mgrLis = lis
	mgrPath = lis.path
	if externalURL == "" {
		display := host
		if display == "0.0.0.0" || display == "::" {
			display = "127.0.0.1"
		}
		portHint := port
		if portHint == 0 {
			_, boundPort, splitErr := net.SplitHostPort(lis.Addr().String())
			if splitErr == nil {
				portHint, _ = strconv.Atoi(boundPort)
			}
		}
		externalURL = fmt.Sprintf("https://%s", net.JoinHostPort(display, fmt.Sprint(portHint)))
	}
	mgrURL = strings.TrimSuffix(externalURL, "/")
	return lis.Addr().String(), nil
}

func StopDefault() error {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	if mgrLis == nil {
		return fmt.Errorf("lite listener not running")
	}
	err := mgrLis.Stop()
	mgrLis = nil
	return err
}

// ConfigInfo is the console-facing build configuration for the C implant.
type ConfigInfo struct {
	Running   bool   `json:"running"`
	Addr      string `json:"addr"`
	URL       string `json:"url"`
	SecretB64 string `json:"secretB64"`
	ConfigH   string `json:"configH"`
}

func currentURL() string {
	if mgrURL != "" {
		return mgrURL + mgrPath
	}
	return "https://127.0.0.1:8443" + DefaultPath
}

func buildInfo(entry SecretEntry) (ConfigInfo, error) {
	cfgH, err := GenerateConfigH(ConfigParams{
		URL:             currentURL(),
		SecretB64:       entry.SecretB64,
		KeyName:         entry.KeyName,
		UserAgent:       RandomUserAgent(),
		BaseIntervalSec: defaultIntervalSec,
	})
	if err != nil {
		return ConfigInfo{}, err
	}
	info := ConfigInfo{URL: currentURL(), SecretB64: entry.SecretB64, ConfigH: cfgH}
	if mgrLis != nil {
		info.Running = true
		info.Addr = mgrLis.Addr().String()
	}
	return info, nil
}

// GetConfig returns build info for the latest secret without issuing a new one.
func GetConfig() (ConfigInfo, error) {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	_, secrets, err := defaultManager()
	if err != nil {
		return ConfigInfo{}, err
	}
	entry, ok := secrets.Latest()
	if !ok {
		return ConfigInfo{}, fmt.Errorf("no secrets")
	}
	return buildInfo(entry)
}

// NewConfig issues a fresh secret (old ones stay valid) and returns its build info.
func NewConfig(label string) (ConfigInfo, error) {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	_, secrets, err := defaultManager()
	if err != nil {
		return ConfigInfo{}, err
	}
	entry, err := secrets.Issue(label)
	if err != nil {
		return ConfigInfo{}, err
	}
	return buildInfo(entry)
}

func ListBeacons() []Beacon {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	if mgrStore == nil {
		return nil
	}
	return mgrStore.ListBeacons()
}

func DeleteBeacon(id string) {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	if mgrStore != nil {
		mgrStore.Delete(id)
	}
}

func QueueTask(id string, t Task) (Task, bool) {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	if mgrStore == nil {
		return t, false
	}
	return mgrStore.QueueTask(id, t)
}

func TakeResults(id string) []Result {
	mgrMutex.Lock()
	defer mgrMutex.Unlock()
	if mgrStore == nil {
		return nil
	}
	return mgrStore.TakeResults(id)
}
