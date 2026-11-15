package netops

import "fmt"

// OpSyncWG makes the kernel's WireGuard devices match a WGSpec (Op.WG).
const OpSyncWG OpKind = "wg_sync"

// WGPeerSpec is one peer of a device. Keys are named, never carried: the
// preshared key is read from the secret directory where the device is
// configured.
type WGPeerSpec struct {
	PublicKey    string   `json:"public_key"`
	PresharedRef string   `json:"preshared_ref,omitempty"`
	AllowedIPs   []string `json:"allowed_ips"`
	Endpoint     string   `json:"endpoint,omitempty"`
	Keepalive    int      `json:"keepalive,omitempty"`
}

// WGDeviceSpec is one WireGuard device.
type WGDeviceSpec struct {
	Name       string   `json:"name"`
	ListenPort int      `json:"listen_port"`
	MTU        int      `json:"mtu,omitempty"`
	Addresses  []string `json:"addresses"`
	// KeyRef names the private key in the secret directory. Empty means the
	// device keeps the key it has, which is how an existing device is
	// adopted without its key ever being read.
	KeyRef string       `json:"key_ref,omitempty"`
	Peers  []WGPeerSpec `json:"peers"`
}

// WGSpec is the desired state of every WireGuard device this program owns.
// Devices it created earlier and that are no longer listed are removed.
type WGSpec struct {
	SecretDir string         `json:"secret_dir"`
	Devices   []WGDeviceSpec `json:"devices"`
}

// SyncWG applies spec. It is a mutation.
func (w *Writer) SyncWG(spec WGSpec) error {
	if !w.AllowWrites {
		return fmt.Errorf("wireguard sync: writes are disabled")
	}
	return w.mutate(Op{Kind: OpSyncWG, WG: &spec})
}
