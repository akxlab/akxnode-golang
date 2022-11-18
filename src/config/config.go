package config

type Config struct {
	name    string
	forkURI string
	rpcHost string
	rpcPort string
	wssHost string
	wssPort string
}

type P2PConfig struct {
	TimeoutInSeconds uint
	MinPeers         uint
	MaxPeers         uint
	Version          []byte
}

func (p2pc *P2PConfig) SetDefaults() {
	p2pc.TimeoutInSeconds = 60 * 1000 // milliseconds
	p2pc.MinPeers = 1
	p2pc.MaxPeers = 50
	p2pc.Version = []byte("1-0-0")

}
