package main

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/subgraph/roflcoptor/service"
	"github.com/yawning/bulb"
)

type AccumulatingListener struct {
	net, address    string
	buffer          bytes.Buffer
	mortalService   *service.MortalService
	hasProtocolInfo bool
	hasAuthenticate bool
}

func NewAccumulatingListener(net, address string) *AccumulatingListener {
	l := AccumulatingListener{
		net:             net,
		address:         address,
		hasProtocolInfo: true,
		hasAuthenticate: true,
	}
	return &l
}

func (a *AccumulatingListener) Start() {
	a.mortalService = service.NewMortalService(a.net, a.address, a.SessionWorker)
	err := a.mortalService.Start()
	if err != nil {
		panic(err)
	}
}

func (a *AccumulatingListener) Stop() {
	fmt.Println("AccumulatingListener STOP")
	a.mortalService.Stop()
}

func (a *AccumulatingListener) SessionWorker(conn net.Conn) error {
	connReader := bufio.NewReader(conn)
	for {

		line, err := connReader.ReadBytes('\n')
		if err != nil {
			//fmt.Println("AccumulatingListener read error:", err)
		}
		lineStr := strings.TrimSpace(string(line))
		a.buffer.WriteString(lineStr + "\n")

		if string(lineStr) == "PROTOCOLINFO" {
			if a.hasProtocolInfo {
				conn.Write([]byte(`250-PROTOCOLINFO 1
250-AUTH METHODS=NULL
250-VERSION Tor="0.2.7.6"
250 OK` + "\n"))
			} else {
				conn.Write([]byte("510 PROTOCOLINFO denied.\r\n"))
			}
		} else if string(lineStr) == "AUTHENTICATE" {
			if a.hasAuthenticate {
				conn.Write([]byte("250 OK\r\n"))
			} else {
				conn.Write([]byte("510 PROTOCOLINFO denied.\r\n"))
			}
		} else {
			conn.Write([]byte("250 OK\r\n"))
		}
	}
	return nil
}

func setupFakeProxyAndTorService(proxyNet, proxyAddress string) (*AccumulatingListener, *ProxyListener) {
	listeners := []AddrString{
		{
			Net:     proxyNet,
			Address: proxyAddress,
		},
	}
	config := RoflcoptorConfig{
		FiltersPath:       "./test_filters",
		Listeners:         listeners,
		TorControlNet:     "unix",
		TorControlAddress: "test_tor_socket",
	}
	fakeTorService := NewAccumulatingListener(config.TorControlNet, config.TorControlAddress)
	fakeTorService.Start()
	watch := false
	proxyListener := NewProxyListener(&config, watch)
	proxyListener.StartListeners()
	fmt.Println("started listeners for testing")
	return fakeTorService, proxyListener
}

func TestGetNilFilterPolicy(t *testing.T) {
	fmt.Println("- TestGetNilFilterPolicy")
	proxyNet := "tcp"
	proxyAddress := "127.0.0.1:4492"

	fakeTorService, proxyService := setupFakeProxyAndTorService(proxyNet, proxyAddress)
	defer fakeTorService.Stop()
	defer proxyService.StopListeners()

	clientConn, err := bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()
	if err != nil {
		panic(err)
	}
	clientConn.Debug(true)
	err = clientConn.Authenticate("")
	if err == nil {
		t.Error("expected failure")
		t.Fail()
	}

}

func TestGetFilterPolicyFromExecPath(t *testing.T) {
	fmt.Println("- TestGetFilterPolicyFromExecPath")
	proxyNet := "tcp"
	proxyAddress := "127.0.0.1:4491"
	fakeTorService, proxyService := setupFakeProxyAndTorService(proxyNet, proxyAddress)
	defer fakeTorService.Stop()
	defer proxyService.StopListeners()

	clientConn, err := bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()
	if err != nil {
		panic(err)
	}
	clientConn.Debug(true)
	err = clientConn.Authenticate("")
	if err != nil {
		t.Errorf("client connect fail: %s\n", err)
		t.Fail()
	}
}

func TestGetMissingFilterPolicy(t *testing.T) {
	fmt.Println("- TestGetMissingFilterPolicy")
	proxyNet := "tcp"
	proxyAddress := "127.0.0.1:4493"
	fakeTorService, proxyService := setupFakeProxyAndTorService(proxyNet, proxyAddress)
	defer fakeTorService.Stop()
	defer proxyService.StopListeners()

	clientConn, err := bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()
	if err != nil {
		panic(err)
	}
	clientConn.Debug(true)
	err = clientConn.Authenticate("")
	if err == nil {
		t.Errorf("expected failure due to missing filter policy")
		t.Fail()
	}
}

func TestProxyAuthListenerSession(t *testing.T) {
	fmt.Println("- TestProxyAuthListenerSession")
	var err error

	proxyNet := "tcp"
	proxyAddress := "127.0.0.1:4491"
	fakeTorService, proxyService := setupFakeProxyAndTorService(proxyNet, proxyAddress)
	defer fakeTorService.Stop()
	defer proxyService.StopListeners()

	var clientConn *bulb.Conn
	clientConn, err = bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()
	if err != nil {
		t.Errorf("Failed to connect to tor control port: %v", err)
		t.Fail()
	}
	clientConn.Debug(true)
	err = clientConn.Authenticate("")
	if err != nil {
		t.Errorf("authentication error: %s", err)
		t.Fail()
	}
}

func TestProxyListenerSession(t *testing.T) {
	var err error
	var clientConn *bulb.Conn
	var response *bulb.Response

	fmt.Println("- TestProxyListenerSession")

	proxyNet := "tcp"
	proxyAddress := "127.0.0.1:4491"
	fakeTorService, proxyService := setupFakeProxyAndTorService(proxyNet, proxyAddress)
	defer proxyService.StopListeners()
	defer fakeTorService.Stop()
	// test legit connection from ricochet

	clientConn, err = bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()

	if err != nil {
		t.Errorf("Failed to connect to tor control port: %v", err)
		t.Fail()
	}

	//clientConn.Debug(true)
	clientConn.StartAsyncReader()

	//defer os.Remove(config.TorControlAddress)

	err = clientConn.Authenticate("")
	if err != nil {
		t.Errorf("tor control port proxy auth fail: %v", err)
		t.Fail()
	}

	response, err = clientConn.Request("ADD_ONION NEW:BEST Port=4491,80")
	if err != nil || !response.IsOk() {
		t.Errorf("wtf ADD_ONION fail: %v", err)
		t.Fail()
	}

	response, err = clientConn.Request("ADD_ONION NEW:BEST Port=4491")
	fmt.Println("response is ", response)
	if response.IsOk() {
		t.Error("yo ADD_ONION fail should have failed because target was control port")
		t.Fail()
	}
	want := "PROTOCOLINFO\nAUTHENTICATE\nADD_ONION NEW:BEST Port=4491,80\n"
	if fakeTorService.buffer.String() != want {
		t.Errorf("accumulated control commands don't match: got:\n%s\n\nbut expected:\n%s", fakeTorService.buffer.String(), want)
		t.Fail()
	}
}

func TestProxyListenerWatchModeSession(t *testing.T) {
	fmt.Println("TestProxyListenerWatchModeSession")
	var err error
	proxyNet := "tcp"
	proxyAddress := "127.0.0.1:4491"

	listeners := []AddrString{
		{
			Net:     proxyNet,
			Address: proxyAddress,
		},
	}
	config := RoflcoptorConfig{
		FiltersPath:       "./filters",
		Listeners:         listeners,
		TorControlNet:     "unix",
		TorControlAddress: "test_tor_socket",
	}
	fakeTorService := NewAccumulatingListener(config.TorControlNet, config.TorControlAddress)
	fakeTorService.Start()

	watch := true
	proxyService := NewProxyListener(&config, watch)
	defer fakeTorService.Stop()

	proxyService.StartListeners()
	defer proxyService.StopListeners()

	// test legit connection from ricochet
	var clientConn *bulb.Conn
	clientConn, err = bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()

	if err != nil {
		t.Errorf("Failed to connect to tor control port: %v", err)
		t.Fail()
	}

	clientConn.Debug(true)
	//defer os.Remove(config.TorControlAddress)

	err = clientConn.Authenticate("")
	if err != nil {
		panic(err)
	}

	want := "PROTOCOLINFO\nAUTHENTICATE\n"
	if fakeTorService.buffer.String() != want {
		t.Errorf("accumulated control commands don't match: got:\n%s\n\nbut expected:\n%s", fakeTorService.buffer.String(), want)
		t.Fail()
	}
}

func TestUnixSocketListener(t *testing.T) {
	fmt.Println("TestUnixSocketListener")
	var err error
	proxyNet := "unix"
	proxyAddress := "testing123_socket"
	fakeTorService, proxyService := setupFakeProxyAndTorService(proxyNet, proxyAddress)
	defer fakeTorService.Stop()
	defer proxyService.StopListeners()

	var clientConn *bulb.Conn
	clientConn, err = bulb.Dial(proxyNet, proxyAddress)
	defer clientConn.Close()
	if err != nil {
		t.Errorf("Failed to connect to tor control port: %v", err)
		t.Fail()
	}
	clientConn.Debug(true)
	err = clientConn.Authenticate("")
	if err != nil {
		t.Errorf("authentication error")
		t.Fail()
	}
}

func TestBadAddressTorControlPort(t *testing.T) {
	fmt.Println("TestBadAddressTorControlPort")
	var conn net.Conn
	torControlNet := "unix"
	torControlAddress := "123"
	denyOnions := []AddrString{}
	policy := &SievePolicyJSONConfig{}
	session := NewAuthProxySession(conn, torControlNet, torControlAddress, denyOnions, false, policy)

	err := session.initTorControl()
	if err == nil {
		t.Errorf("expected failure")
		t.Fail()
	}
}

func TestNoProtocolInfoTorControlPort(t *testing.T) {
	fmt.Println("TestNoProtocolInfoTorControlPort")
	listeners := []AddrString{
		{
			Net:     "unix",
			Address: "proxy_socket",
		},
	}
	config := RoflcoptorConfig{
		FiltersPath:       "./filters",
		Listeners:         listeners,
		TorControlNet:     "unix",
		TorControlAddress: "test_tor_socket",
	}
	fakeTorService := NewAccumulatingListener(config.TorControlNet, config.TorControlAddress)
	fakeTorService.hasProtocolInfo = false
	fakeTorService.Start()
	defer fakeTorService.Stop()

	var conn net.Conn
	denyOnions := []AddrString{}
	policy := &SievePolicyJSONConfig{}
	session := NewAuthProxySession(conn, config.TorControlNet, config.TorControlAddress, denyOnions, false, policy)
	err := session.initTorControl()
	if err == nil {
		t.Errorf("expected failure")
		t.Fail()
	}
	session.torConn.Close()
}

func TestNoAuthenticateTorControlPort(t *testing.T) {
	fmt.Println("TestNoAuthenticateTorControlPort")
	listeners := []AddrString{
		{
			Net:     "unix",
			Address: "proxy_socket",
		},
	}
	config := RoflcoptorConfig{
		FiltersPath:       "./filters",
		Listeners:         listeners,
		TorControlNet:     "unix",
		TorControlAddress: "test_tor_socket",
	}
	fakeTorService := NewAccumulatingListener(config.TorControlNet, config.TorControlAddress)
	fakeTorService.hasAuthenticate = false
	fakeTorService.Start()
	defer fakeTorService.Stop()

	var conn net.Conn
	denyOnions := []AddrString{}
	policy := &SievePolicyJSONConfig{}
	session := NewAuthProxySession(conn, config.TorControlNet, config.TorControlAddress, denyOnions, false, policy)
	err := session.initTorControl()
	if err == nil {
		t.Errorf("expected failure")
		t.Fail()
	}
	session.torConn.Close()
}

func TestShouldAllowOnion(t *testing.T) {
	fmt.Println("TestShouldAllowOnion")
	var conn net.Conn
	denyOnions := []AddrString{
		{"unix", "/var/run/tor/control"},
		{"tcp", "127.0.0.1:9051"},
	}
	policy := &SievePolicyJSONConfig{}
	session := NewAuthProxySession(conn, "meownew", "meowaddr", denyOnions, false, policy)

	tests := []struct {
		in   string
		want bool
	}{
		{"meow", true},
		{"", true},
		{"ADD_ONION NEW:BEST Port=80,127.0.0.1:9051", false},
		{"ADD_ONION NEW:BEST Port=80,unix:/var/run/tor/control", false},
		{"ADD_ONION NEW:BEST Port=80", true},
		{"ADD_ONION NEW:BEST Port=9051", false},
		{"ADD_ONION NEW:BEST Port=80,80", true},
		{"ADD_ONION NEW:BEST Port=9051,9051", false},
		{"ADD_ONION NEW:BEST Port=80,9051", false},
		{"ADD_ONION NEW:BEST Port=9051,80", true},
	}

	for _, test := range tests {
		isAllowed := session.shouldAllowOnion(test.in)
		if isAllowed != test.want {
			t.Errorf("test fail; command: %s wanted: %v but got %v", test.in, test.want, isAllowed)
			t.Fail()
		}
	}
}
