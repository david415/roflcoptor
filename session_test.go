package main

import (
	"fmt"
	"sync"
	"testing"

	"github.com/yawning/bulb"
)

type MockProcInfo struct {
}

func (r MockProcInfo) LookupTCPSocketProcess(srcPort uint16, dstAddr net.IP, dstPort uint16) *procsnitch.Info {
	info := procsnitch.Info{
		UID:       1,
		Pid:       1,
		ParentPid: 1,
		loaded:    true,
		ExePath:   "testing_exec_path",
		CmdLine:   "testing_cmd_line",
	}
	return &info
}

func TestProxyListener(t *testing.T) {
	config := RoflcoptorConfig{
		LogFile:              "-",
		FiltersPath:          "./filters",
		ListenTCPPort:        "4356",
		ListenIP:             "127.0.0.1",
		TorControlSocketPath: "/var/lib/tor/control",
	}
	wg := sync.WaitGroup{}
	watch := false

	proxyListener, err := NewProxyListener(&config, &wg, watch)
	if err != nil {
		t.Errorf("failed to create proxy listener: %s", err)
		t.Fail()
	}

	go proxyListener.FilterTCPAcceptLoop()

	var torConn *bulb.Conn
	torConn, err = bulb.Dial("tcp", "127.0.0.1:4356")
	if err != nil {
		t.Errorf("ERR/tor: Failed to connect to tor control port: %v", err)
		t.Fail()
	}

	var protoInfo *bulb.ProtocolInfo
	protoInfo, err = torConn.ProtocolInfo()
	if err != nil {
		t.Errorf("ERR/tor: Failed to issue PROTOCOLINFO: %v", err)
		t.Fail()
	}
	fmt.Printf("protoInfo %s", protoInfo)

}
