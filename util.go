package vm

import (
	"encoding/binary"
	"flag"
	"fmt"
	decoder "github.com/hasnhasan/vm/decoders"
	"github.com/hasnhasan/vm/decoders/netflow"
	"github.com/hasnhasan/vm/decoders/netflowlegacy"
	"github.com/hasnhasan/vm/decoders/sflow"
	flowmessage "github.com/hasnhasan/vm/pb"

	. "github.com/ahmetb/go-linq"

	"net"
	"runtime"
	"sync"
	"time"

	"github.com/libp2p/go-reuseport"
	"github.com/pquerna/ffjson/ffjson"
)

// Tanımlamaları yap
var (
	Workers = flag.Int("workers", 1, "Number of workers per collector")
)

// Flow çıktıları için
type flowData struct {
	Type          flowmessage.FlowMessage_FlowType
	TimeReceived  uint64
	SequenceNum   uint32
	SamplingRate  uint64
	FlowDirection string
	// Sampler information
	SamplerAddress string
	// Found inside packet
	TimeFlowStart uint64
	TimeFlowEnd   uint64
	// Size of the sampled packet
	Bytes   uint64
	Packets uint64
	// Source/destination addresses
	SrcAddr string
	DstAddr string
	// Layer 3 protocol (IPv4/IPv6/ARP/...)
	Etype uint32
	// Layer 4 protocol
	Proto string
	// Ports for UDP and TCP
	SrcPort uint32
	DstPort uint32
	// Interfaces
	SrcIf uint32
	DstIf uint32
	// Ethernet information
	SrcMac string
	DstMac string
	// Vlan
	SrcVlan uint32
	DstVlan uint32
	// 802.1q VLAN in sampled packet
	VlanId uint32
	// VRF
	IngressVrfID uint32
	EgressVrfID  uint32
	// IP and TCP special flags
	IPTos            uint32
	ForwardingStatus uint32
	IPTTL            uint32
	TCPFlags         uint32
	IcmpType         uint32
	IcmpCode         uint32
	IPv6FlowLabel    uint32
	// Fragments (IPv4/IPv6)
	FragmentId      uint32
	FragmentOffset  uint32
	BiFlowDirection uint32
	// Autonomous system information
	SrcAS     uint32
	DstAS     uint32
	NextHop   string
	NextHopAS uint32
	// Prefix size
	SrcNet uint32
	DstNet uint32
}

var flowDatas []flowData

// Cihazdan gelen bilgileri flowDatas a ata
type ProccessTransport struct {
}

type Transport interface {
	Publish([]*flowmessage.FlowMessage)
}

type BaseMessage struct {
	Src     net.IP
	Port    int
	Payload []byte
}

func (s *ProccessTransport) Publish(msgs []*flowmessage.FlowMessage) {

	for _, fmsg := range msgs {
		srcmac := make([]byte, 8)
		dstmac := make([]byte, 8)
		binary.BigEndian.PutUint64(srcmac, fmsg.SrcMac)
		binary.BigEndian.PutUint64(dstmac, fmsg.DstMac)
		srcmac = srcmac[2:8]
		dstmac = dstmac[2:8]

		flowData := flowData{
			Type:             fmsg.Type,
			TimeReceived:     fmsg.TimeReceived,
			SequenceNum:      fmsg.SequenceNum,
			SamplingRate:     fmsg.SamplingRate,
			SamplerAddress:   net.IP(fmsg.SamplerAddress).String(),
			TimeFlowStart:    fmsg.TimeFlowStart,
			TimeFlowEnd:      fmsg.TimeFlowEnd,
			Bytes:            fmsg.Bytes,
			Packets:          fmsg.Packets,
			SrcAddr:          net.IP(fmsg.SrcAddr).String(),
			DstAddr:          net.IP(fmsg.DstAddr).String(),
			Etype:            fmsg.Etype,
			Proto:            protocolToString(fmsg.Proto),
			SrcPort:          fmsg.SrcPort,
			DstPort:          fmsg.DstPort,
			SrcIf:            fmsg.SrcIf,
			DstIf:            fmsg.DstIf,
			SrcMac:           net.HardwareAddr(srcmac).String(),
			DstMac:           net.HardwareAddr(dstmac).String(),
			SrcVlan:          fmsg.SrcVlan,
			DstVlan:          fmsg.DstVlan,
			VlanId:           fmsg.VlanId,
			IngressVrfID:     fmsg.IngressVrfID,
			EgressVrfID:      fmsg.EgressVrfID,
			IPTos:            fmsg.IPTos,
			ForwardingStatus: fmsg.ForwardingStatus,
			IPTTL:            fmsg.IPTTL,
			TCPFlags:         fmsg.TCPFlags,
			IcmpType:         fmsg.IcmpType,
			IcmpCode:         fmsg.IcmpCode,
			IPv6FlowLabel:    fmsg.IPv6FlowLabel,
			FragmentId:       fmsg.FragmentId,
			FragmentOffset:   fmsg.FragmentOffset,
			BiFlowDirection:  fmsg.BiFlowDirection,
			SrcAS:            fmsg.SrcAS,
			DstAS:            fmsg.DstAS,
			NextHop:          net.IP(fmsg.NextHop).String(),
			NextHopAS:        fmsg.NextHopAS,
			SrcNet:           fmsg.SrcNet,
			DstNet:           fmsg.DstNet,
		}

		flowDatas = append(flowDatas, flowData)
	}
}

func RunListener(FlowType string, Addr string, Port int, Report bool) {
	flag.Parse()

	runtime.GOMAXPROCS(runtime.NumCPU())

	//log.Info("Starting GoFlow")
	chn := make(chan bool)
	wg := &sync.WaitGroup{}

	switch FlowType {
	case "sFlow": // sFlow

		sSFlow := &sflow.StateSFlow{
			Transport: &ProccessTransport{},
		}

		//Worker Oluştur
		wg.Add(1)
		go func() {
			err := UDPRoutine("sFlow", sSFlow.DecodeFlow, *Workers, Addr, Port, Report)

			if err != nil {
				fmt.Printf("Fatal error: could not listen to UDP (%v)", err)
			}
			wg.Done()

			chn <- true
		}()
	case "NFL": // NetFlow v5
		sNFL := &netflowlegacy.StateNFLegacy{
			Transport: &ProccessTransport{},
		}
		wg.Add(1)
		//Worker Oluştur
		go func() {
			err := UDPRoutine("NetFlowV5", sNFL.DecodeFlow, *Workers, Addr, Port, Report)
			if err != nil {
				fmt.Printf("Fatal error: could not listen to UDP (%v)", err)
			}
			wg.Done()
		}()
	case "IPFIX": // NetFlow/IPFIX
		sNF := &netflow.StateNetFlow{
			Transport: &ProccessTransport{},
		}
		wg.Add(1)
		go func() {
			err := UDPRoutine("NetFlow", sNF.DecodeFlow, *Workers, Addr, Port, Report)
			if err != nil {
				fmt.Printf("Fatal error: could not listen to UDP (%v)", err)
			}
			wg.Done()
		}()

	}
	// Her 15 saniyede FlowDatası VM ye gönder
	result := false
	fmt.Println("başladı")
	for {

		select {
		case result = <-chn:
			fmt.Println("cikiyoruz")
		case <-time.After(15 * time.Second):
			fmt.Println("Çalıştı")

			//Sıfırla flowDatas tmp at  sonra sıfırla

			//SouceIP, RemoteIP, Protocol
			q := From(flowDatas).OrderByDescending(
				func(i interface{}) interface{} {
					return i.(flowData).Bytes
				}).Take(5).Results()

			bolB, _ := ffjson.Marshal(q)
			fmt.Println(string(bolB))

			//os.Exit(1)
		}
		if result {
			break
		}
	}

	wg.Wait()
}

func UDPRoutine(name string, decodeFunc decoder.DecoderFunc, workers int, addr string, port int, sockReuse bool) error {
	/*ecb := DefaultErrorCallback{
		Logger: logger,
	}*/

	decoderParams := decoder.DecoderParams{
		DecoderFunc: decodeFunc,
		//ErrorCallback: ecb.Callback,
	}

	processor := decoder.CreateProcessor(workers, decoderParams, name)
	processor.Start()

	addrUDP := net.UDPAddr{
		IP:   net.ParseIP(addr),
		Port: port,
	}

	var udpconn *net.UDPConn
	var err error

	if sockReuse {
		pconn, err := reuseport.ListenPacket("udp", addrUDP.String())
		defer pconn.Close()
		if err != nil {
			return err
		}
		var ok bool
		udpconn, ok = pconn.(*net.UDPConn)
		if !ok {
			return err
		}
	} else {
		udpconn, err = net.ListenUDP("udp", &addrUDP)
		defer udpconn.Close()
		if err != nil {
			return err
		}
	}

	payload := make([]byte, 9000)

	for {
		size, pktAddr, _ := udpconn.ReadFromUDP(payload)
		payloadCut := make([]byte, size)
		copy(payloadCut, payload[0:size])

		baseMessage := BaseMessage{
			Src:     pktAddr.IP,
			Port:    pktAddr.Port,
			Payload: payloadCut,
		}
		processor.ProcessMessage(baseMessage)

	}
}

func protocolToString(Proto uint32) string {
	switch int(Proto) {
	case 17:
		return "UDP"
	case 6:
		return "TCP"
	case 1:
		return "ICMP"
	case 2:
		return "IGMP"
	case 8:
		return "EGP"
	}
	return fmt.Sprintf("UNK%d", int(Proto))
}
