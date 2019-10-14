package netflowlegacy

import (
	"bytes"
	"fmt"

	"time"
	"github.com/hasnhasan/vm"
	"github.com/hasnhasan/vm/decoders/utils"
	flowmessage "github.com/hasnhasan/vm/pb"
	"github.com/hasnhasan/vm/producer"
)

type ErrorVersion struct {
	version uint16
}

func NewErrorVersion(version uint16) *ErrorVersion {
	return &ErrorVersion{
		version: version,
	}
}

func (e *ErrorVersion) Error() string {
	return fmt.Sprintf("Unknown NetFlow version %v (only decodes v5)", e.version)
}

func DecodeMessage(payload *bytes.Buffer) (interface{}, error) {
	var version uint16
	utils.BinaryDecoder(payload, &version)
	packet := PacketNetFlowV5{}
	if version == 5 {
		packet.Version = version

		utils.BinaryDecoder(payload,
			&(packet.Count),
			&(packet.SysUptime),
			&(packet.UnixSecs),
			&(packet.UnixNSecs),
			&(packet.FlowSequence),
			&(packet.EngineType),
			&(packet.EngineId),
			&(packet.SamplingInterval),
		)

		packet.Records = make([]RecordsNetFlowV5, int(packet.Count))
		for i := 0; i < int(packet.Count) && payload.Len() >= 48; i++ {
			record := RecordsNetFlowV5{}
			utils.BinaryDecoder(payload, &record)
			packet.Records[i] = record
		}

		return packet, nil
	} else {
		return nil, NewErrorVersion(version)
	}
}

type StateNFLegacy struct {
	Transport vm.Transport
}

func (s *StateNFLegacy) DecodeFlow(msg interface{}) error {
	pkt := msg.(vm.BaseMessage)
	buf := bytes.NewBuffer(pkt.Payload)

	samplerAddress := pkt.Src
	if samplerAddress.To4() != nil {
		samplerAddress = samplerAddress.To4()
	}

	msgDec, err := DecodeMessage(buf)

	if err != nil {
		return err
	}

	var flowMessageSet []*flowmessage.FlowMessage
	flowMessageSet, err = producer.ProcessMessageNetFlowLegacy(msgDec)

	for _, fmsg := range flowMessageSet {
		fmsg.TimeReceived = uint64(time.Now().UTC().Unix())
		fmsg.SamplerAddress = samplerAddress
	}

	if s.Transport != nil {
		s.Transport.Publish(flowMessageSet)
	}

	return nil
}
