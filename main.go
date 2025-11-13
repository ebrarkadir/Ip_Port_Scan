package main

import (
	"fmt"
	"log"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	var (
		device      string = "wlan0"
		snapshotLen int32  = 1024
		promiscuous bool   = false
		err         error
		timeout     time.Duration = 10 * time.Second
		handle      *pcap.Handle
		buffer      gopacket.SerializeBuffer
	)

	var SerializationOptions = gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}

	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	ethernetLayer := &layers.Ethernet{
		SrcMAC:       net.HardwareAddr{0x84, 0x3e, 0x1d, 0x29, 0x2e, 0x9a}, // Kendi cihazınızın MAC adresi
		DstMAC:       net.HardwareAddr{0x68, 0xca, 0xc4, 0x8d, 0xc6, 0x14}, // Hedef cihazın MAC adresi
		EthernetType: layers.EthernetTypeIPv4,
	}
	
	ipLayer := &layers.IPv4{
		SrcIP:    net.IP{192, 168, 51, 208},
		DstIP:    net.IP{192, 168, 51, 93},
		Version:  4,
		TTL:      64,
		Protocol: layers.IPProtocolTCP,
	}
	tcpLayer := &layers.TCP{
		SrcPort: layers.TCPPort(4321),
		DstPort: layers.TCPPort(8888),
		SYN:     true,
	}
	tcpLayer.SetNetworkLayerForChecksum(ipLayer)

	buffer = gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, SerializationOptions,
		ethernetLayer,
		ipLayer,
		tcpLayer,
	)
	if err != nil {
		log.Fatal(err)
	}

	outgoingPacket := buffer.Bytes()
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	 for packet := range packetSource.Packets() {
	 	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
	 		tcp, _ := tcpLayer.(*layers.TCP)
	 		if tcp.SYN && tcp.ACK {
	 			fmt.Println("Port açık")
	 			break
	 		} else if tcp.RST {
	 			fmt.Println("Port kapalı")
	 			break
	 		}
	 	}
	 }
}
