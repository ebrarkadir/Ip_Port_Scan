// package main

// import (
// 	"encoding/binary"
// 	"fmt"
// 	"log"
// 	"net"
// 	"time"
// )

// func main() {
// 	// Hedef IP adresi ve port numarası
// 	targetIP := "192.168.51.93"
// 	targetPort := 8080

// 	// Kaynak IP adresi ve port numarası
// 	srcIP := net.ParseIP("192.168.51.208") // Kendi cihazınızın IP adresi
// 	srcPort := 17664                       // Gönderen port

// 	// TCP SYN paketi oluşturma
// 	ipHeader := createIPv4Header(srcIP, net.ParseIP(targetIP))
// 	tcpHeader := createTCPHeader(srcPort, targetPort)

// 	// TCP checksum hesaplama
// 	pseudoHeader := createPseudoHeader(srcIP, net.ParseIP(targetIP), len(tcpHeader))
// 	checksum := tcpChecksum(pseudoHeader, tcpHeader)
// 	binary.BigEndian.PutUint16(tcpHeader[16:], checksum)

// 	// IP ve TCP headerlarını birleştirme
// 	packet := append(ipHeader, tcpHeader...)

// 	// RAW soket oluşturma
// 	conn, err := net.Dial("ip4:tcp", targetIP)
// 	if err != nil {
// 		log.Fatal("RAW soket oluşturulurken hata oluştu:", err)
// 	}
// 	defer conn.Close()

// 	// Paketi gönderme
// 	if _, err := conn.Write(packet); err != nil {
// 		log.Fatal("Paket gönderilirken hata oluştu:", err)
// 	}

// 	fmt.Println("TCP SYN isteği gönderildi.")

// 	// SYN-ACK yanıtını belirli bir süre bekleyerek dinleme
// 	buf := make([]byte, 4096)
// 	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
// 	n, err := conn.Read(buf)
// 	if err != nil {
// 		if e, ok := err.(net.Error); ok && e.Timeout() {
// 			fmt.Println("Port kapalı.")
// 		} else {
// 			log.Fatal("Yanıt alınırken hata oluştu:", err)
// 		}
// 		return
// 	}

// 	// SYN-ACK yanıtını kontrol etme
// 	if isSynAck(buf[:n]) {
// 		fmt.Println("Port açık!")
// 	} else {
// 		fmt.Println("Port kapalı.")
// 	}
// }

// func createIPv4Header(srcIP, dstIP net.IP) []byte {
// 	ipHeader := make([]byte, 20)
// 	ipHeader[0] = 0x45                           // 4 yüksek nibble:ip sürümü, 5 düşük nibble:IP header uzunluğu
// 	ipHeader[1] = 0x00                           // hizmet türü
// 	binary.BigEndian.PutUint16(ipHeader[2:], 40) //Ip + tcp
// 	binary.BigEndian.PutUint16(ipHeader[4:], 0)  // Identification
// 	ipHeader[6] = 0x40                           // Flag ve fragment offset
// 	ipHeader[8] = 64                             // TTL (Time to Live)
// 	ipHeader[9] = 6                              // Protocol (TCP)
// 	copy(ipHeader[12:16], srcIP.To4())           // Source IP
// 	copy(ipHeader[16:20], dstIP.To4())           // Destination IP
// 	checksum := checksum(ipHeader)
// 	binary.BigEndian.PutUint16(ipHeader[10:], checksum) // Header Checksum
// 	return ipHeader
// }

// func createTCPHeader(srcPort, dstPort int) []byte {
// 	tcpHeader := make([]byte, 20)
// 	binary.BigEndian.PutUint16(tcpHeader[0:], uint16(srcPort)) // Source Port
// 	binary.BigEndian.PutUint16(tcpHeader[2:], uint16(dstPort)) // Destination Port
// 	binary.BigEndian.PutUint32(tcpHeader[4:], 0)               // Sequence
// 	binary.BigEndian.PutUint32(tcpHeader[8:], 0)               // Acknowledgment
// 	tcpHeader[12] = 0x50                                       // Data Offset (5), Reserved
// 	tcpHeader[13] = 0x02                                       // Flag (SYN)
// 	binary.BigEndian.PutUint16(tcpHeader[14:], 14600)          // Window değeri
// 	return tcpHeader
// }

// func createPseudoHeader(srcIP, dstIP net.IP, tcpLength int) []byte {
// 	pseudoHeader := make([]byte, 12)
// 	copy(pseudoHeader[0:4], srcIP.To4())                             // Source IP
// 	copy(pseudoHeader[4:8], dstIP.To4())                             // Destination IP
// 	pseudoHeader[9] = 6                                              // Protocol (TCP)
// 	binary.BigEndian.PutUint16(pseudoHeader[10:], uint16(tcpLength)) // TCP uzunluğu
// 	return pseudoHeader
// }

// func tcpChecksum(pseudoHeader, tcpHeader []byte) uint16 {
// 	data := append(pseudoHeader, tcpHeader...)
// 	return checksum(data)
// }

// func checksum(data []byte) uint16 {
// 	var sum uint32
// 	for i := 0; i < len(data)-1; i += 2 {
// 		sum += uint32(binary.BigEndian.Uint16(data[i:]))
// 	}
// 	if len(data)%2 == 1 {
// 		sum += uint32(data[len(data)-1]) << 8
// 	}
// 	sum = (sum >> 16) + (sum & 0xFFFF)
// 	sum += sum >> 16
// 	return uint16(^sum)
// }

// func isSynAck(packet []byte) bool {
// 	if len(packet) < 40 {
// 		return false
// 	}
// 	ipHeader := packet[:20]
// 	tcpHeader := packet[20:40]
// 	if ipHeader[9] != 6 { // TCP
// 		return false
// 	}
// 	flags := tcpHeader[13]
// 	return flags&0x12 == 0x12 // SYN and ACK
// }


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

	// Cihazı paket yakalama için aç
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Bu sefer bazı bilgileri dolduralım
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

	// Paketi serileştir
	buffer = gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, SerializationOptions,
		ethernetLayer,
		ipLayer,
		tcpLayer,
	)
	if err != nil {
		log.Fatal(err)
	}

	// Paketi gönder
	outgoingPacket := buffer.Bytes()
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal(err)
	}

	// Yanıtı yakala
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
