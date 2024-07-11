package main

import (
    "encoding/binary"
    "fmt"
    "log"
    "net"
    "time"
)

func main() {
    // Hedef IP adresi ve port numarası
    targetIP := "192.168.51.93"
    targetPort := 5000

    // Kaynak IP adresi ve port numarası
    srcIP := net.ParseIP("192.168.51.208") // Kendi cihazınızın IP adresi
    srcPort := 8080

    // TCP SYN paketi oluşturma
    ipHeader := createIPv4Header(srcIP, net.ParseIP(targetIP))
    tcpHeader := createTCPHeader(srcPort, targetPort)

    // TCP checksum hesaplama
    pseudoHeader := createPseudoHeader(srcIP, net.ParseIP(targetIP), len(tcpHeader))
    checksum := tcpChecksum(pseudoHeader, tcpHeader)
    binary.BigEndian.PutUint16(tcpHeader[16:], checksum)

    // IP ve TCP headerlarını birleştirme
    packet := append(ipHeader, tcpHeader...)

    // RAW soket oluşturma
    conn, err := net.Dial("ip4:tcp", targetIP)
    if err != nil {
        log.Fatal("RAW soket oluşturulurken hata oluştu:", err)
    }
    defer conn.Close()

    // Paketi gönderme
    if _, err := conn.Write(packet); err != nil {
        log.Fatal("Paket gönderilirken hata oluştu:", err)
    }

    fmt.Println("TCP SYN isteği başarıyla gönderildi.")

    // SYN-ACK yanıtını belirli bir süre bekleyerek dinleme
    buf := make([]byte, 4096)
    conn.SetReadDeadline(time.Now().Add(5 * time.Second))
    n, err := conn.Read(buf)
    if err != nil {
        if e, ok := err.(net.Error); ok && e.Timeout() {
            fmt.Println("Port kapalı.")
        } else {
            log.Fatal("Yanıt alınırken hata oluştu:", err)
        }
        return
    }

    // SYN-ACK yanıtını kontrol etme
    if isSynAck(buf[:n]) {
        fmt.Println("Port açık!")
    } else {
        fmt.Println("Port kapalı.")
    }
}

func createIPv4Header(srcIP, dstIP net.IP) []byte {
    ipHeader := make([]byte, 20)
    ipHeader[0] = 0x45 //ip headerının ilk byte ı (4 yüksek nibble:ip sürüm, 5 düşük nibble:ip başlığı uzunluğu 5*4=20 byte)
    ipHeader[1] = 0x00 //hizmet türü 
    binary.BigEndian.PutUint16(ipHeader[2:], 40) // IP + TCP header length
    binary.BigEndian.PutUint16(ipHeader[4:], 0)// identification
    ipHeader[6] = 0x40 // flag ve fragment offset. 0x40 dont fragment demek
    ipHeader[7] = 0x00 // fragment offset i 0 olarak ayarlar
    ipHeader[8] = 64 // TTL
    ipHeader[9] = 6 // TCP protokol numarası
    copy(ipHeader[12:16], srcIP.To4()) //kaynak ip yi header yerlerleştirme 
    copy(ipHeader[16:20], dstIP.To4()) //hedef ip yi header yerleştirme
    checksum := checksum(ipHeader)
    binary.BigEndian.PutUint16(ipHeader[10:], checksum)
    return ipHeader
}

func createTCPHeader(srcPort, dstPort int) []byte {
    tcpHeader := make([]byte, 20)
    binary.BigEndian.PutUint16(tcpHeader[0:], uint16(srcPort))//kaynap port numarasını headera yerleştirme
    binary.BigEndian.PutUint16(tcpHeader[2:], uint16(dstPort))//hedef port numarasını headera yerleştirme
    binary.BigEndian.PutUint32(tcpHeader[4:], 0)//sequence 
    binary.BigEndian.PutUint32(tcpHeader[8:], 0)//acknowledgement
    tcpHeader[12] = 0x50//data offset ve reserved alanı : data offest 5(20 byte), geri kalan bitler 0
    tcpHeader[13] = 0x02 // SYN flagı alanını ayarlar 0x02
    binary.BigEndian.PutUint16(tcpHeader[14:], 14600)//window değerini ayarlar
    return tcpHeader
}

func createPseudoHeader(srcIP, dstIP net.IP, tcpLength int) []byte {
    pseudoHeader := make([]byte, 12)
    copy(pseudoHeader[0:4], srcIP.To4())//kaynak ip yi pseudo headera atar 
    copy(pseudoHeader[4:8], dstIP.To4())//hedef ip yi pseudo headera atar
    pseudoHeader[8] = 0
    pseudoHeader[9] = 6 // TCP protokol numarası
    binary.BigEndian.PutUint16(pseudoHeader[10:], uint16(tcpLength))//TCP headerın uzunluğunu yazar
    return pseudoHeader
}

func tcpChecksum(pseudoHeader, tcpHeader []byte) uint16 {
    return checksum(append(pseudoHeader, tcpHeader...))
}

func checksum(data []byte) uint16 {
    sum := uint32(0)
    for i := 0; i < len(data)-1; i += 2 {
        sum += uint32(binary.BigEndian.Uint16(data[i:]))
    }
    if len(data)%2 == 1 {
        sum += uint32(data[len(data)-1]) << 8
    }
    sum = (sum >> 16) + (sum & 0xffff)
    sum += sum >> 16
    return uint16(^sum)
}

func isSynAck(packet []byte) bool {
    if len(packet) < 40 {
        return false
    }
    ipHeader := packet[:20]
    tcpHeader := packet[20:40]
    if ipHeader[9] != 6 { // TCP protokol numarası
        return false
    }
    flags := tcpHeader[13]
    return flags&0x12 == 0x12 // SYN ve ACK bayrakları set edilmiş
}
