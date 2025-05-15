# 🔍 IP & Port Scanner (TCP SYN Scan) – Go + Gopacket + Pcap

Bu proje, Go programlama dili ile geliştirilmiş, düşük seviyeli TCP SYN taraması gerçekleştiren bir port tarama aracıdır. Proje, **gopacket** ve **pcap** kütüphaneleri ile özel olarak oluşturulmuş TCP SYN paketlerini doğrudan hedef IP adresine gönderir ve alınan cevaba göre portun açık veya kapalı olduğunu belirler.

Bu yaklaşım klasik `connect()` temelli port tarayıcılarından farklıdır; daha çok nmap’in `-sS` seçeneğinde kullandığı **half-open scan** (yarı-açık tarama) tekniğine benzer şekilde çalışır.

---

## 🎯 Hedefler ve Kullanım Senaryosu

- Güvenlik araştırmacıları için basit ve etkili bir port denetleme aracı oluşturmak
- TCP bağlantı kurulmadan hedef sistemde port açığını test edebilmek
- Ağ seviyesi protokolleri daha iyi anlamak için pratik bir örnek sunmak
- Özellikle firewall veya IDS sistemlerinin tepki analizlerinde kullanılabilecek temel test aracı geliştirmek

---

## 🛠️ Kullanılan Teknolojiler ve Kütüphaneler

| Bileşen              | Açıklama                                                                 |
|----------------------|--------------------------------------------------------------------------|
| **Go**               | Yüksek performanslı, sistem seviyesi programlama için kullanılan dil     |
| **gopacket**         | Ethernet, IP ve TCP gibi protokol seviyelerinde özel paket oluşturma     |
| **pcap (libpcap)**   | Ağ arayüzünden doğrudan paket gönderme/alma işlemleri                    |
| **net**              | IP ve MAC adresi tanımlama işlemleri                                     |
| **time**             | Paket timeout süresi kontrolü                                            |

---

## 📦 Proje Yapısı

```bash
Ip_Port_Scan/
├── main.go            # Uygulamanın ana dosyası, tüm işlem burada yapılır
├── go.mod             # Go bağımlılık tanımları
├── go.sum             # Bağımlılık doğrulama dosyası
