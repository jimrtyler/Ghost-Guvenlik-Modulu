# 👻 Ghost Güvenlik Modülü
**PowerShell Tabanlı Windows & Azure Güvenlik Sıkılaştırma Aracı**

> **Windows uç noktaları ve Azure ortamları için proaktif güvenlik sıkılaştırması.** Ghost, gereksiz hizmetleri ve protokolleri devre dışı bırakarak yaygın saldırı vektörlerini azaltmaya yardımcı olan PowerShell tabanlı sıkılaştırma işlevleri sağlar.

## ⚠️ Önemli Sorumluluk Reddi Beyanları

**TEST GEREKLİDİR**: Ghost'u her zaman önce üretim dışı ortamlarda test edin. Hizmetleri devre dışı bırakmak meşru iş işlevlerini etkileyebilir.

**GARANTİ YOK**: Ghost yaygın saldırı vektörlerini hedef alsa da, hiçbir güvenlik aracı tüm saldırıları önleyemez. Bu, kapsamlı bir güvenlik stratejisinin bir bileşenidir.

**OPERASYONEL ETKİ**: Bazı işlevler sistem işlevselliğini etkileyebilir. Dağıtımdan önce her ayarı dikkatli bir şekilde gözden geçirin.

**PROFESYONELDEĞERLENDİRME**: Üretim ortamları için, ayarların kuruluşunuzun ihtiyaçlarıyla uyumlu olduğundan emin olmak için güvenlik uzmanlarına danışın.

## 📊 Güvenlik Manzarası

Ransomware zararları **2025'te 57 milyar dolara** ulaştı ve araştırmalar birçok başarılı saldırının temel Windows hizmetlerini ve yanlış yapılandırmaları istismar ettiğini gösteriyor. Yaygın saldırı vektörleri şunları içerir:

- **Ransomware olaylarının %90'ı** RDP istismarını içerir
- **SMBv1 güvenlik açıkları** WannaCry ve NotPetya gibi saldırıları mümkün kıldı
- **Belge makroları** birincil malware dağıtım yöntemi olarak kalıyor
- **USB tabanlı saldırılar** hava boşluklu ağları hedeflemeye devam ediyor
- **PowerShell kötüye kullanımı** son yıllarda önemli ölçüde arttı

## 🛡️ Ghost Güvenlik İşlevleri

Ghost **16 Windows sıkılaştırma işlevi** artı **Azure güvenlik entegrasyonu** sağlar:

### Windows Uç Nokta Sıkılaştırması

| İşlev | Amaç | Dikkat Edilecekler |
|----------|---------|----------------|
| `Set-RDP` | Uzak Masaüstü erişimini yönetir | Uzaktan yönetimi etkileyebilir |
| `Set-SMBv1` | Eski SMB protokolünü kontrol eder | Çok eski sistemler için gerekli |
| `Set-AutoRun` | AutoPlay/AutoRun'ı kontrol eder | Kullanıcı rahatlığını etkileyebilir |
| `Set-USBStorage` | USB depolama cihazlarını kısıtlar | Meşru USB kullanımını etkileyebilir |
| `Set-Macros` | Office makro yürütmesini kontrol eder | Makro etkin belgeleri etkileyebilir |
| `Set-PSRemoting` | PowerShell uzaktan erişimini yönetir | Uzaktan yönetimi etkileyebilir |
| `Set-WinRM` | Windows Uzaktan Yönetimi'ni kontrol eder | Uzaktan yönetimi etkileyebilir |
| `Set-LLMNR` | Ad çözümleme protokolünü yönetir | Genellikle devre dışı bırakmak güvenlidir |
| `Set-NetBIOS` | TCP/IP üzerinden NetBIOS'u kontrol eder | Eski uygulamaları etkileyebilir |
| `Set-AdminShares` | Yönetici paylaşımlarını yönetir | Uzak dosya erişimini etkileyebilir |
| `Set-Telemetry` | Veri toplamayı kontrol eder | Tanılama yeteneklerini etkileyebilir |
| `Set-GuestAccount` | Misafir hesabını yönetir | Genellikle devre dışı bırakmak güvenlidir |
| `Set-ICMP` | Ping yanıtlarını kontrol eder | Ağ tanılamalarını etkileyebilir |
| `Set-RemoteAssistance` | Uzaktan Yardım'ı yönetir | Yardım masası operasyonlarını etkileyebilir |
| `Set-NetworkDiscovery` | Ağ keşfini kontrol eder | Ağ taramayı etkileyebilir |
| `Set-Firewall` | Windows Güvenlik Duvarı'nı yönetir | Ağ güvenliği için kritik |

### Azure Bulut Güvenliği

| İşlev | Amaç | Gereksinimler |
|----------|---------|--------------|
| `Set-AzureSecurityDefaults` | Temel Azure AD güvenliğini etkinleştirir | Microsoft Graph izinleri |
| `Set-AzureConditionalAccess` | Erişim politikalarını yapılandırır | Azure AD P1/P2 lisanslama |
| `Set-AzurePrivilegedUsers` | Ayrıcalıklı hesapları denetler | Global Admin izinleri |

### Kurumsal Dağıtım Seçenekleri

| Yöntem | Kullanım Durumu | Gereksinimler |
|--------|----------|--------------|
| **Doğrudan Yürütme** | Test, küçük ortamlar | Yerel yönetici hakları |
| **Grup İlkesi** | Etki alanı ortamları | Etki alanı yöneticisi, GP yönetimi |
| **Microsoft Intune** | Bulut yönetimli cihazlar | Intune lisanslama, Graph API |

## 🚀 Hızlı Başlangıç

### Güvenlik Değerlendirmesi
```powershell
# Ghost modülünü yükle
Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/main/Ghost.ps1' -OutFile .\Ghost.ps1
Get-Content .\Ghost.ps1
. .\Ghost.ps1

# Mevcut güvenlik duruşunu kontrol et
Get-Ghost
```

### Temel Sıkılaştırma (Önce Test Et)
```powershell
# Temel sıkılaştırma - önce laboratuvar ortamında test et
Set-Ghost -SMBv1 -AutoRun -Macros

# Değişiklikleri gözden geçir
Get-Ghost
```

### Kurumsal Dağıtım
```powershell
# Grup İlkesi dağıtımı (etki alanı ortamları)
Set-Ghost -SMBv1 -AutoRun -GroupPolicy

# Intune dağıtımı (bulut yönetimli cihazlar)
Set-Ghost -SMBv1 -RDP -USBStorage -Intune
```

## 📋 Kurulum Yöntemleri

### Seçenek 1: Doğrudan İndirme (Test)
```powershell
Invoke-WebRequest 'https://raw.githubusercontent.com/jimrtyler/Ghost/main/Ghost.ps1' -OutFile .\Ghost.ps1
Get-Content .\Ghost.ps1
. .\Ghost.ps1
```

### Seçenek 2: Modül Kurulumu
```powershell
# PowerShell Gallery'den kur (mevcut olduğunda)
Install-Module Ghost -Scope CurrentUser
Import-Module Ghost
```

### Seçenek 3: Kurumsal Dağıtım
```powershell
# Grup İlkesi dağıtımı için ağ konumuna kopyala
# Bulut dağıtımı için Intune PowerShell scriptlerini yapılandır
```

## 💼 Kullanım Durumu Örnekleri

### Küçük İşletme
```powershell
# Minimal etkiyle temel koruma
Set-Ghost -SMBv1 -AutoRun -Macros -ICMP
```

### Sağlık Ortamı
```powershell
# HIPAA odaklı sıkılaştırma
Set-Ghost -SMBv1 -RDP -USBStorage -AdminShares -Telemetry
```

### Finansal Hizmetler
```powershell
# Yüksek güvenlik yapılandırması
Set-Ghost -RDP -SMBv1 -AutoRun -USBStorage -Macros -PSRemoting -AdminShares
```

### Bulut-İlk Organizasyon
```powershell
# Intune yönetimli dağıtım
Connect-IntuneGhost -Interactive
Set-Ghost -SMBv1 -RDP -AutoRun -Macros -Intune
```

## 🔍 İşlev Detayları

### Temel Sıkılaştırma İşlevleri

#### Ağ Hizmetleri
- **RDP**: Uzak masaüstü erişimini bloklar veya port'u rastgele yapar
- **SMBv1**: Eski dosya paylaşım protokolünü devre dışı bırakır
- **ICMP**: Keşif için ping yanıtlarını önler
- **LLMNR/NetBIOS**: Eski ad çözümleme protokollerini bloklar

#### Uygulama Güvenliği
- **Makrolar**: Office uygulamalarında makro yürütmesini devre dışı bırakır
- **AutoRun**: Çıkarılabilir medyadan otomatik yürütmeyi önler

#### Uzaktan Yönetim
- **PSRemoting**: PowerShell uzak oturumlarını devre dışı bırakır
- **WinRM**: Windows Uzaktan Yönetimi'ni durdurur
- **Remote Assistance**: Uzaktan yardım bağlantılarını bloklar

#### Erişim Kontrolü
- **Admin Shares**: C$, ADMIN$ paylaşımlarını devre dışı bırakır
- **Guest Account**: Misafir hesap erişimini devre dışı bırakır
- **USB Storage**: USB cihaz kullanımını kısıtlar

### Azure Entegrasyonu
```powershell
# Azure kiracısına bağlan
Connect-AzureGhost -Interactive

# Güvenlik varsayılanlarını etkinleştir
Set-AzureSecurityDefaults -Enable

# Koşullu erişimi yapılandır
Set-AzureConditionalAccess -BlockLegacyAuth -RequireMFA

# Ayrıcalıklı kullanıcıları denetle
Set-AzurePrivilegedUsers -AuditOnly
```

### Intune Entegrasyonu (v2'de Yeni)
```powershell
# Intune'a bağlan
Connect-IntuneGhost -Interactive

# Intune ilkeleri ile dağıt
Set-IntuneGhost -Settings @{
    RDP = $true
    SMBv1 = $true
    USBStorage = $true
    Macros = $true
}
```

## ⚠️ Önemli Dikkat Edilecekler

### Test Gereksinimleri
- **Laboratuvar Ortamı**: Önce tüm ayarları izole ortamda test et
- **Aşamalı Dağıtım**: Sorunları tespit etmek için kademeli olarak genişlet
- **Geri Alma Planı**: Gerekirse değişiklikleri geri alabileceğinden emin ol
- **Dokümantasyon**: Ortamınız için hangi ayarların çalıştığını kaydet

### Potansiyel Etki
- **Kullanıcı Verimliliği**: Bazı ayarlar günlük iş akışlarını etkileyebilir
- **Eski Uygulamalar**: Eski sistemler belirli protokoller gerektirebilir
- **Uzaktan Erişim**: Meşru uzaktan yönetim üzerindeki etkiyi düşün
- **İş Süreçleri**: Ayarların kritik işlevleri bozmadığını doğrula

### Güvenlik Sınırlamaları
- **Derinlemesine Savunma**: Ghost güvenliğin bir katmanı, tam çözüm değil
- **Sürekli Yönetim**: Güvenlik sürekli izleme ve güncellemeler gerektirir
- **Kullanıcı Eğitimi**: Teknik kontroller güvenlik farkındalığı ile eşleştirilmeli
- **Tehdit Evrimi**: Yeni saldırı yöntemleri mevcut korumaları atlayabilir

## 🎯 Saldırı Senaryosu Örnekleri

Ghost yaygın saldırı vektörlerini hedef alsa da, spesifik önleme uygun uygulama ve teste bağlıdır:

### WannaCry Tarzı Saldırılar
- **Azaltma**: `Set-Ghost -SMBv1` savunmasız protokolü devre dışı bırakır
- **Dikkat**: Hiçbir eski sistemin SMBv1 gerektirmediğinden emin ol

### RDP Tabanlı Ransomware
- **Azaltma**: `Set-Ghost -RDP` uzak masaüstü erişimini bloklar
- **Dikkat**: Alternatif uzaktan erişim yöntemleri gerekebilir

### Belge Tabanlı Malware
- **Azaltma**: `Set-Ghost -Macros` makro yürütmesini devre dışı bırakır
- **Dikkat**: Meşru makro etkin belgeleri etkileyebilir

### USB Teslim Edilmiş Tehditler
- **Azaltma**: `Set-Ghost -USBStorage -AutoRun` USB işlevselliğini kısıtlar
- **Dikkat**: Meşru USB cihaz kullanımını etkileyebilir

## 🏢 Kurumsal Özellikler

### Grup İlkesi Desteği
```powershell
# Grup İlkesi kayıt defteri ile ayarları uygula
Set-Ghost -SMBv1 -RDP -AutoRun -GroupPolicy

# GP yenilenmesinden sonra ayarlar etki alanı genelinde uygulanır
gpupdate /force
```

### Microsoft Intune Entegrasyonu
```powershell
# Ghost ayarları için Intune ilkeleri oluştur
Set-IntuneGhost -Settings $GhostSettings -Interactive

# İlkeler yönetilen cihazlara otomatik olarak dağıtılır
```

### Uyumluluk Raporlama
```powershell
# Güvenlik değerlendirme raporu oluştur
Get-Ghost | Export-Csv -Path "GüvenlikDenetimi-$(Get-Date -Format 'yyyy-MM-dd').csv"

# Azure güvenlik duruşu raporu
Get-AzureGhost | Out-File "AzureGüvenlikRaporu.txt"
```

## 📚 En İyi Uygulamalar

### Dağıtım Öncesi
1. **Mevcut Durumu Belgele**: Değişikliklerden önce `Get-Ghost` çalıştır
2. **Kapsamlı Test Et**: Üretim dışı ortamda doğrula
3. **Geri Alma Planla**: Her ayarı nasıl geri alacağını bil
4. **Paydaş İncelemesi**: İş birimlerinin değişiklikleri onayladığından emin ol

### Dağıtım Sırasında
1. **Aşamalı Yaklaşım**: Önce pilot gruplara dağıt
2. **Etkiyi İzle**: Kullanıcı şikayetlerini veya sistem sorunlarını takip et
3. **Sorunları Belgele**: Gelecek referans için herhangi bir sorunu kaydet
4. **Değişiklikleri İletişim Kur**: Güvenlik iyileştirmelerini kullanıcılara bildir

### Dağıtım Sonrası
1. **Düzenli Değerlendirme**: Ayarları doğrulamak için periyodik `Get-Ghost` çalıştır
2. **Dokümantasyonu Güncelle**: Güvenlik yapılandırmalarını güncel tut
3. **Etkinliği Gözden Geçir**: Güvenlik olaylarını izle
4. **Sürekli İyileştirme**: Tehdit manzarasına göre ayarları düzenle

## 🔧 Sorun Giderme

### Yaygın Sorunlar
- **İzin Hataları**: Yükseltilmiş PowerShell oturumunu sağla
- **Hizmet Bağımlılıkları**: Bazı hizmetlerin bağımlılıkları olabilir
- **Uygulama Uyumluluğu**: İş uygulamalarıyla test et
- **Ağ Bağlantısı**: Uzaktan erişimin hala çalıştığını doğrula

### Kurtarma Seçenekleri
```powershell
# Gerekirse spesifik hizmetleri yeniden etkinleştir
Set-RDP -Enable
Set-SMBv1 -Enable
Set-AutoRun -Enable
Set-Macros -Enable
```

## 👨‍💻 Yazar Hakkında

**Jim Tyler** - PowerShell için Microsoft MVP
- **YouTube**: [@PowerShellEngineer](https://youtube.com/@PowerShellEngineer) (10.000+ abone)
- **Haber Bülteni**: [PowerShell.News](https://powershell.news) - Haftalık güvenlik istihbaratı
- **Yazar**: "PowerShell for Systems Engineers"
- **Deneyim**: PowerShell otomasyonu ve Windows güvenliğinde onlarca yıl

## 📄 Lisans & Sorumluluk Reddi

### MIT Lisansı
Ghost ücretsiz kullanım, değiştirme ve dağıtım için MIT Lisansı altında sağlanır.

### Güvenlik Sorumluluk Reddi
- **Garanti Yok**: Ghost herhangi bir garanti olmaksızın "olduğu gibi" sağlanır
- **Test Gerekli**: Her zaman önce üretim dışı ortamlarda test et
- **Profesyonel Rehberlik**: Üretim dağıtımları için güvenlik uzmanlarına danış
- **Operasyonel Etki**: Yazarlar herhangi bir operasyonel kesintiden sorumlu değildir
- **Kapsamlı Güvenlik**: Ghost tam güvenlik stratejisinin bir bileşenidir

### Destek
- **GitHub Issues**: [Hata bildir veya özellik talep et](https://github.com/jimrtyler/Ghost/issues)
- **Dokümantasyon**: Detaylı yardım için `Get-Help <function> -Full` kullan
- **Topluluk**: PowerShell ve güvenlik topluluk forumları

---

**🔒 Ghost ile güvenlik duruşunuzu güçlendirin - ama her zaman önce test edin.**

```powershell
# Varsayımlarla değil, değerlendirmeyle başla
Get-Ghost
```

**⭐ Ghost güvenlik duruşunuzu iyileştirmeye yardımcı oluyorsa bu repository'yi yıldızlayın!**