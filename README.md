# Discord Erişim Aracı

Bu arayüz GoodbyeDPI Turkey paketini kullanır ve terminal yerine yerine otomatik, kullanıcı girişi gerektirmeyen bir kurulum sağlayan arayüz sunar.

## Neler yapar
- `goodbyedpi-0.2.3rc3-turkey` klasörünü `C:\Program Files\Discord\` içine kopyalar.
- `GoodbyeDPI` servisini kurar ve otomatik test yapar.
- Çalışan yöntemi bulana kadar farklı DNS ve bayrak kombinasyonlarını dener.
- Günlüğü `%LOCALAPPDATA%\DiscordErisim\discord_erisimi.log` dosyasına yazar.

## Otomatik test yöntemi
Her denemeden sonra Discord bağlantısını HTTPS ile test eder.
Test başarısız olursa bir sonraki seçeneğe geçer.

## DNS seçenekleri
Yandex, Cloudflare, Google, Quad9, OpenDNS, AdGuard ve ek filtreli seçenekler dahildir.

## Kaldırma
**Kaldır** düğmesini kullanın veya şu komutu çalıştırın:
```
DiscordErisim.exe --uninstall
```
Uygulama yalnızca servisleri kaldırır, dosyaları silmez.

## Build
Çalıştırın:
```
.\build.ps1
```
Çıktı `dist\DiscordErisim.exe` olacaktır.

## CLI
- `--install` (opsiyonel DNS seçimi için: `--auto`, `--yandex`, `--cloudflare`, `--google`, `--quad9`, `--opendns`, `--adguard`, `--adguard_nofilter`, `--adguard_family`, `--cloudflare_malware`, `--cloudflare_family`)
- `--uninstall`
- `--test`
