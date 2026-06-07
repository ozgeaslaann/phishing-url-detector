# 🎣 Phishing URL Detector

Python tabanlı, hafif, hızlı ve güçlü bir Oltalama (Phishing) URL Tespit Aracı. Girilen URL'nin şüpheli olup olmadığını hem yerel analiz kurallarına göre hem de açık kaynaklı güncel tehdit veritabanlarına (OpenPhish ve URLhaus) göre analiz eder.

Hiçbir API anahtarı (API Key) veya ekstra kütüphane kurulumu **gerektirmez**, doğrudan Python'un dahili kütüphaneleriyle çalışır!

## 🚀 Özellikler

- **Hızlı ve Pratik:** Herhangi bir dış kütüphane (`pip install` vs.) gerektirmez. Kur-çalıştır mantığıyla tasarlanmıştır.
- **Gerçek Zamanlı Veritabanı Kontrolü:** İnternet üzerindeki güncel phishing veritabanlarından **~30.000 aktif zararlı URL'yi** anlık olarak RAM'e çeker ve saniyeler içinde analiz yapar.
- **Akıllı Önbellekleme (Caching):** Toplu URL analizlerinde (örneğin listeden okurken) veritabanını sadece ilk seferde indirir, sonrakilerde hafızadan hızla tarar.

## 🛡️ Analiz Edilen Kriterler

Uygulama iki farklı katmanda güvenlik analizi yapar:

### 1. Açık Kaynaklı Tehdit İstihbaratı (OSINT)
Aşağıdaki açık kaynaklı phishing ve malware listelerinden anlık tarama yapılarak doğrudan eşleşme aranır:
* **[OpenPhish](https://openphish.com):** Güncel oltalama veritabanı.
* **[URLhaus (Abuse.ch)](https://urlhaus.abuse.ch/):** Zararlı yazılım (malware) dağıtan aktif siteler veritabanı.

### 2. Yerel Algoritma Kontrolleri (Heuristics)
Eğer veritabanında bulunmazsa, URL'nin genel yapısı şüpheli mi diye şu metrikler incelenir:
* URL HTTPS protokolü kullanıyor mu?
* URL gereğinden fazla mı uzun? (Gizlenmiş parametre kontrolü)
* URL içinde `@` karakteri barındırıyor mu? (Kullanıcı adı/şifre gizleme taktikleri)
* Çok fazla alt alan adı (subdomain) tespiti için `.` sayı kontrolü.
* Çok fazla `-` (tire) kullanılmış mı?
* Domain yerine doğrudan **IP adresi** mi kullanılmış?
* URL içerisinde phishing şüphesi uyandıran kritik kelimeler var mı? (`login`, `verify`, `update`, `secure`, `account`, `password`, `bank`, `confirm` vs.)

## 🛠️ Kurulum ve Çalıştırma

Proje sadece Python standart kütüphanelerini kullanmaktadır. Herhangi bir bağımlılık kurulumuna gerek yoktur. 

Terminal veya komut satırınızı açıp proje dizinine gidin ve uygulamayı başlatın:

```bash
python main.py
```
*(Eğer Windows kullanıyorsanız ve üstteki komut çalışmazsa `py main.py` veya `python3 main.py` komutlarını deneyebilirsiniz.)*

## 💻 Kullanım Arayüzü

Program çalıştırıldığında sizi basit bir konsol menüsü karşılar:

```text
=== Basit Phishing URL Tespit Sistemi ===
1 - URL analiz et
2 - Örnek URL listesini analiz et
0 - Çıkış
```

- **Seçenek 1:** Sizden tek bir URL ister ve bu URL'i detaylıca analiz eder.
- **Seçenek 2:** Proje içerisinde bulunan `sample_urls.txt` isimli dosyadaki URL'leri sırasıyla okur ve toplu analiz yapar. (Eğer test etmek istediğiniz kendi URL listeniz varsa bu dosyanın içine satır satır ekleyebilirsiniz.)

## 📝 Örnek Çıktı

```text
[Bilgi] Açık kaynak phishing veritabanları (OpenPhish & URLhaus) yükleniyor...
[Bilgi] Toplam 30124 adet zararlı URL başarıyla hafızaya alındı!

Analiz edilen URL: http://secure-login-bank-update.com

Bulunan riskler:
- HTTPS kullanılmıyor
- URL içinde çok fazla tire var
- Şüpheli kelime bulundu: secure
- Şüpheli kelime bulundu: login
- Şüpheli kelime bulundu: bank
- Şüpheli kelime bulundu: update

Risk puanı: 6
Sonuç: YÜKSEK RİSK: Doğrulanmış veya Yüksek İhtimalle Phishing URL!
```

---
*Bu araç eğitim ve hızlı analiz amacıyla geliştirilmiştir. Yüzde yüz güvenlik garantisi vermez.*
