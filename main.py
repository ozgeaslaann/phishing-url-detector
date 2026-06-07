import re
import urllib.request
from urllib.parse import urlparse


SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "update",
    "secure",
    "account",
    "password",
    "bank",
    "confirm",
]


# Açık kaynaklı güncel phishing listeleri için önbellek
PHISHING_URLS = set()
DATABASES_LOADED = False


def load_phishing_databases():
    global DATABASES_LOADED
    if not DATABASES_LOADED:
        try:
            print("[Bilgi] Açık kaynak phishing veritabanları (OpenPhish & URLhaus) yükleniyor...")
            
            # OpenPhish
            req1 = urllib.request.Request("https://openphish.com/feed.txt", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req1, timeout=7) as response:
                for line in response.read().decode('utf-8').splitlines():
                    if line.strip():
                        PHISHING_URLS.add(line.strip())
            
            # URLhaus
            req2 = urllib.request.Request("https://urlhaus.abuse.ch/downloads/text_online/", headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req2, timeout=7) as response:
                for line in response.read().decode('utf-8').splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        PHISHING_URLS.add(line)
                        
            DATABASES_LOADED = True
            print(f"[Bilgi] Toplam {len(PHISHING_URLS)} adet zararlı URL başarıyla hafızaya alındı!")
        except Exception:
            print("[Uyarı] İnternet veritabanlarına tam erişim sağlanamadı. Sadece yerel analiz yapılacak.")
            DATABASES_LOADED = True  # Hata olsa da tekrar tekrar denemesin
            
    return PHISHING_URLS


def check_with_databases(url):
    db = load_phishing_databases()
    return url in db


def analyze_url(url):
    risks = []
    score = 0

    normalized_url = url.strip().lower()
    parsed_url = urlparse(normalized_url)
    domain = parsed_url.netloc

    if not normalized_url.startswith("https://"):
        risks.append("HTTPS kullanılmıyor")
        score += 1

    if len(normalized_url) > 75:
        risks.append("URL uzunluğu fazla")
        score += 1

    if "@" in normalized_url:
        risks.append("URL içinde @ karakteri var")
        score += 2

    if normalized_url.count(".") > 4:
        risks.append("URL içinde çok fazla nokta var")
        score += 1

    if normalized_url.count("-") > 2:
        risks.append("URL içinde çok fazla tire var")
        score += 1

    if is_ip_address(domain):
        risks.append("Domain yerine IP adresi kullanılmış")
        score += 2

    for word in SUSPICIOUS_WORDS:
        if word in normalized_url:
            risks.append("Şüpheli kelime bulundu: " + word)
            score += 1

    # İnternet Üzerinden Veritabanı Kontrolleri
    if check_with_databases(url):
        risks.append("URL bilinen güncel phishing/zararlı yazılım veritabanlarında tespit edildi!")
        score += 5

    result = "Güvenli görünüyor"
    if score >= 5:
        result = "YÜKSEK RİSK: Doğrulanmış veya Yüksek İhtimalle Phishing URL!"
    elif score >= 3:
        result = "Şüpheli URL olabilir"

    return {
        "url": url,
        "score": score,
        "result": result,
        "risks": risks,
    }


def is_ip_address(domain):
    domain_without_port = domain.split(":")[0]
    pattern = r"^\d{1,3}(\.\d{1,3}){3}$"
    return re.match(pattern, domain_without_port) is not None


def print_analysis(analysis):
    print("\nAnaliz edilen URL:", analysis["url"])
    print("\nBulunan riskler:")

    if len(analysis["risks"]) == 0:
        print("- Belirgin bir risk bulunmadı")
    else:
        for risk in analysis["risks"]:
            print("-", risk)

    print("\nRisk puanı:", analysis["score"])
    print("Sonuç:", analysis["result"])


def analyze_manual_url():
    url = input("Analiz etmek istediğiniz URL'yi girin: ")
    analysis = analyze_url(url)
    print_analysis(analysis)


def analyze_sample_urls():
    try:
        with open("sample_urls.txt", "r", encoding="utf-8") as file:
            urls = file.readlines()
    except FileNotFoundError:
        print("sample_urls.txt dosyası bulunamadı.")
        return

    for url in urls:
        cleaned_url = url.strip()
        if cleaned_url:
            analysis = analyze_url(cleaned_url)
            print_analysis(analysis)
            print("-" * 50)


def show_menu():
    while True:
        print("\n=== Basit Phishing URL Tespit Sistemi ===")
        print("1 - URL analiz et")
        print("2 - Örnek URL listesini analiz et")
        print("0 - Çıkış")

        choice = input("Seçim: ")

        if choice == "1":
            analyze_manual_url()
        elif choice == "2":
            analyze_sample_urls()
        elif choice == "0":
            print("Program kapatıldı.")
            break
        else:
            print("Geçersiz seçim.")


if __name__ == "__main__":
    show_menu()
