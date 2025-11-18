# 🔐 Autoryzacja XAdES w KSeF – Skrypt PHP

### z wykorzystaniem certyfikatu autoryzacyjnego generowanego w systemie KSeF

Skrypt umożliwia przeprowadzenie autoryzacji XAdES w Krajowym Systemie e-Faktur (KSeF) z użyciem **certyfikatu autoryzacyjnego**, który należy wygenerować w wybranym środowisku KSeF (TEST, DEMO lub PROD).

Podpis XAdES jest tworzony w **czystym PHP**, bez zewnętrznych bibliotek.
Skrypt działa zarówno w CLI, jak i w przeglądarce.

---

## 📥 Pobieranie / instalacja

### 1. Klonowanie z GitHuba (zalecane)

```bash
git clone https://github.com/rgzyl/KSeF-PHP-Autoryzacja-XAdES-i-pobieranie-tokenu-API-v2-.git
cd KSeF-PHP-Autoryzacja-XAdES-i-pobieranie-tokenu-API-v2-
```

### 2. Pobranie ZIP z GitHuba

1. Wejdź:
   [https://github.com/rgzyl/KSeF-PHP-Autoryzacja-XAdES-i-pobieranie-tokenu-API-v2-](https://github.com/rgzyl/KSeF-PHP-Autoryzacja-XAdES-i-pobieranie-tokenu-API-v2-)
2. Kliknij zielony przycisk **Code**.
3. Wybierz **Download ZIP**.
4. Wypakuj paczkę na serwerze lub lokalnie.

---

## 🧩 Funkcjonalność

* pobranie `challenge` z KSeF
* zbudowanie struktury XML `AuthTokenRequest`
* kanonizacja XML (Exclusive C14N)
* podpis ECDSA SHA256 (DER → RAW)
* wysłanie podpisanego XML do `/api/v2/auth/xades-signature`
* odebranie `authenticationToken`

---

## ⚙ Wymagania

* PHP **7.4+**
* Włączone rozszerzenia:

  * `openssl`, `curl`, `dom`, `xmlwriter`, `hash`
* Certyfikaty wygenerowane **w systemie KSeF**:

  * `cert.crt`
  * `cert.key`
  * `pass.txt`
* Dostęp do API KSeF:

  * TEST: `https://test-ksef.mf.gov.pl`
  * DEMO: `https://demo-ksef.mf.gov.pl`
  * PROD: `https://ksef.mf.gov.pl`

---

## 📂 Konfiguracja

### 1. Ustaw NIP:

```php
define('NIP', '1234567890');
```

### 2. Wybierz środowisko:

```php
define('KSEF_BASE', 'https://test-ksef.mf.gov.pl');
// lub: https://demo-ksef.mf.gov.pl
// lub: https://ksef.mf.gov.pl
```

### 3. Wgraj certyfikaty z KSeF:

```
cert.crt
cert.key
pass.txt
```

Skrypt automatycznie pobierze `cacert.pem`, jeśli go nie ma.

---

## ▶️ Uruchamianie

### CLI

```bash
php ksef_xades.php
```

Wynik:

```text
TOKEN=...
VALID_UNTIL=...
```

### Przeglądarka

Otwórz:

```
https://twoja-domena/ksef_xades.php
```

---

## 🧪 Debug

Skrypt generuje pomocnicze pliki:

* `debug_before_sign.xml`
* `debug_signedprops_canon.txt`
* `debug_final_signed.xml`

---

## ✔ Środowiska KSeF (skrótowo)

| Środowisko | URL                                                        | Dane        |
| ---------- | ---------------------------------------------------------- | ----------- |
| **TEST**   | [https://test-ksef.mf.gov.pl](https://test-ksef.mf.gov.pl) | fikcyjne    |
| **DEMO**   | [https://demo-ksef.mf.gov.pl](https://demo-ksef.mf.gov.pl) | prawdziwe   |
| **PROD**   | [https://ksef.mf.gov.pl](https://ksef.mf.gov.pl)           | produkcyjne |

Certyfikaty muszą pochodzić **z tego samego środowiska**, które ustawione jest w `KSEF_BASE`.
