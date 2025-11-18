<?php
/**
 * Skrypt do autoryzacji XAdES w systemie KSeF
 */

// ============================================
// TRYB URUCHOMIENIA (CLI vs PRZEGLĄDARKA)
// ============================================

$isCli = (php_sapi_name() === 'cli');

if (!$isCli) {
    header('Content-Type: text/html; charset=utf-8');
}

// ============================================
// KONFIGURACJA
// ============================================

define('NIP', '1234567890'); 

define('CERT_PATH', __DIR__ . '/cert.crt');
define('KEY_PATH', __DIR__ . '/cert.key');
define('PASS_PATH', __DIR__ . '/pass.txt');
define('CACERT_PATH', __DIR__ . '/cacert.pem'); 

define('KSEF_BASE', 'https://ksef-demo.mf.gov.pl');
define('URL_CHALLENGE', KSEF_BASE . '/api/v2/auth/challenge');
define('URL_XADES', KSEF_BASE . '/api/v2/auth/xades-signature?verifyCertificateChain=false');

// ============================================
// FUNKCJE POMOCNICZE
// ============================================

function logStep($message) {
    global $isCli;

    if ($isCli) {
        echo $message . PHP_EOL;
    } else {
        echo htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8') . "<br>\n";
    }
    flush();
}

function exitWithError($message) {
    global $isCli;

    if ($isCli) {
        fwrite(STDERR, "BŁĄD: " . $message . PHP_EOL);
        exit(1);
    } else {
        http_response_code(500);
        echo "<strong>BŁĄD:</strong> " . htmlspecialchars($message, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        exit;
    }
}

function ensureFile($path, $description) {
    if (!file_exists($path)) {
        exitWithError("Brak pliku $description: $path");
    }
}

function preChecks() {
    $required = ['openssl', 'curl', 'dom', 'xmlwriter', 'hash'];
    foreach ($required as $ext) {
        if (!extension_loaded($ext)) {
            exitWithError("Wymagane rozszerzenie PHP: $ext");
        }
    }
    
    ensureFile(CERT_PATH, 'certyfikatu');
    ensureFile(KEY_PATH, 'klucza prywatnego');
    ensureFile(PASS_PATH, 'hasła');
    
    if (!file_exists(CACERT_PATH)) {
        logStep('Pobieram cacert.pem...');
        downloadCACert();
    }
}

function downloadCACert() {
    $url = 'https://curl.se/ca/cacert.pem';
    $ch = curl_init($url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
    
    $content = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    curl_close($ch);
    
    if ($httpCode !== 200 || !$content) {
        exitWithError("Nie można pobrać cacert.pem z $url");
    }
    
    file_put_contents(CACERT_PATH, $content);
    logStep('Zapisano cacert.pem');
}

// ============================================
// WCZYTANIE CERTYFIKATU I WALIDACJA
// ============================================

function loadCertificate() {
    $certContent = file_get_contents(CERT_PATH);
    $cert = openssl_x509_read($certContent);
    
    if (!$cert) {
        exitWithError("Nie można wczytać certyfikatu: " . openssl_error_string());
    }
    
    return $cert;
}

function loadPrivateKey() {
    $password = trim(file_get_contents(PASS_PATH));
    $keyContent = file_get_contents(KEY_PATH);
    
    $privateKey = openssl_pkey_get_private($keyContent, $password ?: null);
    
    if (!$privateKey) {
        exitWithError("Nie można wczytać klucza prywatnego: " . openssl_error_string());
    }
    
    return $privateKey;
}

function validateKeyAndCert($cert, $privateKey) {
    if (!openssl_x509_check_private_key($cert, $privateKey)) {
        exitWithError("Klucz prywatny nie pasuje do certyfikatu");
    }
}

// ============================================
// DANE CERTYFIKATU
// ============================================

function getCertDigestB64($cert) {
    openssl_x509_export($cert, $certPem);
    $certDer = base64_decode(preg_replace('/-----[^-]+-----/', '', $certPem));
    return base64_encode(hash('sha256', $certDer, true));
}

function getCertIssuerName($cert) {
    $certInfo = openssl_x509_parse($cert);
    $issuer = $certInfo['issuer'];
    
    $parts = [];
    $order = ['CN', 'OU', 'O', 'L', 'ST', 'C'];
    
    foreach ($order as $key) {
        if (isset($issuer[$key])) {
            $value = is_array($issuer[$key]) ? $issuer[$key][0] : $issuer[$key];
            $parts[] = "$key=$value";
        }
    }
    
    return implode(',', $parts);
}

function getCertSerialDec($cert) {
    $certInfo = openssl_x509_parse($cert);

    if (isset($certInfo['serialNumber'])) {
        return (string)$certInfo['serialNumber'];
    }

    if (isset($certInfo['serialNumberHex']) && ctype_xdigit($certInfo['serialNumberHex'])) {
        return base_convert($certInfo['serialNumberHex'], 16, 10);
    }

    exitWithError("Brak numeru seryjnego certyfikatu");
}

function getCertBase64Body() {
    $certContent = file_get_contents(CERT_PATH);
    preg_match('/-----BEGIN CERTIFICATE-----(.+)-----END CERTIFICATE-----/s', $certContent, $matches);
    return trim($matches[1]);
}

// ============================================
// POBRANIE CHALLENGE
// ============================================

function fetchChallenge() {
    logStep('[1/4] Pobieram challenge...');
    
    $payload = json_encode([
        'contextIdentifier' => [
            'nip' => NIP
        ]
    ]);
    
    $ch = curl_init(URL_CHALLENGE);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/json',
        'Content-Length: ' . strlen($payload)
    ]);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_CAINFO, CACERT_PATH);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
    if (curl_errno($ch)) {
        $error = curl_error($ch);
        curl_close($ch);
        exitWithError("CURL error: $error");
    }
    
    curl_close($ch);
    
    if ($httpCode !== 200) {
        exitWithError("HTTP $httpCode podczas pobierania challenge:\n$response");
    }
    
    $data = json_decode($response, true);
    $challenge = $data['challenge'] ?? null;
    
    if (!$challenge) {
        exitWithError("Nie udało się pobrać challenge. Odpowiedź:\n$response");
    }
    
    logStep("CHALLENGE=$challenge");
    return $challenge;
}

// ============================================
// BUDOWA XML
// ============================================

function buildAuthXML($challenge, $cert) {
    logStep('[2/4] Przygotowuję dane do XAdES...');
    
    $certDigest = getCertDigestB64($cert);
    $issuer = getCertIssuerName($cert);
    $serialDec = getCertSerialDec($cert);
    $signingTime = gmdate('Y-m-d\TH:i:s\Z');
    $certB64Body = getCertBase64Body();
    
    $xml = new DOMDocument('1.0', 'UTF-8');
    $xml->formatOutput = false;
    $xml->preserveWhiteSpace = false;
    
    $root = $xml->createElementNS('http://ksef.mf.gov.pl/auth/token/2.0', 'AuthTokenRequest');
    $xml->appendChild($root);
    
    $root->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', 'http://www.w3.org/2000/09/xmldsig#');
    $root->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:xades', 'http://uri.etsi.org/01903/v1.3.2#');
    
    $challengeEl = $xml->createElement('Challenge', $challenge);
    $root->appendChild($challengeEl);
    
    $ctxId = $xml->createElement('ContextIdentifier');
    $root->appendChild($ctxId);
    $nipEl = $xml->createElement('Nip', NIP);
    $ctxId->appendChild($nipEl);
    
    $subjType = $xml->createElement('SubjectIdentifierType', 'certificateSubject');
    $root->appendChild($subjType);
    
    $signature = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:Signature');
    $signature->setAttribute('Id', 'Sig-1');
    $root->appendChild($signature);
    
    $signedInfo = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:SignedInfo');
    $signature->appendChild($signedInfo);
    
    $canonMethod = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:CanonicalizationMethod');
    $canonMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
    $signedInfo->appendChild($canonMethod);
    
    $sigMethod = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:SignatureMethod');
    $sigMethod->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256');
    $signedInfo->appendChild($sigMethod);
    
    $ref1 = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:Reference');
    $ref1->setAttribute('URI', '');
    $signedInfo->appendChild($ref1);
    
    $transforms1 = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:Transforms');
    $ref1->appendChild($transforms1);
    
    $transform1a = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:Transform');
    $transform1a->setAttribute('Algorithm', 'http://www.w3.org/2000/09/xmldsig#enveloped-signature');
    $transforms1->appendChild($transform1a);
    
    $transform1b = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:Transform');
    $transform1b->setAttribute('Algorithm', 'http://www.w3.org/2001/10/xml-exc-c14n#');
    $transforms1->appendChild($transform1b);
    
    $digestMethod1 = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:DigestMethod');
    $digestMethod1->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
    $ref1->appendChild($digestMethod1);
    
    $digestValue1 = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:DigestValue');
    $ref1->appendChild($digestValue1);
    
    $ref2 = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:Reference');
    $ref2->setAttribute('Type', 'http://uri.etsi.org/01903#SignedProperties');
    $ref2->setAttribute('URI', '#SignedProperties-1');
    $signedInfo->appendChild($ref2);
    
    $digestMethod2 = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:DigestMethod');
    $digestMethod2->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
    $ref2->appendChild($digestMethod2);
    
    $digestValue2 = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:DigestValue');
    $ref2->appendChild($digestValue2);
    
    $sigValue = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:SignatureValue');
    $signature->appendChild($sigValue);
    
    $keyInfo = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:KeyInfo');
    $signature->appendChild($keyInfo);
    
    $x509Data = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:X509Data');
    $keyInfo->appendChild($x509Data);
    
    $x509Cert = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:X509Certificate', $certB64Body);
    $x509Data->appendChild($x509Cert);
    
    $object = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:Object');
    $signature->appendChild($object);
    
    $qualProps = $xml->createElementNS('http://uri.etsi.org/01903/v1.3.2#', 'xades:QualifyingProperties');
    $qualProps->setAttribute('Target', '#Sig-1');
    $object->appendChild($qualProps);
    
    $signedProps = $xml->createElementNS('http://uri.etsi.org/01903/v1.3.2#', 'xades:SignedProperties');
    $signedProps->setAttribute('Id', 'SignedProperties-1');
    $signedProps->setAttributeNS('http://www.w3.org/2000/xmlns/', 'xmlns:ds', 'http://www.w3.org/2000/09/xmldsig#');
    $qualProps->appendChild($signedProps);
    
    $signedSigProps = $xml->createElementNS('http://uri.etsi.org/01903/v1.3.2#', 'xades:SignedSignatureProperties');
    $signedProps->appendChild($signedSigProps);
    
    $signingTimeEl = $xml->createElementNS('http://uri.etsi.org/01903/v1.3.2#', 'xades:SigningTime', $signingTime);
    $signedSigProps->appendChild($signingTimeEl);
    
    $signingCert = $xml->createElementNS('http://uri.etsi.org/01903/v1.3.2#', 'xades:SigningCertificate');
    $signedSigProps->appendChild($signingCert);
    
    $certEl = $xml->createElementNS('http://uri.etsi.org/01903/v1.3.2#', 'xades:Cert');
    $signingCert->appendChild($certEl);
    
    $certDigestEl = $xml->createElementNS('http://uri.etsi.org/01903/v1.3.2#', 'xades:CertDigest');
    $certEl->appendChild($certDigestEl);
    
    $digestMethodCert = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:DigestMethod');
    $digestMethodCert->setAttribute('Algorithm', 'http://www.w3.org/2001/04/xmlenc#sha256');
    $certDigestEl->appendChild($digestMethodCert);
    
    $digestValueCert = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:DigestValue', $certDigest);
    $certDigestEl->appendChild($digestValueCert);
    
    $issuerSerial = $xml->createElementNS('http://uri.etsi.org/01903/v1.3.2#', 'xades:IssuerSerial');
    $certEl->appendChild($issuerSerial);
    
    $x509IssuerName = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:X509IssuerName', $issuer);
    $issuerSerial->appendChild($x509IssuerName);
    
    $x509SerialNumber = $xml->createElementNS('http://www.w3.org/2000/09/xmldsig#', 'ds:X509SerialNumber', $serialDec);
    $issuerSerial->appendChild($x509SerialNumber);
    
    return $xml;
}

// ============================================
// KANONIZACJA XML (C14N Exclusive)
// ============================================

function canonicalizeNode($node, $withComments = false, $exclusive = true, $withSubtree = true) {
    return $node->C14N($exclusive, $withComments, null, null);
}

function canonicalizeElement($xml, $elementId) {
    $xpath = new DOMXPath($xml);
    $xpath->registerNamespace('xades', 'http://uri.etsi.org/01903/v1.3.2#');
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    
    $node = $xpath->query("//*[@Id='$elementId']")->item(0);
    
    if (!$node) {
        exitWithError("Nie znaleziono elementu z Id='$elementId'");
    }
    
    return $node->C14N(true, false);
}

// ============================================
// PODPIS XML - PURE PHP
// ============================================

function signXMLPurePHP($xml, $privateKey) {
    logStep('[3/4] Podpisuję XML (pure PHP)...');
    
    file_put_contents(__DIR__ . '/debug_before_sign.xml', $xml->saveXML());
    
    $xpath = new DOMXPath($xml);
    $xpath->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    $xpath->registerNamespace('xades', 'http://uri.etsi.org/01903/v1.3.2#');
    
    $signatureNode = $xpath->query('//ds:Signature')->item(0);
    $signedInfoNode = $xpath->query('//ds:SignedInfo')->item(0);
    
    $docCopy = $xml->cloneNode(true);
    $xpathCopy = new DOMXPath($docCopy);
    $xpathCopy->registerNamespace('ds', 'http://www.w3.org/2000/09/xmldsig#');
    $signatureNodeCopy = $xpathCopy->query('//ds:Signature')->item(0);
    $signatureNodeCopy->parentNode->removeChild($signatureNodeCopy);
    
    $docCanon = $docCopy->C14N(true, false);
    $docDigest = base64_encode(hash('sha256', $docCanon, true));
    
    $digestValue1 = $xpath->query('//ds:Reference[@URI=""]/ds:DigestValue')->item(0);
    $digestValue1->nodeValue = $docDigest;
    
    $signedPropsNode = $xpath->query('//xades:SignedProperties[@Id="SignedProperties-1"]')->item(0);
    
    if (!$signedPropsNode) {
        exitWithError("Nie znaleziono xades:SignedProperties");
    }
    
    $signedPropsCanon = $signedPropsNode->C14N(false, false); 
    
    file_put_contents(__DIR__ . '/debug_signedprops_canon.txt', $signedPropsCanon);
    logStep("DEBUG: Digest SignedProperties: " . base64_encode(hash('sha256', $signedPropsCanon, true)));
    logStep("DEBUG: Długość canon: " . strlen($signedPropsCanon));
    
    $signedPropsDigest = base64_encode(hash('sha256', $signedPropsCanon, true));
    
    $digestValue2 = $xpath->query('//ds:Reference[@URI="#SignedProperties-1"]/ds:DigestValue')->item(0);
    $digestValue2->nodeValue = $signedPropsDigest;
    
    $signedInfoCanon = $signedInfoNode->C14N(true, false);
    
    $signature = '';
    $signAlgo = OPENSSL_ALGO_SHA256;
    
    if (!openssl_sign($signedInfoCanon, $signature, $privateKey, $signAlgo)) {
        exitWithError("Nie można podpisać: " . openssl_error_string());
    }
    
    $keyDetails = openssl_pkey_get_details($privateKey);
    if ($keyDetails['type'] === OPENSSL_KEYTYPE_EC) {
        $signature = convertECDSASignatureDERtoRaw($signature);
    }
    
    $sigValueNode = $xpath->query('//ds:SignatureValue')->item(0);
    $sigValueNode->nodeValue = base64_encode($signature);
    
    file_put_contents(__DIR__ . '/debug_final_signed.xml', $xml->saveXML());
    logStep("DEBUG: Zapisano XMLe debug");
    
    return $xml->saveXML();
}

// ============================================
// KONWERSJA PODPISU ECDSA: DER -> raw (r||s)
// ============================================

function convertECDSASignatureDERtoRaw($derSignature) {
    
    $offset = 0;
    $length = strlen($derSignature);
    
    if (ord($derSignature[$offset++]) !== 0x30) {
        exitWithError("Nieprawidłowy format podpisu DER ECDSA (brak SEQUENCE)");
    }
    
    $seqLen = ord($derSignature[$offset++]);
    if ($seqLen & 0x80) {
        $lenBytes = $seqLen & 0x7F;
        $seqLen = 0;
        for ($i = 0; $i < $lenBytes; $i++) {
            $seqLen = ($seqLen << 8) | ord($derSignature[$offset++]);
        }
    }
    
    if (ord($derSignature[$offset++]) !== 0x02) {
        exitWithError("Nieprawidłowy format podpisu DER ECDSA (brak INTEGER dla r)");
    }
    
    $rLen = ord($derSignature[$offset++]);
    $r = substr($derSignature, $offset, $rLen);
    $offset += $rLen;
    
    $r = ltrim($r, "\x00");
    
    if (ord($derSignature[$offset++]) !== 0x02) {
        exitWithError("Nieprawidłowy format podpisu DER ECDSA (brak INTEGER dla s)");
    }
    
    $sLen = ord($derSignature[$offset++]);
    $s = substr($derSignature, $offset, $sLen);
    
    $s = ltrim($s, "\x00");
    
    $targetLen = 32;
    
    $r = str_pad($r, $targetLen, "\x00", STR_PAD_LEFT);
    $s = str_pad($s, $targetLen, "\x00", STR_PAD_LEFT);
    
    return $r . $s;
}

// ============================================
// WYSYŁKA DO KSEF
// ============================================

function sendSignedXML($signedXml) {
    global $isCli;

    logStep('[4/4] Wysyłam podpis do KSeF (TEST)...');
    
    $ch = curl_init(URL_XADES);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
    curl_setopt($ch, CURLOPT_POST, true);
    curl_setopt($ch, CURLOPT_POSTFIELDS, $signedXml);
    curl_setopt($ch, CURLOPT_HTTPHEADER, [
        'Content-Type: application/xml',
        'Content-Length: ' . strlen($signedXml)
    ]);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, true);
    curl_setopt($ch, CURLOPT_CAINFO, CACERT_PATH);
    
    $response = curl_exec($ch);
    $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    
    if (curl_errno($ch)) {
        $error = curl_error($ch);
        curl_close($ch);
        exitWithError("CURL error: $error");
    }
    
    curl_close($ch);
    
    if (!in_array($httpCode, [200, 202])) {
        exitWithError("HTTP $httpCode z KSeF:\n$response");
    }
    
    $data = json_decode($response, true);
    
    if (!$data) {
        exitWithError("Odpowiedź nie jest JSON:\n$response");
    }
    
    $token = $data['authenticationToken']['token'] ?? null;
    $validUntil = $data['authenticationToken']['validUntil'] ?? null;
    
    if ($token) {
        logStep('OK: Otrzymano authenticationToken.');

        if ($isCli) {
            echo "TOKEN=$token" . PHP_EOL;
            if ($validUntil) {
                echo "VALID_UNTIL=$validUntil" . PHP_EOL;
            }
        } else {
            echo "<hr>";
            echo "<p><strong>TOKEN:</strong><br><textarea style=\"width:100%;height:120px;\">"
                . htmlspecialchars($token, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
                . "</textarea></p>";
            if ($validUntil) {
                echo "<p><strong>VALID_UNTIL:</strong> "
                    . htmlspecialchars($validUntil, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8')
                    . "</p>";
            }
        }

        exit(0);
    } else {
        exitWithError("Brak tokenu. Odpowiedź serwera:\n$response");
    }
}

// ============================================
// MAIN
// ============================================

function main() {
    $cert = null;
    $privateKey = null;

    preChecks();
    $cert = loadCertificate();
    $privateKey = loadPrivateKey();
    validateKeyAndCert($cert, $privateKey);
    
    $challenge = fetchChallenge();
    $xml = buildAuthXML($challenge, $cert);
    $signedXml = signXMLPurePHP($xml, $privateKey);
    
    sendSignedXML($signedXml);
}

main();
