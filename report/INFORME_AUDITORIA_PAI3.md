# INFORME TÉCNICO DE AUDITORÍA DE SEGURIDAD Y PLAN DE BASTIONADO (PAI-3)

**Proyecto:** PAI-3 VULNAWEB  
**Entidad Auditada:** Universidad Pública U-Secure  
**Equipo Auditor:** Security Team ST-01 (INSEGUS)  
**Marco Normativo:** Esquema Nacional de Seguridad (ENS - Categoría Alta), CIS Benchmarks, OWASP Top 10 (2021) & OWASP API Security Top 10 (2023), NIST SP 800-115  
**Fecha:** Octubre / Noviembre 2026  

---

## ÍNDICE DE CONTENIDOS
1. Resumen Ejecutivo
2. Auditoría y Bastionado de Sistemas Informáticos (Endpoints Linux)
   - 2.1 Descripción de los sistemas analizados y herramientas de análisis
   - 2.2 Plan de pruebas y resultados comparativos (Línea Base vs Post-Bastionado)
   - 2.3 Medidas técnicas aplicadas y justificación de exclusiones
   - 2.4 Conclusiones del bastionado de endpoints
3. Análisis y Bastionado de Navegadores Web Corporativos
   - 3.1 Descripción del sistema analizado y modelo de despliegue
   - 3.2 Directivas implementadas y plan de pruebas de robustecimiento
   - 3.3 Conclusiones y trazabilidad de robustecimiento
4. Auditoría de Seguridad de Dispositivos Móviles (BYOD)
   - 4.1 Descripción de los sistemas móviles y herramientas de análisis
   - 4.2 Matriz de evaluación de postura y plan de pruebas
   - 4.3 Medidas correctoras ejecutadas
   - 4.4 Conclusiones del entorno móvil
5. Auditoría de Aplicaciones Web y Servicios API (DAST, OWASP Top 10 y OWASP API 2023)
   - 5.1 Descripción de la plataforma web/API y herramientas DAST
   - 5.2 Trazabilidad de tráfico cifrado HTTPS (OWASP ZAP)
   - 5.3 Evaluación de vulnerabilidades y pruebas de concepto controladas
   - 5.4 Plan formal de mitigación defensiva (Web y API Security 2023)
   - 5.5 Conclusiones de la auditoría web
6. Referencias
7. Anexos y Trazas Técnicas

---

## 1. RESUMEN EJECUTIVO

En cumplimiento del Plan Director de Seguridad de la Información de la Universidad Pública U-Secure y en colaboración con INSEGUS, se ha llevado a cabo una auditoría técnica integral y un proceso exhaustivo de bastionado (hardening). La infraestructura evaluada comprende los puestos de trabajo corporativos (Linux), los navegadores web de acceso a la sede electrónica, los dispositivos móviles en modalidad BYOD utilizados por el Personal Docente e Investigador (PDI) y Personal Técnico, de Gestión y de Administración y Servicios (PTGAS), así como las plataformas web institucionales y sus correspondientes interfaces de programación de aplicaciones (APIs REST).

### Resultados Globales Clave:
- **Endpoints Linux:** La postura de seguridad inicial presentaba un Hardening Index de **66/100** (Lynis 3.1.6). Tras la aplicación sistemática de políticas de kernel sysctl, restricciones de almacenamiento modprobe, políticas de calidad PAM, cortafuegos UFW y software de detección de intrusiones, se ha alcanzado un Hardening Index verificado de **74/100**, superando el umbral mínimo exigido por la política corporativa (≥ 70).
- **Navegadores Web:** Se han desplegado directivas corporativas centralizadas (`policies.json`) forzando el modo HTTPS-Only, aislando cookies de primera parte, bloqueando extensiones no autorizadas, forzando la instalación de uBlock Origin y desactivando la telemetría, mitigando vectores de robo de credenciales y fuga de metadatos.
- **Dispositivos Móviles:** Se auditaron 2 dispositivos BYOD representativos (PDI y PTGAS) mediante análisis estático y dinámico (Malwarebytes / Koodous / ADB). Se eliminaron vectores críticos mediante la desactivación de orígenes desconocidos (sideloading = 0), la revocación de permisos de accesibilidad/overlay abusivos y el endurecimiento de interfaces inalámbricas.
- **DAST, Pentesting Web y Seguridad de APIs (OWASP API 2023):** Se validó la intercepción y trazabilidad completa de tráfico HTTP/HTTPS mediante proxy local en puerto 8081 (OWASP ZAP) con preservación íntegra de parámetros y cabeceras. Se identificaron y documentaron tres vulnerabilidades críticas del OWASP Top 10 y del estándar **OWASP API Security Top 10 (2023)** (Inyección en backend/SQLi, Cross-Site Scripting y Rotura de Autorización/BOLA/Path Traversal) en entorno de pruebas controlado (Juice Shop / DVWA), formulándose un plan formal de remediación con consultas parametrizadas, validación de esquemas JSON, codificación contextual de salida y políticas Content-Security-Policy (CSP).

---

## 2. AUDITORÍA Y BASTIONADO DE SISTEMAS INFORMÁTICOS (ENDPOINTS LINUX)

### 2.1 Descripción de los sistemas analizados y herramientas
Se ha seleccionado y auditado un entorno representativo del puesto de trabajo corporativo:
- **Sistema Auditado:** Ubuntu Linux (x86_64), Kernel 6.x, entorno corporativo de puesto docente/administrativo.
- **Herramienta de auditoría:** **Lynis v3.1.6**, estándar para auditoría de seguridad defensiva, escaneo de conformidad CIS Benchmarks y cálculo automatizado del índice de endurecimiento.

### 2.2 Plan de pruebas y resultados comparativos

| Métrica / Parámetro | Estado Inicial (Baseline) | Estado Post-Bastionado | Objetivo Política | Cumplimiento |
|---|---|---|---|---|
| **Hardening Index** | **66 / 100** | **74 / 100** | **≥ 70** | **SUPERADO (+8 pts)** |
| **Pruebas Ejecutadas** | 244 comprobaciones | 254 comprobaciones | Cobertura total | Conforme |
| **Componente Cortafuegos** | Inactivo / No configurado | **Activo (UFW: Deny In / Allow Out)** | ENS MP.IF.1 | Conforme |
| **Software de Intrusión (IDS)** | No detectado `[X]` | **Activo `[V]` (fail2ban / auditd)** | ENS OP.EXP.8 | Conforme |
| **Escáner de Malware** | No detectado `[X]` | **Activo `[V]` (rkhunter / debsums)** | ENS MP.SI.3 | Conforme |
| **Protección Kernel (sysctl)** | Valores por defecto | Fortificado (`fs.protected_*`, `dmesg_restrict`) | CIS Level 1 | Conforme |
| **Control PAM / Contraseñas** | Sin enforce de complejidad | `libpam-pwquality` (minlen=12, dcredit=-1) | ENS MP.ACC.2 | Conforme |

### 2.3 Medidas técnicas aplicadas y justificación de exclusiones
Las medidas correctoras aplicadas se implementaron mediante el script automatizado `harden_linux.sh`:
1. **Endurecimiento de Kernel y Red (`/etc/sysctl.d/99-security-hardening.conf`):** Desactivación de redirecciones ICMP (`accept_redirects = 0`), registro de paquetes marcianos (`log_martians = 1`), mitigación SYN flood (`tcp_syncookies = 1`) y restricción de punteros de kernel (`kptr_restrict = 2`, `dmesg_restrict = 1`).
2. **Políticas de Autenticación (`/etc/login.defs` y `/etc/security/pwquality.conf`):** Reducción de vigencia de contraseñas (`PASS_MAX_DAYS 90`), antelación de aviso (`PASS_WARN_AGE 14`), requisitos de complejidad PAM y umask restrictivo corporativo (`027`).
3. **Restricción de Almacenamiento y Control Físico (`/etc/modprobe.d/security-hardening.conf`):** Inhabilitación de drivers legacy como `firewire-core`, `cramfs`, `jffs2` y `udf` mediante directiva `install <modulo> /bin/true`.
4. **Banners Legales Disuasorios (`/etc/issue`, `/etc/issue.net`):** Cumplimiento de requisitos de advertencia legal previa a la autenticación conforme a ENS.
5. **Permisos de Archivos Críticos:** Restricción a `700` en directorios `/etc/cron.*` y `600` en `/etc/crontab`.

**Justificación de pruebas excluidas en `custom.prf`:**
- `FILE-6310` (Partición `/tmp` separada): Excluida debido al despliegue sobre almacenamiento unificado gestionado por volúmenes lógicos con montaje seguro por systemd (`nodev, nosuid, noexec`).
- `STRG-1846` (Controlador Firewire): Excluido por carecer el hardware evaluado de interfaz física Firewire en su placa base, siendo nula la superficie de ataque.
- `BOOT-5122` (Gestor LILO legacy): Excluido por utilizarse gestor moderno GRUB2 / UEFI Secure Boot.

### 2.4 Conclusiones
La ejecución del plan de bastionado elevó el índice de endurecimiento desde el nivel inicial (66) hasta un valor de **74**, cumpliendo el estándar exigido por la Universidad (≥ 70) y activando la tríada de defensa: cortafuegos perimetral, detección de intrusiones y análisis de integridad.

---

## 3. ANÁLISIS Y BASTIONADO DE NAVEGADORES WEB

### 3.1 Descripción del sistema analizado
- **Navegadores Evaluados:** Mozilla Firefox y Chromium / Google Chrome instalados en los puestos corporativos.
- **Mecanismo de Despliegue:** Inyección centralizada de directivas mediante `/etc/firefox/policies/policies.json` y `/etc/chromium/policies/managed/corporate_policy.json`.

### 3.2 Directivas implementadas y plan de pruebas

| Directiva Corporativa | Valor Configurado | Justificación y Amenaza Mitigada |
|---|---|---|
| `HttpsOnlyMode` | `force_enabled` | Previene ataques Man-in-the-Middle y SSL-Stripping forzando canales TLS 1.2+. |
| `PasswordManagerEnabled` | `false` | Impide el almacenamiento local de credenciales en ficheros SQLite vulnerables a malware. |
| `ExtensionSettings` | Lista blanca (Bloqueo `*`, Forzar `uBlock Origin`) | Impide la instalación de complementos maliciosos o extensiones que exfiltren cookies. |
| `BlockAboutConfig` | `true` | Evita que el usuario relaje configuraciones de seguridad de forma accidental o deliberada. |
| `DisableTelemetry` | `true` | Garantiza el cumplimiento de privacidad RGPD impidiendo el envío de datos de telemetría. |
| `network.trr.mode` (DoH) | `2` (DNS over HTTPS Cloudflare/Quad9) | Cifra las resoluciones DNS evitando el perfilado de navegación por el proveedor de red. |
| `Permissions (Camera/Mic/Loc)` | Denegación por defecto | Mitiga la activación no consentida de dispositivos de captura y geolocalización. |
| `media.peerconnection.enabled` | `false` | Mitiga la fuga de direcciones IP privadas a través de WebRTC al navegar mediante proxy/VPN. |

### 3.3 Conclusiones
La configuración bloqueada mediante directivas elimina el vector de error humano en la navegación diaria, garantizando que el acceso a la sede electrónica universitaria se realice exclusivamente bajo túneles TLS auditados.

---

## 4. AUDITORÍA DE SEGURIDAD DE DISPOSITIVOS MÓVILES (BYOD)

### 4.1 Descripción de sistemas móviles y herramientas
- **Dispositivo 1 (PDI):** Terminal Android 13 (Samsung Galaxy S22 - OneUI).
- **Dispositivo 2 (PTGAS):** Terminal Android 12 (Xiaomi Redmi Note 11 - MIUI).
- **Herramientas de evaluación:** Malwarebytes Mobile Security, Koodous Antivirus, Android Debug Bridge (ADB) y MobSF para análisis estático de paquetes institucionales.

### 4.2 Matriz de evaluación y resultados

```
[Vectores Evaluados]
  ├─ Sideloading (Orígenes desconocidos)   --> Inicial: Habilitado (1)  --> Remediado: BLOQUEADO (0)
  ├─ Integridad (Rooting / Magisk / SU)   --> Verificado: Ausente      --> SELinux: ENFORCING
  ├─ Actualización SO / Parche Seguridad  --> Inicial: Retraso         --> Remediado: ACTUALIZADO
  ├─ Interfaces Inalámbricas (Bluetooth)  --> Inicial: Visible         --> Remediado: RESTRINGIDO
  ├─ Permisos Críticos (Accesibilidad)    --> Inicial: 2 apps          --> Remediado: REVOCADOS
  └─ Escaneo Antimalware (Malwarebytes)   --> 0 Amenazas / 0 PUPs      --> LIMPIO
```

### 4.3 Medidas correctoras ejecutadas
1. **Desactivación de orígenes desconocidos:** Se verificó que `install_non_market_apps = 0`, restringiendo la descarga únicamente a tiendas oficiales supervisadas.
2. **Supervisión de Sockets y Conexiones:** Se auditaron las conexiones abiertas concurrentes, verificando la inexistencia de canales C2 activos en segundo plano durante las sesiones de acceso web institucional.
3. **Revocación de Permisos de Superposición y Accesibilidad:** Se eliminaron los permisos `SYSTEM_ALERT_WINDOW` a herramientas de terceros para impedir ataques de tipo *Tapjacking* y captura de pantalla.

### 4.4 Conclusiones
El establecimiento de directivas técnicas claras sobre dispositivos BYOD mitiga el riesgo de que terminales personales comprometidos actúen como puente hacia los servidores internos de la universidad.

---

## 5. AUDITORÍA DE APLICACIONES WEB Y SERVICIOS API (DAST Y OWASP API 2023)

### 5.1 Descripción de la plataforma web/API y herramientas DAST
- **Entorno de Evaluación:** Plataforma de prueba controlada desplegada en contenedor local (`http://127.0.0.1:3000`), representativa de aplicaciones ricas en JavaScript (SPA) que consumen APIs REST.
- **Herramienta DAST:** **OWASP ZAP (Zed Attack Proxy)**, configurado como proxy local en `127.0.0.1:8081`.

### 5.2 Trazabilidad de tráfico cifrado HTTPS (OWASP ZAP)
- **Instalación de CA Raíz:** Se generó y exportó el certificado dinámico de OWASP ZAP, siendo importado en el almacén de Autoridades de Certificación del navegador con confianza para identificación de sitios web.
- **Trazabilidad sin Modificación:** Se capturaron las peticiones de navegación estándar. La pestaña *History* de ZAP reflejó de forma fidedigna cada tupla Petición/Respuesta, incluyendo cabeceras HTTP (`User-Agent`, `Host`, `Cookie`, `Authorization`) y cuerpos JSON/form-urlencoded, demostrando visibilidad completa sobre el tráfico de red con cero degradación de parámetros.
- **Demostración de Intercepción Activa (Breakpoint):** Mediante la activación de breakpoints globales en ZAP, se interceptaron peticiones en tránsito antes de alcanzar el servidor web, demostrando la capacidad de auditar y ajustar campos de prueba en memoria antes de su reenvío.

### 5.3 Evaluación de vulnerabilidades OWASP Top 10 y OWASP API Security 2023

1. **A03:2021 (Web) / API8:2023 & API10:2023 – Inyección SQL en Backend API:**
   - *Hallazgo:* Parámetros de consulta en endpoints REST (`/rest/products/search?q=`) concatenaban entradas directamente en consultas backend.
   - *Evidencia:* Respuestas reflejadas y errores de sintaxis del motor de base de datos en respuestas JSON.
2. **A03:2021 (Web) / API8:2023 – Cross-Site Scripting y Renderizado Inseguro de JSON:**
   - *Hallazgo:* Datos devueltos por la API se insertaban en el DOM mediante sumideros inseguros sin codificación contextual.
   - *Evidencia:* Renderizado e interpretación de bloques de script en la sesión de prueba cliente.
3. **A01:2021 (Web) / API1:2023 – Rotura de Autorización a Nivel de Objeto (BOLA) / Path Traversal:**
   - *Hallazgo:* Endpoints de recuperación de ficheros/recursos permitían secuencias de escape de directorio (`../`) o enumeración de identificadores de objeto sin comprobar la pertenencia del recurso al usuario autenticado.
   - *Evidencia:* Acceso a recursos de otros usuarios o archivos fuera del directorio autorizado.

### 5.4 Plan formal de mitigación defensiva (Web y API Security 2023)
- **Mitigación de Inyección Backend (API8/API10):** Consultas preparadas obligatorias con PDO/JPA y tipado estricto en Data Transfer Objects (DTOs) en controladores API.
- **Mitigación XSS (API8):** Codificación contextual de salida (`htmlspecialchars` con UTF-8) y cabecera HTTP `Content-Security-Policy (CSP)` estricta, junto a cookies de sesión marcadas con `HttpOnly; Secure; SameSite=Strict`.
- **Mitigación BOLA & Path Traversal (API1:2023):** Verificación contextual de propiedad en cada petición API (`owner_id == auth_user_id`), listas blancas de ficheros y validación de confinamiento de ruta con `realpath()`.
- **Control de Consumo de Recursos (API4:2023):** Despliegue de limitación de tasa (rate limiting de 100 peticiones/minuto por token/IP) y limitación de tamaño máximo de cuerpo en peticiones JSON.

### 5.5 Conclusiones
Las vulnerabilidades detectadas responden a fallos de validación en la capa de desarrollo y arquitectura API que son plenamente corregibles mediante patrones de arquitectura segura, validación DAST automatizada y alineamiento con el estándar **OWASP API Security Top 10 (2023)**.

---

## 6. REFERENCIAS
1. Centro Criptológico Nacional (CCN-CERT). *Guías CCN-STIC 800 - Esquema Nacional de Seguridad (ENS)*.
2. Center for Internet Security (CIS). *CIS Ubuntu Linux Benchmark v1.0.0*.
3. Center for Internet Security (CIS). *CIS Mozilla Firefox Benchmark v1.1.0*.
4. OWASP Foundation. *OWASP Top 10:2021 - The Ten Most Critical Web Application Security Risks*.
5. OWASP Foundation. *OWASP API Security Top 10:2023 - The Ten Most Critical API Security Risks*.
6. National Institute of Standards and Technology. *NIST SP 800-115: Technical Guide to Information Security Testing and Assessment*.

---

## 7. ANEXOS Y EVIDENCIAS TÉCNICAS
- **Anexo A:** Script de endurecimiento automatizado (`hardening/harden_linux.sh`).
- **Anexo B:** Perfil de escaneo Lynis con justificación de exclusiones (`hardening/custom.prf`).
- **Anexo C:** Registros de auditoría Lynis inicial (`66`) y final (`74`) (`evidence/lynis_*`).
- **Anexo D:** Directivas de bastionado de navegadores (`browser/firefox_policies.json`).
- **Anexo E:** Hojas de auditoría de dispositivos móviles BYOD (`evidence/mobile/`).
- **Anexo F:** Trazabilidad de tráfico e intercepción proxy ZAP (`evidence/web_audit/TRACEABILITY_EVIDENCE.md`).
- **Anexo G:** Plan técnico de mitigación defensiva Web y API Security 2023 (`web_audit/OWASP_TOP10_DEFENSIVE_REMEDIATION_PLAN.md`).
