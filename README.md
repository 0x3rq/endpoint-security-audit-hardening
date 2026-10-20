# Endpoint Security Audit & System Hardening (Windows & Linux) 
Auditoría técnica de cumplimiento normativo, evaluación de vulnerabilidades y plan de bastionado (*system hardening*) sobre puestos de trabajo corporativos en entornos **Windows 10/11** y **Ubuntu Linux** [3, 7]. 

## Resumen del Proyecto 
Este proyecto analiza la postura de seguridad de las estaciones de trabajo de la organización corporativa (NOVATEC), evaluando la eficacia de los controles de seguridad locales frente a la normativa interna de protección del puesto [2, 3, 8]. El análisis combina verificación por línea de comandos (PowerShell y Bash) [9], detección de configuraciones inefectivas o ausentes [10] y trazabilidad de eventos anómalos [11-13]. 
--- 

## Ámbitos de Auditoría Técnica 

### Estación de Trabajo Windows 
* **Privilegios y Cuentas:** Verificación de cuentas locales habilitadas y asignación de permisos de administración mediante `Get-LocalGroupMember` y `Get-LocalUser` [14, 15]. 
* **Protección Antimalware e Inefectividad:** Identificación de exclusiones críticas globales en la raíz `C:\` mediante `Get-MpPreference` que anulaban la protección en tiempo real de Windows Defender [16, 17]. 
* **Servicios y Protocolos Inseguros:** Detección del protocolo obsoleto SMBv1 activado (`SMB1Protocol Enabled`) y desactivación de actualizaciones automáticas (`wuauserv`) [18-20]. 
* **Políticas de Sesión y Credenciales:** Ausencia de requisitos de complejidad de contraseñas (`net accounts`) e inefectividad en el bloqueo de sesión tras inactividad sin solicitud de contraseña [18, 20-22]. 
* **Trazabilidad de Registro:** Evaluación de auditoría de eventos de inicio de sesión mediante `auditpol` [21, 23]. 

### Estación de Trabajo Linux (Ubuntu) 
* **Control de Superusuario:** Comprobación de usuarios con `UID 0` adicionales en `/etc/passwd` y restricciones de ejecución `sudo` [24, 25]. 
* **Seguridad de Red y SSH:** Identificación del servicio SSH expuesto en todas las interfaces (`0.0.0.0:22`) permitiendo autenticación directa de `root` y contraseña sin par de claves (`PermitRootLogin yes`, `PasswordAuthentication yes`) [26, 27]. 
* **Cortafuegos y Antivirus:** Verificación de estado del cortafuegos local `ufw` y ausencia de motores de escaneo antimalware [28-30]. 
* **Actualizaciones Desatendidas:** Comprobación del servicio `unattended-upgrades` [28, 30]. 
--- 

## Matriz Resumen de Hallazgos y Riesgos 

| ID | Sistema | Ámbito Auditado | Evidencia Principal | Estado | Nivel de Riesgo | Prioridad | 
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | 
| **W-01** | Windows | Privilegios | Cuentas de usuario en grupo Administradores [15] | No Conforme | **Alto** | P1 | 
| **W-04** | Windows | Antimalware | Exclusión global en ruta `C:\` en Defender [16, 17] | **Inefectivo** | **Alto** | P1 | 
| **W-05** | Windows | Actualizaciones | Servicio `wuauserv` deshabilitado / manual [18, 19] | No Conforme | Medio | P2 | 
| **W-07** | Windows | Acceso Remoto | Protocolo SMBv1 activo en el sistema [20] | No Conforme | **Alto** | P1 | 
| **L-01** | Linux | Privilegios | Permisos `sudo` irrestricto `(ALL : ALL) ALL` [25] | No Conforme | **Alto** | P1 | 
| **L-04** | Linux | Antimalware | Ausencia de software de protección activo [29, 30] | No Conforme | **Alto** | P1 | 
| **L-07** | Linux | Servicio SSH | Acceso directo de `root` y contraseña activa [26, 27] | No Conforme | **Alto** | P1 | 
| **L-08** | Linux | Contraseñas | Parámetros de complejidad por defecto sin PAM [28, 31] | No Conforme | Medio | P2 | 
--- 

## Análisis Forense y Trazabilidad de Anomalías 
* **Mecanismos de Persistencia:** Localización de tareas programadas sospechosas (`ActualizadorSys` en Windows y `sysupd` en `/etc/cron.d/` en Linux) diseñadas para ejecutarse con privilegios elevados [12, 13, 32, 33]. 
* **Vector de Entrada:** Rastreo de correos electrónicos de ingeniería social (*phishing* de factura vencida) y scripts ejecutables que explotaron la falta de canales de notificación y la inefectividad de los antivirus [13, 16, 34, 35]. 
--- 

## Plan de Bastionado y Mejora Continua (PDCA) 
1. **Remediación Técnica:** Eliminación de exclusiones en antivirus, desactivación de SMBv1, deshabilitación del acceso root por SSH e implantación de autenticación por clave pública [26, 36-38]. 
2. **Concienciación y Cultura:** Despliegue de un botón directo de **Reporte de Incidentes** en el escritorio de los usuarios y ejecución de simulacros de *phishing* periódicos con Gophish [39-41].
