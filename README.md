# Endpoint Security Audit & System Hardening (Windows & Linux)

Auditoría técnica de cumplimiento normativo, evaluación de seguridad y plan de bastionado (*system hardening*) para puestos de trabajo corporativos en entornos **Windows 10/11** y **Ubuntu Linux**.

---

## Objetivo del Proyecto

Evaluar la postura de seguridad de las estaciones de trabajo de la organización corporativa (NOVATEC), identificando configuraciones inefectivas, servicios vulnerables y deficiencias en las políticas de seguridad locales frente a la normativa interna de protección del puesto.

---

## Tecnologías y Herramientas Utilizadas

* **Sistemas Operativos:** Windows 10/11 Pro, Ubuntu Linux (Desktop/Server).
* **Auditoría Windows:** PowerShell, `Get-MpPreference`, `Get-LocalGroupMember`, `net accounts`, `auditpol`.
* **Auditoría Linux:** Bash, `/etc/passwd`, `sudoers`, `ufw`, `ss/netstat`, `journald`, `auth.log`.
* **Análisis de Amenazas:** Trazabilidad de tareas programadas (`cron` / `Task Scheduler`) y vectores de entrada (*phishing*).

---

## Alcance y Metodología

1. **Auditoría de Control de Accesos y Privilegios:** Verificación de superusuarios (`UID 0`), permisos de administración y políticas de contraseñas.
2. **Evaluación de Antivirus y Cortafuegos:** Identificación de exclusiones críticas en Defender, estado del cortafuegos local y servicios de actualización deshabilitados.
3. **Análisis de Servicios e Inseguridad de Red:** Detección de protocolos obsoletos activos (SMBv1) y bastionado de accesos remotos (SSH).
4. **Respuesta e Investigación Forense:** Rastreo del vector de entrada de correo malicioso y mecanismos de persistencia en el sistema.
5. **Plan de Bastionado (PDCA):** Hoja de ruta de remediación técnica y programa de concienciación sobre ciberseguridad.

---

## Estructura del Repositorio

* **`Informe_Auditoria_Security_Hardening.pdf`**: Reporte técnico forense y de auditoría completo con evidencias, matrices de riesgo (P1-P4) y soluciones detalladas.
* **`README.md`**: Resumen del proyecto y ficha técnica.

---

**Para consultar la matriz completa de riesgos, evidencias y comandos de remediación, revisa el [Informe Técnico PDF](./Informe_Auditoria_Security_Hardening.pdf).**
