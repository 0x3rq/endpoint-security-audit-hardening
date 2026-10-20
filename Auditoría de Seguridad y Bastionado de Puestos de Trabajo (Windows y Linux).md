### INFORME TÉCNICO DE AUDITORÍA DE SEGURIDAD Y BASTIONADO DE PUESTOS DE TRABAJO (NOVATEC)

#### 1\. Resumen Ejecutivo y Marco Normativo de Protección del Puesto

##### Contexto Estratégico e Introducción

El presente informe técnico expone los resultados de la auditoría de seguridad y evaluación de cumplimiento normativo realizada sobre una muestra representativa de las nuevas estaciones de trabajo destinadas a la infraestructura corporativa de NOVATEC. El alcance abarca tanto puestos de trabajo basados en el sistema operativo Microsoft Windows (orientados al personal administrativo y de gestión) como sistemas Linux Ubuntu Desktop (asignados al equipo técnico e informático). El objetivo estratégico esencial de este dictamen es evaluar la postura defensiva, la superficie de exposición y el grado de preparación operativa ante incidentes de dichos activos antes de autorizar su despliegue definitivo en producción y permitir el procesamiento de datos corporativos sensibles.

##### Síntesis Ejecutiva del Estado de Seguridad

La evaluación global revela un perfil de riesgo altamente crítico. Aunque la infraestructura presenta controles defensivos visibles reportados formalmente como "activos" por los sistemas operativos, el análisis técnico en profundidad demuestra la existencia de severas inconsistencias de configuración que anulan su efectividad real. Se han identificado exclusiones globales en el motor antivirus corporativo, protocolos de red obsoletos e inseguros habilitados, mecanismos de administración remota SSH desbastionados, omisión de políticas de complejidad de contraseñas y ausencia de bloqueo efectivo de sesión por inactividad. Esta divergencia entre la presencia formal y la eficacia práctica expone a NOVATEC a un riesgo inminente de compromiso por ingeniería social (phishing), ejecución ilimitada de código malicioso, escalada local de privilegios y movimiento lateral sin barreras entre plataformas.

##### Análisis del Marco Normativo Interno de NOVATEC

Como término de referencia y verificación se ha empleado la  *Normativa de Protección del Puesto*  corporativa de NOVATEC. Este marco técnico articula los requisitos mínimos de obligado cumplimiento estructurados en 11 dominios clave, diseñados para garantizar el principio de mínimo privilegio, el bastionado de servicios y la capacidad institucional de respuesta ante anomalías.  
Ámbito,Requisito de Obligado Cumplimiento  
Privilegios,La cuenta de uso diario no tiene privilegios de administrador; la elevación es puntual y controlada.  
Cuentas,No existen cuentas locales no autorizadas ni cuentas con privilegios equivalentes a root/administrador sin justificar.  
Cortafuegos,El firewall local está activo y es efectivo en todos los perfiles; no hay reglas que permitan todo el tráfico entrante.  
Antimalware,La protección en tiempo real está activa y sin exclusiones que la anulen.  
Actualizaciones,Las actualizaciones automáticas de seguridad están habilitadas.  
Bloqueo de Sesión,El equipo se bloquea por inactividad y el bloqueo exige credenciales.  
Acceso Remoto / Servicios,Solo los servicios necesarios están expuestos; el acceso remoto está restringido y SMBv1 deshabilitado (Windows).  
SSH (Linux),El servicio SSH no permite acceso directo de root ni autenticación solo por contraseña.  
Política de Contraseñas,Existe una política de caducidad/complejidad de contraseñas.  
Trazabilidad,El registro de eventos de inicio de sesión está activo (soporte a la detección/notificación).  
Notificación,El puesto dispone de un medio conocido para que el usuario notifique un incidente.

##### Análisis Crítico de la Eficacia frente a la Presencia

Esta auditoría aplica una metodología rigurosa orientada a desmitificar el estado booleano de las salvaguardas tecnológicas. La mera presencia de un software o indicador con la etiqueta "activado" carece de valor defensivo si las reglas operativas internas han sido alteradas. Un control se clasifica formalmente como  **"Inefectivo"**  cuando, estando habilitado a nivel de sistema operativo o servicio, contiene excepciones absolutas, configuraciones permisivas o ausencias de reautenticación que neutralizan por completo su capacidad de mitigación de riesgos. Identificar y catalogar estos controles inefectivos constituye la piedra angular de esta evaluación técnica.  
*Una vez fundamentada la aproximación metodológica y los requisitos normativos corporativos, se detalla a continuación la auditoría técnica pormenorizada sobre el entorno Microsoft Windows.*

#### 2\. Auditoría Técnica de Puestos de Trabajo Windows

##### Contexto Técnico e Introducción

La evaluación sobre la plataforma Windows se ha centrado en las estaciones de trabajo destinadas a cubrir las funciones operativas y administrativas de NOVATEC. En este entorno, la falta de endurecimiento local ( *hardening* ) genera un impacto organizacional grave, puesto que estos equipos gestionan flujos continuos de correo electrónico corporativo, navegación web e interactúan de forma directa con recursos compartidos en red. Un fallo en el bastionado local convierte a estos puestos en la puerta de entrada idónea para vectores de infección inicial.

##### Evaluación de Privilegios y Cuentas Locales

El análisis de usuarios, pertenencia a grupos locales y asignación de tokens de seguridad se ejecutó mediante la invocación de cmdlets nativos de PowerShell:

* **Verificación de miembros del grupo Administradores y tokens de sesión:**

Get-LocalGroupMember \-Group "Administradores"  
whoami /groups

*Resultado:*  Se identificó la asignación de cuentas de uso cotidiano del usuario final directamente dentro del grupo local Administradores, otorgando privilegios administrativos permanentes y contraviniendo el principio de mínimo privilegio.

* **Inventario y estado de cuentas de usuario del sistema:**

Get-LocalUser | Select-Object Name, Enabled, LastLogon, Description

*Resultado:*  Se inspeccionó el estado de las cuentas predeterminadas (Administrador, Invitado, DefaultAccount, WDAGUtilityAccount). Si bien las cuentas nativas deshabilitadas por defecto figuraban como inactivas (Enabled \= False), la cuenta de trabajo nominativa mantenía permisos de elevación sin restricciones de Control de Cuentas de Usuario (UAC).

##### Análisis de Cortafuegos y Antimalware (Exclusiones Críticas)

La revisión de las herramientas de defensa perimetral de host y antimalware evidenció el hallazgo técnico de mayor severidad en la plataforma Windows:

* **Auditoría del Cortafuegos de Windows:**

Get-NetFirewallProfile | Select-Object Name, Enabled  
Get-NetFirewallRule \-Enabled True \-Direction Inbound \-Action Allow | Select-Object DisplayName, Profile, Action

*Resultado:*  Se constató que los perfiles del cortafuegos ( *Domain* ,  *Private* ,  *Public* ) figuran en estado activo (Enabled \= True). Las reglas de entrada analizadas mostraron permisos habilitados para asistencia remota y descubrimiento de red, sin detectar reglas explícitas de denegación total o permisividad global  *any-to-any* .

* **Evaluación del Antivirus Corporativo (Windows Defender):**

Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, AntivirusEnabled  
Get-MpPreference | Select-Object DisableRealtimeMonitoring, ExclusionPath, ExclusionExtension, ExclusionProcess

*Resultado (Vulnerabilidad Crítica):*  La ejecución de Get-MpComputerStatus reporta formalmente que la protección en tiempo real está habilitada (RealTimeProtectionEnabled \= True). Sin embargo, el análisis profundo de directivas mediante Get-MpPreference reveló una exclusión absoluta configurada en el parámetro ExclusionPath apuntando directamente a la raíz C:\\. Esta configuración anula por completo el motor de análisis heurístico y de firmas sobre el volumen de almacenamiento principal, dejando inoperante la protección en tiempo real ante la descarga de artefactos dañinos.  
\+-------------------------------------------------------------------------+  
|                  EVALUACIÓN DE EFICACIA ANTIMALWARE (WINDOWS)           |  
\+-------------------------------------------------------------------------+  
| Estado Reportado: RealTimeProtectionEnabled \= True (Aparentemente OK)   |  
| Configuración Real: ExclusionPath \= "C:\\" (Exclusión total de disco)    |  
| Impacto Técnico: Motor de escaneo ciego ante cualquier ejecutable local |  
| Veredicto Audit: CONTROL INEFECTIVO (Riesgo Crítico / Prioridad P1)     |  
\+-------------------------------------------------------------------------+

##### Auditoría de Actualizaciones y Bloqueo de Sesión

El análisis de mantenimiento preventivo y controles de seguridad física arrojó las siguientes deficiencias:

* **Estado del Servicio de Actualizaciones de Windows:**

Get-Service \-Name wuauserv | Select-Object Name, Status, StartType

*Resultado:*  El servicio Windows Update (wuauserv) se identificó detenido (Status \= Stopped) y en modo de inicio manual (StartType \= Manual). Adicionalmente, se registran bloqueos por directiva local que impiden la descarga y aplicación automática de parches de seguridad críticos.

* **Mecanismos de Bloqueo de Pantalla por Inactividad:**

Get-ItemProperty \-Path 'HKCU:\\Control Panel\\Desktop' | Select-Object ScreenSaveActive, ScreenSaverIsSecure, ScreenSaveTimeOut

*Resultado:*  La consulta al Registro confirmó la activación del protector de pantalla (ScreenSaveActive \= 1). No obstante, el valor ScreenSaverIsSecure se encontró configurado en 0 (o asociado a cuentas sin contraseña definida). En consecuencia, tras cumplirse el tiempo de inactividad, el sistema apaga el monitor pero no exige credenciales para reanudar la sesión, haciendo inefectivo el control de seguridad física.

##### Servicios Remotos, Protocolos Inseguros y Política de Contraseñas

El examen de la superficie de exposición en red y la gestión de identidades reveló:

* **Protocolos obsoletos y servicios remotos:**

Get-WindowsOptionalFeature \-Online \-FeatureName SMB1Protocol | Select-Object FeatureName, State  
Get-Service \-Name TermService | Select-Object Name, Status, StartType

*Resultado:*  Se confirmó que el protocolo inseguro y descatalogado SMBv1 (SMB1Protocol) se encuentra activo (State \= Enabled), exponiendo la estación a vulnerabilidades de ejecución remota de código y propagación lateral tipo  *Worm* . El servicio de Escritorio Remoto (TermService) figuraba en estado detenido.

* **Directivas de Contraseñas Locales:**

net accounts

*Resultado:*  La auditoría de directivas de cuenta confirmó la permisión explícita de contraseñas de longitud cero (en blanco), ausencia de historial de reutilización y falta de requisitos de complejidad de claves.

##### Trazabilidad y Canal de Notificación de Incidentes

* **Auditoría de Eventos de Inicio de Sesión:**

auditpol /get /subcategory:"Inicio de sesión"

*Resultado:*  Se analizó la directiva de auditoría de eventos. Se identificó una discrepancia según la muestra de host analizada: mientras algunas imágenes registran eventos de éxito y fallo, otras presentan deshabilitada la captura de eventos de autenticación local, imposibilitando la trazabilidad forense.

* **Canal Corporativo de Notificación de Incidentes:**

Get-ChildItem \-Path "\$env:USERPROFILE\\Desktop", "\$env:USERPROFILE\\Documents"

*Resultado:*  La revisión de los entornos de trabajo del usuario confirmó la ausencia total de aplicaciones, accesos directos o procedimientos guiados que permitan al empleado notificar de forma inmediata un incidente de seguridad al departamento de TI.  
*Documentado el estado técnico defensivo del entorno Windows, la siguiente sección aborda la evaluación homóloga sobre el sistema operativo Linux.*

#### 3\. Auditoría Técnica de Puestos de Trabajo Linux

##### Contexto Técnico e Introducción

Las estaciones de trabajo basadas en Ubuntu Desktop 24.04 LTS están asignadas al personal técnico y de desarrollo informático de NOVATEC. La trascendencia de auditar minuciosamente este entorno radica en el nivel superior de accesos operados por este colectivo, la presencia de servicios de administración remota como SSH y el riesgo de que la infección de una estación técnica sea utilizada como pivote directo para comprometer la infraestructura de servidores de producción.

##### Gestión de Privilegios y Cuentas de Usuario

La verificación de identidades locales y privilegios administrativos en Linux se realizó mediante la inspección de ficheros del sistema:

* **Detección de cuentas no autorizadas con UID 0:**

awk \-F: '(\$3 \== 0\) { print \$1 }' /etc/passwd

*Resultado:*  Se confirmó que únicamente la cuenta root posee el identificador de superusuario UID 0\.

* **Análisis de intérpretes de comandos y cuentas del sistema:**

grep \-E '/bin/bash|/bin/sh' /etc/passwd

*Resultado:*  El análisis del fichero /etc/passwd identificó las cuentas habilitadas con consola interactiva. Se detectaron configuraciones atípicas en cuentas de servicio como sshd asignada con UID 122 y GID 65534, requiriendo un control estricto sobre sus permisos de ejecución.

##### Seguridad de Red y Protección Antimalware

* **Estado del Cortafuegos Local (UFW):**

sudo ufw status verbose

*Resultado:*  El cortafuegos Uncomplicated Firewall (ufw) está activo, aplicando una directiva por defecto de denegar tráfico entrante (deny (incoming)) y permitir tráfico saliente (allow (outgoing)).

* **Verificación de Motores Antimalware:**

systemctl status clamav-daemon  
which clamscan rkhunter chkrootkit

*Resultado:*  La comprobación de servicios y binarios confirmó la ausencia total de software antivirus o herramientas de detección de rootkits (ClamAV, rkhunter, chkrootkit). El puesto de trabajo técnico opera sin capacidades de escaneo antimalware.

##### Mantenimiento del Sistema y Bloqueo de Pantalla (GNOME)

* **Parches Automáticos de Seguridad:**

systemctl status unattended-upgrades  
cat /etc/apt/apt.conf.d/20auto-upgrades

*Resultado:*  El servicio de actualizaciones no supervisadas (unattended-upgrades) se encuentra inactivo y deshabilitado en las directivas de apt, impidiendo la instalación automatizada de parches de seguridad distribuidos por el fabricante.

* **Auditoría del Entorno de Escritorio GNOME:**

gsettings get org.gnome.desktop.session idle-delay  
gsettings get org.gnome.desktop.screensaver lock-enabled  
gsettings get org.gnome.desktop.screensaver lock-delay

*Resultado:*  Si bien el temporizador de inactividad de sesión (idle-delay) está definido en 300 segundos (5 minutos), el bloqueo automático de pantalla (lock-enabled) figura configurado en false (o con lock-delay prolongado). Esto permite que la pantalla se apague por inactividad pero mantenga la sesión desbloqueada, exponiendo el sistema a manipulación física no autorizada.

##### Hardening de SSH y Exposición de Servicios

El análisis de la configuración del demonio OpenSSH reveló deficiencias críticas de bastionado:

* **Identificación de Puertos y Servicios en Escucha:**

sudo ss \-tulpn

*Resultado:*  Se confirmó que el servicio sshd escucha en el puerto TCP 22 sobre todas las interfaces de red del equipo (0.0.0.0:22), quedando totalmente expuesto a la red local.

* **Auditoría de Directivas de Seguridad SSH:**

sudo grep \-Ei '^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)' /etc/ssh/sshd\_config /etc/ssh/sshd\_config.d/\* 2\>/dev/null

*Resultado (Vulnerabilidad Crítica):*  La inspección de las directivas activas de OpenSSH arrojó los siguientes parámetros:  
\+-------------------------------------------------------------------------+  
|                  EVALUACIÓN DE CONFIGURACIÓN SSH (LINUX)                |  
\+-------------------------------------------------------------------------+  
| Interfaz de Escucha: 0.0.0.0:22 (Exposición global en red)              |  
| Acceso Root Directo: PermitRootLogin \= yes (Permitido)                  |  
| Autenticación: PasswordAuthentication \= yes (Vulnerable a fuerza bruta) |  
| Veredicto Audit: NO CONFORME / RIESGO CRÍTICO (Prioridad P1)            |  
\+-------------------------------------------------------------------------+

##### Políticas de Contraseñas, Trazabilidad y Notificación

* **Parámetros de Contraseñas y Complejidad:**

grep \-E '^(PASS\_MAX\_DAYS|PASS\_MIN\_DAYS|PASS\_WARN\_AGE|PASS\_MIN\_LEN)' /etc/login.defs  
grep \-E 'pam\_pwquality|pam\_cracklib' /etc/pam.d/common-password

*Resultado:*  El fichero /etc/login.defs mantiene la configuración por defecto de la distribución sin caducidad estricta. En /etc/pam.d/common-password, los módulos de control de complejidad (pam\_pwquality) se encuentran comentados, permitiendo credenciales débiles.

* **Trazabilidad y Registros de Autenticación:**

sudo systemctl status systemd-journald rsyslog | grep \-E 'Active:'  
sudo cat /var/log/auth.log

*Resultado:*  Se confirmó que los servicios systemd-journald y rsyslog se encuentran activos, almacenando de forma correcta los eventos de inicio de sesión y uso de sudo en /var/log/auth.log.

* **Mecanismos de Notificación de Incidentes:**

ls \-la \~/Desktop \~/Downloads /usr/share/applications/\*incident\* 2\>/dev/null

*Resultado:*  Al igual que en Windows, no existen lanzadores, documentos ni utilidades en el entorno de usuario destinados a facilitar la comunicación inmediata de incidentes de seguridad al equipo de TI.  
*Una vez recolectadas las evidencias técnicas en ambas plataformas, se procede a consolidar los hallazgos en las matrices corporativas de evaluación de riesgos.*

#### 4\. Matriz Completa de Hallazgos y Evaluación de Riesgos

##### Contexto Analítico e Introducción

La clasificación de riesgos de esta auditoría adopta la metodología estandarizada de estimación de Impacto y Probabilidad, priorizando la remediación en cuatro niveles (P1 a P4):

* **P1 (Crítico):**  Vulnerabilidades que permiten la ejecución remota de código, escalada de privilegios incondicional o anulación completa de salvaguardas primarias.  
* **P2 (Alto):**  Inexistencia de controles preventivos clave, fallos de parches o controles inefectivos que facilitan accesos no autorizados.  
* **P3 (Medio):**  Configuraciones permisivas en directivas de contraseñas o mantenimiento preventivo deficiente.  
* **P4 (Bajo):**  Desviaciones menores o controles conformes que requieren seguimiento periódico.

**Nota Metodológica de Muestreo Multiequipo:**  Durante la auditoría de campo realizada sobre el lote de estaciones de NOVATEC (muestras procesadas por el equipo de auditoría), se detectaron variaciones puntuales entre imágenes de despliegue (p. ej., muestras donde el usuario conservaba privilegios de administración frente a otras con privilegios restringidos; o diferencias en la auditoría de logs). Para ofrecer una visión ejecutiva consolidada sin confundir al lector, las matrices sintetizan estos hallazgos reflejando los veredictos dobles debidamente acotados.

##### Matriz de Hallazgos de Windows (W-01 a W-10)

ID,Requisito,Evidencia Téc. / Comando,Estado,Nivel de Riesgo,Prioridad  
W-01,Privilegios,"Get-LocalGroupMember \-Group ""Administradores"" / whoami /groups",No conforme / Conforme (\*),Alto / Bajo,P1 / P4  
W-02,Cuentas locales,"Get-LocalUser \\| Select-Object Name, Enabled",Conforme,Bajo,P4  
W-03,Cortafuegos,Get-NetFirewallProfile / Get-NetFirewallRule,Conforme,Bajo,P4  
W-04,Antimalware,Get-MpPreference (ExclusionPath \= C:\\),Inefectivo,Crítico,P1  
W-05,Actualizaciones,Get-Service \-Name wuauserv (Stopped / Manual),No conforme,Medio,P2  
W-06,Bloqueo de sesión,Get-ItemProperty (ScreenSaverIsSecure \= 0),Inefectivo,Alto,P2  
W-07,Acceso remoto y SMBv1,Get-WindowsOptionalFeature (SMB1Protocol \= Enabled),No conforme,Crítico,P1  
W-08,Política de contraseñas,net accounts (Permite claves en blanco / sin histórico),No conforme,Medio,P2  
W-09,Trazabilidad,"auditpol /get /subcategory:""Inicio de sesión""",Conforme / No conforme (\*),Bajo / Alto,P4 / P1  
W-10,Notificación de incidentes,Get-ChildItem en Desktop y Documents,No conforme / No aplica,Medio,P2 / P4  
\**Nota: Refleja variaciones de configuración detectadas en el muestreo de imágenes de evaluación.*

##### Matriz de Hallazgos de Linux (L-01 a L-10)

ID,Requisito,Evidencia Téc. / Comando,Estado,Nivel de Riesgo,Prioridad  
L-01,Privilegios / Sudo,awk \-F: '(\$3 \== 0\) { print \$1 }' /etc/passwd / sudo \-l,Conforme / No conforme (\*),Bajo / Alto,P4 / P1  
L-02,Cuentas locales / UID,grep \-E '/bin/bash\\|/bin/sh' /etc/passwd (sshd UID 122),No conforme,Medio,P2  
L-03,Cortafuegos,sudo ufw status verbose (deny incoming),Conforme,Bajo,P4  
L-04,Antimalware,which clamscan rkhunter chkrootkit (No instalados),No conforme,Crítico,P1  
L-05,Actualizaciones automáticas,systemctl status unattended-upgrades (Desactivado),No conforme,Medio,P2  
L-06,Bloqueo de pantalla,gsettings get org.gnome.desktop.screensaver lock-enabled (false),Inefectivo,Alto,P2  
L-07,Acceso SSH / Exposición,sudo ss \-tulpn (0.0.0.0:22) / sshd\_config (Root/Pass \= yes),No conforme,Crítico,P1  
L-08,Política de contraseñas,/etc/login.defs / /etc/pam.d/common-password (Débil),No conforme,Alto,P1  
L-09,Trazabilidad,sudo systemctl status rsyslog / cat /var/log/auth.log,Conforme,Bajo,P4  
L-10,Notificación de incidentes,ls \-la \~/Desktop /usr/share/applications/incident,No conforme / No aplica,Medio,P2 / P4

##### Análisis Comparativo del Perfil de Riesgo

La coexistencia de estas vulnerabilidades en ambas plataformas genera una cadena de ataque catastrófica para NOVATEC. Un atacante que consiga la ejecución de código en Windows mediante un correo de phishing no encontrará resistencia del antivirus debido a la exclusión de C:\\. Posteriormente, la presencia del protocolo SMBv1 y la exposición del servicio SSH en Linux configurado con autenticación por contraseña y acceso root directo, abren la puerta al movimiento lateral no detectado y a la toma de control absoluta de los entornos informáticos corporativos.  
*Identificada la vulnerabilidad estructural de los puestos, la siguiente sección documenta la investigación forense realizada sobre los rastros de compromiso real identificados en las máquinas.*

#### 5\. Análisis de Incidentes y Trazabilidad Forense

##### Contexto Forense e Introducción

Durante la inspección técnica de los sistemas entregados para auditoría, se localizaron artefactos y registros indicativos de un compromiso previo. El objetivo de este análisis forense no es efectuar una reconstrucción completa de memoria, sino identificar los mecanismos de persistencia establecidos por la amenaza, determinar el vector de entrada inicial y evidenciar qué fallos de control permitieron la materialización del incidente.

##### Detección e Investigación de Persistencia

###### *1\. Entorno Windows: Mecanismo de Elevación y Persistencia*

La investigación de automatizaciones locales mediante PowerShell permitió identificar una tarea programada ajena a la línea base del sistema operativo:  
Get-ScheduledTask | Where-Object TaskPath \-notlike "\*Microsoft\*" | Select-Object TaskName, TaskPath, State  
(Get-ScheduledTask \-TaskName "ActualizadorSys").Actions

*Análisis Forense:*  Se detectó la tarea programada ActualizadorSys. El examen de sus acciones reveló que estaba diseñada para invocar binarios ejecutables ubicados en rutas del usuario. Debido a que la cuenta del usuario pertenecía al grupo Administradores y el control UAC se encontraba de facto anulado por la tarea, el script lograba la ejecución sistemática de procesos en segundo plano con  **privilegios elevados autorizados implícitamente** , manteniendo persistencia indefinida tras cada reinicio del sistema sin requerir interacción ni confirmación por parte del usuario.

###### *2\. Entorno Linux: Persistencia mediante Cron*

El rastreo de archivos de configuración temporal y automatizaciones en la estación Ubuntu se ejecutó mediante:  
crontab \-l; ls \-la /etc/cron.d/ /etc/crontab 2\>/dev/null  
cat /etc/cron.d/sysupd

*Análisis Forense:*  Se identificó el fichero /etc/cron.d/sysupd. El análisis de su sintaxis confirmó la programación de una tarea ejecutada periódicamente  **cada 10 minutos con privilegios de**  **root** . Esta instrucción ejecutaba un script en segundo plano que realizaba llamadas al sistema y registraba trazas operativas, asegurando el control persistente sobre el activo técnico.

##### Análisis del Vector de Entrada y Phishing

El rastreo de directorios de usuario (Desktop, Downloads, Temp) permitió reconstruir la secuencia de infección inicial:

* **Vector Windows:**  Se descubrió la presencia del archivo de correo de suplantación Factura\_Vencida.eml. La inspección del mensaje evidenció el uso de ingeniería social basada en la extorsión operativa (amenaza de suspensión inmediata del servicio por impago). El mensaje instaba al usuario a abrir un adjunto malicioso que desencadenaba la ejecución del script inicial.  
* **Vector Linux:**  Se identificó la presencia del script de instalación seed\_linux.sh almacenado en la carpeta personal, el cual configuró el estado anómalo y las tareas de persistencia en el equipo.

\+-------------------------------------------------------------------------+  
|                  CADENA FORENSE Y SECUENCIA DEL INCIDENTE               |  
\+-------------------------------------------------------------------------+  
| \[1. Phishing\]      \--\> Correo "Factura\_Vencida.eml" recibido por usuario|  
| \[2. Ejecución\]     \--\> Adjunto malicioso abierto sin bloqueo Defender   |  
| \[3. Persistencia\]  \--\> Tarea "ActualizadorSys" (Win) / "sysupd" (Linux) |  
| \[4. Escalada/UAC\]  \--\> Ejecución automática con privilegios Administrator/Root|  
\+-------------------------------------------------------------------------+

##### Correlación Causal entre Huecos de Control e Incidentes (El "So What?")

La materialización y persistencia de este incidente no fue accidental, sino la consecuencia directa de las deficiencias de control identificadas en las Secciones 2 y 3:

1. **Fallo de Prevención Primario (Antivirus Inefectivo):**  La exclusión de la ruta C:\\ en Windows Defender impidió que el motor en tiempo real analizara el archivo adjunto contenido en Factura\_Vencida.eml, permitiendo la descarga y ejecución del código malicioso sin generar alertas.  
2. **Fallo de Control de Elevación (Privilegios Excesivos):**  La pertenencia del usuario al grupo Administradores permitió que el código ejecutado creara la tarea programada ActualizadorSys con máximos privilegios, logrando la persistencia del malware.  
3. **Fallo de Detección Temprana y Movimiento Lateral:**  La activación de SMBv1 en Windows y la desconfiguración de SSH en Linux (permisión de acceso root con contraseña) dejaron los puertos de red expuestos, facilitando vectores de movimiento lateral entre puestos sin dejar registros consolidados.  
4. **Fallo de Notificación Humana:**  La inexistencia de una herramienta o canal directo de reporte de incidentes en el escritorio provocó que el usuario, tras recibir el correo de phishing, no notificara la anomalía a TI, permitiendo que la amenaza permaneciera latente.

*Demostrada la relación causa-efecto entre los fallos de configuración y el incidente real, la siguiente sección presenta el plan de bastionado técnico y la estrategia de concienciación.*

#### 6\. Plan de Bastionado y Hoja de Ruta de Concienciación (Ciclo PDCA)

##### Contexto de Mitigación e Introducción

Para neutralizar los riesgos diagnosticados, se articula una respuesta integral estructurada en dos vertientes: el  **bastionado técnico inmediato**  de las deficiencias P1 y P2, y el despliegue de un  **Programa Corporativo de Concienciación**  regido por la metodología  **PDCA**  ( *Plan-Do-Check-Act* ). Esta aproximación garantiza la remediación tecnológica de los puestos junto con la capacitación permanente del factor humano.

##### Plan de Bastionado Directo para Deficiencias Críticas

A continuación, se proporcionan las instrucciones y scripts de comandos nativos ( **PowerShell**  y  **Bash** ) para la remediación técnica inmediata de las vulnerabilidades P1 y P2 identificadas:

###### *1\. Remediación en Windows (PowerShell Administrador)*

\# \[P1\] 1\. Eliminar exclusión total de la unidad C:\\ en Windows Defender  
Remove-MpPreference \-ExclusionPath "C:\\" \-ErrorAction SilentlyContinue

\# \[P1\] 2\. Deshabilitar el protocolo obsoleto e inseguro SMBv1  
Disable-WindowsOptionalFeature \-Online \-FeatureName "SMB1Protocol" \-NoRestart

\# \[P2\] 3\. Forzar bloqueo de pantalla seguro exigiendo credenciales al reanudar  
Set-ItemProperty \-Path 'HKCU:\\Control Panel\\Desktop' \-Name "ScreenSaveActive" \-Value "1"  
Set-ItemProperty \-Path 'HKCU:\\Control Panel\\Desktop' \-Name "ScreenSaverIsSecure" \-Value "1"  
Set-ItemProperty \-Path 'HKCU:\\Control Panel\\Desktop' \-Name "ScreenSaveTimeOut" \-Value "300"

\# \[P2\] 4\. Activar el servicio de actualizaciones de Windows (wuauserv)  
Set-Service \-Name "wuauserv" \-StartupType Automatic  
Start-Service \-Name "wuauserv"

\# \[P1\] 5\. Eliminar tarea programada maliciosa de persistencia  
Unregister-ScheduledTask \-TaskName "ActualizadorSys" \-Confirm:\$false \-ErrorAction SilentlyContinue

###### *2\. Remediación en Linux (Terminal Bash Root)*

\#\!/bin/bash  
\# \[P1\] 1\. Bastionado estricto del servicio OpenSSH (/etc/ssh/sshd\_config)  
sed \-i 's/^\#\*PermitRootLogin.\*/PermitRootLogin no/' /etc/ssh/sshd\_config  
sed \-i 's/^\#\*PasswordAuthentication.\*/PasswordAuthentication no/' /etc/ssh/sshd\_config  
sed \-i 's/^\#\*PubkeyAuthentication.\*/PubkeyAuthentication yes/' /etc/ssh/sshd\_config  
systemctl restart sshd

\# \[P1\] 2\. Instalación de motor antimalware y herramientas de auditoría  
apt update && apt install \-y clamav clamav-daemon rkhunter chkrootkit  
freshclam  
systemctl enable \--now clamav-daemon

\# \[P2\] 3\. Habilitación de parches y actualizaciones automáticas  
apt install \-y unattended-upgrades  
systemctl enable \--now unattended-upgrades

\# \[P2\] 4\. Configuración del bloqueo automático de pantalla en GNOME  
gsettings set org.gnome.desktop.session idle-delay 300  
gsettings set org.gnome.desktop.screensaver lock-enabled true  
gsettings set org.gnome.desktop.screensaver lock-delay 0

\# \[P1\] 5\. Eliminación de la tarea de persistencia maliciosa en cron  
rm \-f /etc/cron.d/sysupd

##### Hoja de Ruta de Concienciación Organizada por Ciclo PDCA

           \+-------------------------------------------------+  
           |              1\. PLAN (Planificar)               |  
           | \- Definición de KPIs (Clics \<5%, Reportes \>80%) |  
           | \- Segmentación: Personal Admin vs. TI Técnico   |  
           \+------------------------+------------------------+  
                                    |  
                                    v  
           \+-------------------------------------------------+  
           |               2\. DO (Ejecutar / Hacer)          |  
           | \- Cronograma anual de formación y píldoras      |  
           | \- Simulacros de Phishing y talleres prácticos   |  
           \+------------------------+------------------------+  
                                    |  
                                    v  
           \+-------------------------------------------------+  
           |             3\. CHECK (Verificar / Evaluar)      |  
           | \- Revisiones a 3, 6 y 12 meses (Gophish / LMS)  |  
           | \- Auditoría de métricas frente a umbrales KPI   |  
           \+------------------------+------------------------+  
                                    |  
                                    v  
           \+-------------------------------------------------+  
           |              4\. ACT (Actuar / Reajustar)        |  
           | \- Tasa clics \>5% \-\> Formación obligatoria extra |  
           | \- Bucle de mejora continua y reajuste de temas  |  
           \+-------------------------------------------------+

###### *1\. Plan (Planificar)*

* **Objetivos Ciberseguros Medibles:**  
* Reducir la tasa de clics en campañas de phishing simulado a un umbral estricto  **inferior al 5%** .  
* Alcanzar una tasa de reporte voluntario de correos sospechosos  **superior al 80%**  en menos de 15 minutos tras la recepción.  
* Garantizar que el  **100% de los puestos de trabajo**  apliquen el bloqueo manual de sesión al ausentarse del puesto.  
* **Segmentación del Público Objetivo:**  
* *Personal Administrativo:*  Enfoque prioritario en identificación de phishing, verificación de remitentes, desconfianza ante mensajes urgentes, prevención de ejecuciones adjuntas y bloqueo físico de pantalla.  
* *Personal Técnico / TI:*  Enfoque avanzado en bastionado de sistemas ( *hardening* ), prohibición absoluta de exclusiones globales en antivirus, gestión segura de credenciales SSH mediante par de claves y gestión responsable de parches.

###### *2\. Do (Hacer)*

Cronograma anual de despliegue de acciones formativas y simulacros:  
Mes,Fase / Acción,Canal / Herramienta,Público Objetivo  
Mes 1,"Despliegue del botón corporativo ""Reportar Incidente"" en escritorios",Comunicado / Script GPO,Toda la plantilla  
Mes 2,Taller de concienciación: Ingeniería social y amenazas por email,Plataforma LMS / Moodle,Personal Administrativo  
Mes 3,Primera simulación de Phishing (Nivel Básico: Factura falsa),Plataforma  Gophish,Toda la plantilla  
Mes 4,"Seminario técnico: Bastionado de SSH, gestión de parches y antivirus",Sesión presencial / Lab,Personal Técnico / TI  
Mes 6,Segunda simulación de Phishing (Nivel Avanzado: Suplantación),Plataforma  Gophish,Toda la plantilla  
Mes 7,Campaña de seguridad física: Contraseñas y bloqueo de sesión,Píldoras / Cartelería,Toda la plantilla  
Mes 9,Simulación de vishing / ingeniería social telefónica,Vía telefónica,Personal Administrativo  
Mes 11,Cuestionario de evaluación global de conocimientos,Formulario Moodle / Forms,Toda la plantilla

###### *3\. Check (Verificar)*

Plan de evaluación de seguimiento estructurado a los 3, 6 y 12 meses utilizando herramientas gratuitas y de código abierto:  
Plazo,Herramienta Abierta / Gratuita,Indicador KPI Medido,Criterio de Éxito Medible  
3 Meses,Gophish  (Simulador de phishing open-source),Tasa de clics en adjuntos/enlaces,Tasa de clics \< 10%; Cero ejecuciones de código  
6 Meses,Moodle / Google Forms / LimeSurvey,% de aciertos en cuestionarios técnicos,Aciertos globales \> 85% en la plantilla  
12 Meses,Sistema de Ticketing de TI / Gophish,Tasa de reporte voluntario e incidentes,Tasa de reporte \> 80%; Clics en phishing \< 5%

###### *4\. Act (Actuar)*

Se establece un bucle automático de corrección. Si en las verificaciones periódicas de los meses 3 o 6 no se alcanzan los criterios de éxito (p. ej.,  **si la tasa de clics en la simulación de phishing supera el 5%** ):

1. Se activará la asignación automática de un  **módulo formativo de refuerzo obligatorio**  para los usuarios reincidentes.  
2. Se revisará el diseño de los materiales de concienciación, ajustando el nivel de dificultad de los simulacros.  
3. Se ejecutará una auditoría técnica no anunciada sobre los puestos para comprobar que no se hayan introducido nuevas exclusiones en Defender ni modificaciones no autorizadas en SSH.

##### Entregable Incluido: Guía Rápida de Seguridad para el Usuario

### GUÍA RÁPIDA DE SEGURIDAD PARA EL USUARIO (NOVATEC)

##### 1\. Identificación de Phishing y Correos Sospechosos

* **Verifique siempre el remitente:**  Compruebe que la dirección de correo coincida exactamente con el dominio corporativo oficial de la entidad remitente.  
* **Desconfíe de la urgencia y coacción:**  Dude de todo mensaje que exija acciones inmediatas bajo amenaza de suspensión de cuentas, multas o cortes de servicio.  
* **Prohibición de ejecutar adjuntos peligrosos:**  Nunca abra ni ejecute archivos descargados de correos no solicitados, especialmente aquellos con extensiones .exe, .ps1, .sh, .bat o .vbs.

##### 2\. Bloqueo Físico de la Sesión

* **Bloquee su pantalla al ausentarse:**  Cada vez que se levante de su puesto de trabajo, aunque sea por unos segundos, bloquee su equipo utilizando los atajos de teclado:  
* En  **Windows:**  Presione la combinación de teclas  **Windows \+ L** .  
* En  **Linux:**  Presione la combinación de teclas  **Ctrl \+ Alt \+ L** .  
* **Custodia de credenciales:**  No comparta sus contraseñas ni las mantenga anotadas en notas adhesivas o documentos no cifrados.

##### 3\. Notificación Inmediata de Incidentes

* **Procedimiento ante anomalías:**  Si recibe un correo sospechoso o detecta un comportamiento anómalo en su estación de trabajo:  
* Haga clic de forma inmediata en el acceso directo  **"Reportar Incidente"**  disponible en el escritorio de su equipo para alertar automáticamente al Departamento de TI.

##### Conclusión del Informe

La auditoría técnica realizada sobre las estaciones de trabajo de NOVATEC ha permitido diagnosticar  **tres deficiencias primarias de alto riesgo**  que comprometen la seguridad corporativa:

1. **La presencia de la exclusión global**  \**C:\\\**  **en el antivirus** , que anuló la protección en tiempo real y permitió la ejecución sin trabas del correo malicioso Factura\_Vencida.eml.  
2. **La exposición inaceptable del servicio SSH** , configurado permitiendo el acceso directo al superusuario root y autenticación basada en contraseñas interactivas.  
3. **La falta de bloqueo efectivo de sesión junto con la ausencia de un canal conocido de notificación de incidentes** , lo que impidió que el usuario alertara tempranamente a la unidad de TI sobre la amenaza recibida.

La ejecución del plan de bastionado directo mediante las instrucciones CLI provistas, en combinación con el despliegue del programa de concienciación bajo el ciclo PDCA, neutralizan de forma definitiva estos vectores de ataque, garantizando un estado defensivo robusto para la autorización final de los puestos de trabajo en producción.  
