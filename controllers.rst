##########################
Hardening de controladoras
##########################

.. highlight:: bash

*********************
Arquitectura genérica
*********************

Roles
=====

En la solución HPE-Aruba, una controladora (versión 6.4, 6.5) puede desempeñar uno de tres roles posibles: Master, Local o Branch. Desde el punto de vista de configuración,

- Las controladoras **Master** contienen la configuración del servicio WiFi. Estas controladoras se provisionan y configuran manualmente, o a través de una plataforma de gestión como Airwave o Aruba Central.
- Las controladoras **Local** replican la configuración del servicio WiFi desde una controladora máster, pero algunos parámetros básicos de conectividad de la controladora (VLANs, direccionamiento IP, gateway, etc) requieren una configuración local (manual o mediante plataforma de gestión).
- Las controladoras **Branch** obtienen toda su configuración desde una controladora máster, incluyendo los parámetros básicos de conectividad. Estas controladoras se provisionan utilizando un mecanismo de autodescubrimiento *Zero Touch Provisioning*, basado en servicios cloud de HPE-Aruba.

Tráfico
=======

Cualquiera de los tres roles puede recibir y conmutar tráfico procedente de APs locales o remotos (RAPs). Entre los distintos tipos de dispositivos hay varios `flujos de comunicación`_ [#omision_firewalls]_:

.. _flujos de comunicación: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/Firewall_Port_Info/Communication_Between__D.htm

.. image:: _static/controller_roles.*

- Entre controladoras (Master-Branch o Master-Local) se establecen túneles cifrados IPSEC, encapsulados en UDP (NAT-T) si se detecta que alguno de los dos extremos está detrás de un firewall o NAT.

  Generalmente estos túneles cursan tráfico de control. En el caso de controladoras Branch, el túnel establecido contra su controladora Master se usa para todo el tráfico entre central y sede remota: control y datos.

   - IKE (UDP 500).
   - IPSEC ESP (protocolo 50).
   - NAT-T (UDP 4500).

- Entre APs locales y controladoras se utilizan varios protocolos:

   - PAPI (UDP 8211).
   - FTP (TCP 21, 22).
   - TFTP (UDP 69).
   - SYSLOG (UDP 514).
   - GRE (protocolo 47).
   - CPSec (UDP 4500).
   - NTP (UDP 123)

- Entre APs remotos (RAPs) y controladoras, se establecen túneles IPSEC encapsulados en UDP (NAT-T)

   - IKE (UDP 500).
   - NAT-T (UDP 4500).

Además de estos flujos, las controladoras pueden establecer las siguientes conexiones entrantes y salientes:

**Entrantes**:
  
  - Gestión:

    - HTTP/HTTPS (TCP 80, 443, 4343). 80 redirige a 443, y 443 redirige inmediatamente a 4343 en el caso de acceso a gestión.
	- HTTP/HTTPS (8080. 8081, 8088 TCP). Usado para portal cautivo.
    - SSH (TCP 22).
    - SNMP (UDP 161).

  - Control:

    - Radius CoA (UDP 3799).

  - Servicios accesibles a usuarios de la LAN / WLAN:

    - DHCP (local o Relay) (UDP 68).
    - HTTPS (TCP 443, 4343) cuando hay portal cautivo.

  - Otros protocolos de conectividad remota:
  
    - L2TP (UDP 1701)
	- PPTP (TCP 1723)

**Salientes**:
  
  - Infraestructura:

    - DNS (UDP 53).
    - DHCP (UDP 67) - En controladoras Branch se usa IP dinámica para los enlaces WAN / Internet. En el resto de controladoras, típicamente se usa IP estática.
    - NTP (UDP 123).

  - Clearpass:

    - RADIUS (UDP 1812, 1813).
    - Relay DHCP (UDP 67).
    - HTTPS (TCP 443) (Guest, IF-MAP).

  - Airwave, ALE:

    - AMON (UDP 8211).

  - Monitorización:

    - SNMP Trap (UDP 162).
    - Syslog (UDP 514, TCP 514).

  - Servicios en la nube:

    - HTTPS (443) (Aruba Activate, Brightcloud).

Configuraciones
===============

Este documento no es un manual de configuración ni sustituye a las guías de usuario. Su objetivo es servir al equipo de seguridad de la empresa como una referencia para:

- Identificar las funcionalidades de hardening que soportan los equipos,
- Expresar las políticas de seguridad en forma de parámetros de configuración para esas funcionalidades,
- Verificar de forma automática que esas configuraciones están aplicadas.

Los diferentes entornos de una empresa pueden varias en arquitectura (standalone, master / branch) y en herramientas de gestión (CLI, Airwave, interfaz web smart branch), y eso afecta a:

- Dónde se realizan las configuraciones: en la propia controladora, en su controladora Master, o en Airwave.
- Qué interfaz de administración se usa: CLI, Airwave, interfaz Web.

Pero en todos los casos se cumple que la configuración aplicada se convierte en un fichero de comandos CLI que se almacena localmente en cada controladora, sea master, local o branch.

Desde este punto de vista, la herramienta más útil para expresar y validar automáticamente una política de configuración en las controladoras es la línea de comandos. El procedimiento sugerido es:

- Definir plantillas de CLI que reflejen cada aspecto de la política de seguridad.
- Permitir que los administradores de acceso utilicen la herramienta que consideren más adecuada (CLI, Airwave, Web) para desplegar la política, tomando las plantillas como referencia.
- Obtener copias periódicas de la configuración de las controladoras, incluyendo opcionalmente la salida de algunos comandos enumerados en este documento.
- Validar la aplicación de las políticas contrastando la copia de configuración con las plantillas de seguridad.

Acceso a la CLI
---------------

Para tener acceso a la CLI de la controladora, es necesario utilizar un cliente SSH v2. La CLI tiene diferentes `modos de acceso`_; generalmente el acceso inicial a la controladora se realiza en modo *usuario*, en oposición al modo  *privilegiado*. Para pasar a modo privilegiado y poder realizar una copia de la configuración, se debe introducir la contraseña de **enable**::

  # Acceso inicial en modo user: El prompt del sistema utiliza el carácter ">"
  $>
  
  # Habilitar el modo privilegiado con el comando "enable".
  # Solicita interactivamente la clave de enable
  $> enable
 
  # Modo privilegiado activo: El prompt del sistema utiliza "#"
  $#

Copia de configuración
----------------------

La configuración local de las controladoras puede enviarse a un servidor FTP o SCP externo, mediante el comando `copy`_::

  # Copia de configuración activa a servidor FTP.
  # Este comando solicita el password del usuario FTP interactivamente.
  $# copy running-config ftp: <ftphost> <user> <filename> <remote dir>
  
  # Si se prefiere usar SCP en lugar de FTP, es necesario copiar
  # primero la configuración a la flash local.
  $# copy running-config flash: current.cfg
  $# copy flash: current.cfg scp: <scphost> <username> <destfilename>

Redirección de comandos
-----------------------

Los parámetros de algunas de las funcionalidades no aparecen en la configuración si están en sus valores por defecto, lo que puede dificultar validar la política. En ese caso, se puede decidir ampliar la información recopilada utilizando comandos *show* adicionales.

La salida de cualquier comando se puede redirigir a un fichero local usando el filtro *| redirect-output*::

  $# show web-server profile | redirect-output
  'show web-server profile ' is written into redirect-output.log ...

La salida de los comandos se acumula en el fichero **redirect-output.log** de la flash. El fichero puede borrarse al iniciar la sesión con `delete`_ *filename redirect-output.log*, y enviarse por ftp/scp al finalizar la sesión con `copy`_::

  $# delete filename redirect-output.log
  $# show web-server profile | redirect-output
  'show web-server profile ' is written into redirect-output.log ...

  $# copy flash: redirect-output.log scp: <scphost> <username> <destfilename>

***********************
Mecanismos de hardening
***********************

Acceso administrativo
=====================

Las controladoras tienen tres interfaces de gestión: consola local, consola remota sobre SSH, e interfaz web sobre HTTPS. HTTP no está disponible para la gestión, y telnet está deshabilitado por defecto, aunque puede activarse con el comando `telnet`_ *cli*::

  # La inclusión del comando "telnet cli" en la configuración activa
  # indica que telnet está habilitado.
  $# show running-config | include "telnet cli"
  Building Configuration...
  telnet cli

  # Puede comprobarse explícitamente el estado del protocolo con "show telnet"
  $# show telnet

  telnet cli is enabled
  telnet soe is disabled

En cualquiera de las interfaces de gestión, las controladoras Aruba reconocen distintos `roles de usuario administrador`_:

===================== =================================================
rol                   Privilegios
===================== =================================================
root                  Acceso total
read-only             Solo lectura
guest-provisioning    Alta de usuarios invitados (portal cautivo)
location-api-mgmt     Acceso a API de localización
network-operations    Rol solo lectura más restringido que read-only
                      (ver `roles de usuario administrador`_)
===================== =================================================

Los roles pueden asociarse tanto a usuarios locales como remotos.

Credenciales locales
--------------------

En el caso de usuario locales, el rol se configura al crear el usuario con el comando de configuración `mgmt-user`_ *<usuario> <rol>*::

  # Lista de usuarios de gestión en la configuración activa
  $# show running-config | include mgmt-user
  Building Configuration...
  mgmt-user admin root d0d5231601a3*******************
  mgmt-user operator root 8bcc837e019d7**********************

  # Comando para enumerar explícitamente los usuarios configurados.
  $# show mgmt-user

  Management User Table
  ---------------------
  USER         PASSWD  ROLE   STATUS
  ----         ------  ----   ------
  admin        *****   root   ACTIVE
  operator     *****   root   ACTIVE

Es habitual tener un usuario local administrador con el rol **root** para casos de fallo de los servidores de autenticación remotos. El resto de usuarios locales podría eliminarse.

El failover de autenticación remota a local (en caso de no respuesta desde ninguno de los servidores de autenticación remotos) está activo por defecto. Se puede desactivar con `mgmt-user`_ *localauth-disable*::

  # La ausencia del comando indica configuración por defecto
  # (en este caso, failover a autenticación local activo)
  $# show running-config | include "mgmt-user localauth-disable"
  Building Configuration...

  # El estado del failover puede consultarse explícitamente con:  
  $# show mgmt-user local-authentication-mode
  Local Authentication Mode:      Enabled

Política de contraseñas
-----------------------

Las controladoras permiten definir múltiples parámetros para la política de contraseñas de usuarios locales:

=================================== ===================================================== ===================
Parámetro                           Descripción                                           Valor por defecto
=================================== ===================================================== ===================
password-lock-out                   Número de intentos fallidos (en 3 minutos)            0 (deshabilitado)
                                    que bloquean la cuenta.                               
password-lock-out-time              Tiempo durante el que la cuenta permanece bloqueada.  3
password-max-character-repeat       Máximo número de caracteres repetidos.                0 (deshabilitado)
password-min-digit                  Mínimo número de dígitos.                             0 (deshabilitado)
assword-min-length                  Longitud mínima.                                      6
password-min-lowercase-characters   Mínimo número de letras minúsculas.                   0 (deshabilitado)
password-min-special-character      Mínimo número de caracteres especiales.               0 (deshabilitado)
password-min-uppercase-characters   Mínimo número de letras mayúsculas.                   0 (deshabilitado)
password-not-username               El password no puede contener el nombre de usuario.   deshabilitado
=================================== ===================================================== ===================

Estos parámetros se configuran dentro del bloque `aaa password-policy mgmt`_::

  $# show running-config | begin "aaa password-policy mgmt"
  Building Configuration...
  aaa password-policy mgmt
     enable
     password-not-username
     password-lock-out <reintentos antes de bloquear>
     password-lock-out-time <minutos bloqueado>
  !

El valor de todos los modificadores (y no sólo de los que no están en su valor por defecto) se puede obtener con la orden `show aaa password-policy mgmt`_::

  $# show aaa password-policy mgmt

  Mgmt Password Policy
  --------------------
  Parameter                                                                                                 Value
  ---------                                                                                                 -----
  Enable password policy                                                                                    Yes
  Minimum password length required                                                                          6 characters
  Minimum number of Upper Case characters                                                                   0 characters
  Minimum number of Lower Case characters                                                                   0 characters
  Minimum number of Digits                                                                                  0 digits
  Minimum number of Special characters (!, @, #, $, %, ^, &, *, <, >, {, }, [, ], :, ., comma, |, +, ~, `)  0 characters
  Username or Reverse of username NOT in Password                                                           Yes
  Maximum consecutive character repeats                                                                     0 characters
  Maximum number of failed attempts in 3 minute window to lockout certificate based user                    0 attempts
  Maximum Number of failed attempts in 3 minute window to lockout password based user                       5 attempts
  Time duration to lockout the certificate based user upon crossing the "lock-out" threshold                3 minutes
  Time duration to lockout the password based user upon crossing the "lock-out" threshold                   10 minutes
  
Autenticación remota
--------------------

La autenticación remota puede realizarse contra RADIUS o TACACS. En ambos casos el procedimiento es muy similar, utilizando grupos ordenados de servidores de autenticación.

La creación de los `server groups`_ está fuera del alcnce de este documento. El server-group creado se asigna al acceso de gestión dentro del bloque de configuración `aaa authentication mgmt`_::

  # Bloque de configuración que activa la autenticación por servidor remoto.
  $# show run | begin "aaa authentication  mgmt"
  aaa authentication mgmt
     default-role "<rol por defecto, si Radius/Tacacs no asigna ninguno>"
     server-group "<grupo de servidores Radius>"
     enable
  !

  # El estado de la autenticación remota se puede consultar explícitamente con:
  $# show aaa authentication mgmt

  Management Authentication Profile
  ---------------------------------
  Parameter     Value
  ---------     -----
  Default Role  no-access
  Server Group  RADIUS_srvgrp
  Enable        Yes
  MSCHAPv2      Disabled

El servidor remoto debe asignar el rol del usuario administrador mediante una VSA reconocida (*Aruba-Admin-Role*). En caso contrario, el usuario adquiere el rol configurado con la opción *default-role*. Es aconsejable que ese rol sea **no-access**.

Si el repositorio de autenticación lo admite, es posible utilizar MsCHAPv2 para la autenticación remota, de forma que las credenciales de usuario no vayan en claro (PAP) en el mensaje RADIUS. Esta medida no es necesaria si se utiliza TACACS para la autenticación.

Para activar *mchapv2*, se utiliza la opción **mchapv2** del bloque de configuración `aaa authentication mgmt`_::

  $# show run | begin "aaa authentication  mgmt"
  aaa authentication mgmt
    # (Lineas omitidas ...)
    mchapv2
  !

  # El estado de la autenticación remota se puede consultar explícitamente con:
  $# show aaa authentication mgmt

  Management Authentication Profile
  ---------------------------------
  Parameter     Value
  ---------     -----
  # (Lineas omitidas...)
  MSCHAPv2      Enabled

Credenciales de enable
----------------------

Tras iniciar sesión, el paso de modo usuario a modo privilegiado en la CLI requiere la introducción de la contraseña de enable. La autenticación del modo enable:

- No se puede hacer contra un servidor externo.
- No admite política de complejidad de contraseña.

Por este motivo, es habitual desactivar el requerimiento de proporcionar la contraseña de enable y dejar que sea el rol asignado por RADIUS al usuario el que fije los privilegios del operador.

Para desactivar la autenticación enable, se utiliza el comando `enable bypass`_::

  $# show run | include "enable bypass"
  Building configuration...
  enable bypass

Password recovery
-----------------

Las controladoras Aruba tienen un mecanismo de password recovery que permite a cualquier usuario con acceso a consola restablecer las contraseñas de gestión local del equipo.

Para utilizar el mecanismo, es necesario forzar a que el equipo realice autenticación local, por ejemplo desconectándolo de la red para que no alcance los servidores Radius. Usando por consola las credenciales conocidas *password*/*forgetme!*, el usuario entra en un modo restringido que le permite reemplazar las contraseñas de administrador.

Para evitar este riesgo, puede desactivarse el acceso a la consola física del equipo con la orden `mgmt-user`_ *console-block*::

  # La ausencia del comando en la configuración indicaría que está en su valor por defecto (deshabilitado)
  $# show run | include "mgmt-user console-block"
  Building Configuration...
  mgmt-user console-block

  # El estado de la funcionalidad puede comprobarse también con:
  $# show mgmt-user console

  Serial Console Access:  Blocked

Tiempo de inactividad
---------------------

La controladora admite dos configuraciones de `tiempo máximo de sesión web`_: inactividad y absoluto [#tiempo_inactividad_web]_. Son parámetros globales que se configuran dentro del *web-server profile* general::

  $# show run | begin "web-server profile"
  Building Configuration...
  web-server profile
   # (lineas omitidas...)
   session-timeout <timeout inactividad - segundos>
   absolute-session-timeout <timeout absoluto - segundos>

Las lineas **no aparecen** en la configuración si están en sus valores por defecto:

  - Session-timeout: 900
  - Absolute session timeout: deshabilitado

En ese caso, la configuración puede validarse mediante la orden `show web-server`_ *profile*::

  $# show web-server profile

  Web Server Configuration
  ------------------------
  Parameter                                          Value
  ---------                                          -----
  Cipher Suite Strength                              high
  # (lineas omitidas...)
  User absolute session timeout <30-3600> (seconds)  0
  User session timeout <30-3600> (seconds)           900

Para las sesiones de gestión por consola, se utiliza un único timer de inactividad configurable con el comando `loginsession`_ *timeout <minutos>*::

  $# show run | include loginsession
  loginsession timeout <minutos>

Si el comando está ausente, la caducidad de la sesión tiene su valor por defecto (15 minutos). Si el comando está presente y el valor del timeout es **0**, la funcionalidad está deshabilitada.

Suites de cifrado
-----------------

Por defecto, el acceso a la interfaz web admite tanto TLS v1, como v1.1 o v1.2. En cualquiera de los protocolos, la suite de cifrado negociada sólo incluye por defecto algoritmos con tamaño de clave superior a 128 bits. Ambos parámetros, versiones del protocolo y suite de cifrado, se pueden modificar dentro de la sección `web-server profile`_ de la configuración del dispositivo, con las opciones:

================== ===================================================== ==========================
Opcion             Descripcion                                           Valor por defecto
================== ===================================================== ==========================
ciphers            Suite de cifrado a usar:                              high
                   *high* (claves de más de 128 bits),
                   *medium* (claves de 128 bits) o
                   *low* (claves de 56 o 64 bits).
ssl-protocol       Versiones de TLS admitidas: tlsv1, tlsv1.1, tlsv1.2   tlsv1 tlsv1.1 tlsv1.2
================== ===================================================== ==========================

Como siempre, si un parámetro tiene su valor por defecto, no aparece reflejado en el volcado de configuración y es necesario usar explícitamente el comando `show web-server profile`_ para ver su valor::

  $# show run | begin "web-server profile"
  web-server profile
   ciphers medium
   ssl-protocol tlsv1.1 tlsv1.2
  !

  $# show web-server profile
  (ArubaMadrid) # show web-server profile

  Web Server Configuration
  ------------------------
  Parameter                                          Value
  ---------                                          -----
  Cipher Suite Strength                              medium
  SSL/TLS Protocol Config                            tlsv1.1 tlsv1.2

Protocolos de cifrado - conexión RAP
------------------------------------

La conexión de APs remotos a las controladoras se realiza a través de IPSEC, utilizando el crypto-map dinámico número *10000* por defecto. Los parámetros de estas conexiones se pueden personalizar para por ejemplo sustituir el grupo Diffie-Hellman 2, vulnerable a ataques de pre-computación [#diffie_hellman_2_vulnerable]_, por otro con un tamaño de clave mayor, como el grupo 14::

  # Configuración de una política IKE con un número de grupo bajo (como el 10),
  # inferior a 10.000, para que tenga preferencia sobre las políticas por defecto.
  (config) $# crypto isakmp policy 10
  (config-isakmp)$# version v2
  (config-isakmp)$# group 14
  (config-isakmp)$# authentication RSA-sig
  (config-isakmp)$# exit

  # Asignación del grupo 14 a PFS.
  (config) $# crypto dynamic-map default-ikev2-dynamicmap 10000
  (config-dynamic-map) $# set pfs-group14

Protección del plano de control (rate-limit)
--------------------------------------------

La función de firewall integrada en las controladoras incluye varios mecanismos para limitar la tasa de tráfico que puede llegar al plano de control, a través de cualquiera de las interfaces, utilizando el comando `firewall cp-bandwidth-contract`_:

.. list-table::
   :header-rows: 1

   * - Orden
     - Aplicación
     - Valor por defecto
   * - `firewall cp-bandwidth-contract`_ *auth <pps>*
     - Tasa de tráfico permitida hacia el proceso de autenticación
     - 976 pps
   * - `firewall cp-bandwidth-contract`_ *route <pps>*
     - Tasa permitida de paquetes que requieren generar un ARP.
     - 976 pps
   * - `firewall cp-bandwidth-contract`_ *arp-traffic <pps>*
     - Tasa de tráfico ARP (procesado por el control plane).
     - 3906 pps
   * - `firewall cp-bandwidth-contract`_ *vrrp <pps>*
     - Tase de tráfico VRRP (procesado por el control plane).
     - 512 pps
   * - `firewall cp-bandwidth-contract`_ *l2-other <pps>*
     - Tasa de tráfico de protocolos de nivel 2 (STP, LACP, LLDP...) (procesado por el control plane).
     - 1953 pps
   * - `firewall cp-bandwidth-contract`_ *untrusted-ucast <pps>*
     - Tasa de unicast destinado a la controladora desde VLANs untrusted.
     - 9765 pps
   * - `firewall cp-bandwidth-contract`_ *sessmirr <pps>*
     - Limita el tráfico de la funcionalidad session mirror.
     - 976 pps
   * - `firewall cp-bandwidth-contract`_ *trusted-mcast <pps>*
     - Tasa de multicast destinado a la controladora desde VLANs trusted.
     - 1953 pps
   * - `firewall cp-bandwidth-contract`_ *trusted-ucast <pps>*
     - Tasa de unicast destinado a la controladora desde VLANs trusted.
     - 65535 pps
   * - `firewall cp-bandwidth-contract`_ *untrusted-mcast <pps>*
     - Tasa de multicast destinado a la controladora desde VLANs untrusted.
     - 1953 pps
   * - `firewall cp-bandwidth-contract`_ *untrusted-ucast <pps>*
     - Tasa de unicast destinado a la controladora desde VLANs untrusted.
     - 9765 pps

Nota: la descripción de interfaces *trusted* y *untrusted* se introduce más adelante en el apartado :ref:`proposito_interfaces`.

También pueden mitigarse varios ataques de flooding habituales (ARP, SYN, ICMP...) con el comando `firewall`_ *attack-rate [arp|cp|grat-arp|ping|session|tcp-syn]*. Ambas configuraciones, rate-limit y protección ante flooding, pueden consultarse con el comando `show firewall`_::

  $# show running-config | include firewall
  Building Configuration...
  # ... lineas omitidas
  firewall attack-rate cp 16384
  firewall attack-rate grat-arp 50 drop
  

  # Los parámetros que tienen el valor por defecto no salen
  # en la configuración. Se pueden consultar explícitamente con "show firewall"
  $# show firewall
  
  Global firewall policies
  ------------------------
  Policy                                       Action                                          Rate         Port
  ------                                       ------                                          ----         ----
  Monitor ping attack                          Disabled
  Monitor TCP SYN attack                       Disabled
  Monitor IP sessions attack                   Disabled
  Monitor ARP attack                           Disabled
  Monitor Gratuitous ARP attack                Enabled                                         50/30sec
  Monitor/police CP attacks                    Enabled                                         16384/30sec
  Rate limit CP untrusted ucast traffic        Enabled                                         9765 pps
  Rate limit CP untrusted mcast traffic        Enabled                                         3906 pps
  Rate limit CP trusted ucast traffic          Enabled                                         65535 pps
  Rate limit CP trusted mcast traffic          Enabled                                         3906 pps
  Rate limit CP route traffic                  Enabled                                         976 pps
  Rate limit CP session mirror traffic         Enabled                                         976 pps
  Rate limit CP auth process traffic           Enabled                                         976 pps
  Rate limit CP vrrp traffic                   Enabled                                         512 pps
  Rate limit CP ARP traffic                    Enabled                                         3906 pps
  Rate limit CP L2 protocol/other traffic      Enabled                                         1953 pps

Protección del plano de control (ACL)
-------------------------------------

Además de limitar la tasa de paquetes de distintos protocolos al plano de control, se puede configurar una lista blanca de acceso a diferentes protocolos en función de IP origen, con el comando `firewall cp`_ *[ipv4|ipv6] [permit|deny] [any|<ip> <mascara>] proto [ftp|http|https|icmp|snmp|ssh|telnet|tftp|<numero de protocolo> ports <puerto inicial> - <puerto final>]*.

Por ejemplo, denegar el acceso al servicio NTP de la controladora (UDP 123, número de protocolo IP de UDP: 17), se podría hacer con la regla::

  (config) $# firewall cp
  (config-fw-cp) $# ipv4 deny any proto 17 ports 123 123

A cada una de las reglas puede asociarse también un contrato de ancho de banda que limite el caudal disponible para ese protocolo y origen de tráfico en particular. Los contratos de ancho de banda se definen con el comando `cp-bandwidth-contract`_ *<nombre> pps <pps>*, y se asocian al protocolo en la regla de `firewall cp`_ descrita anteriormente.

Los contratos de ancho de banda y las reglas configuradas pueden consultarse con los comandos `show cp-bwcontracts`_ y `show firewall-cp`_::

  $# show cp-bwcontracts

  CP bw contracts
  ---------------
  Contract                  Id     Rate (packets/second)
  --------                  --     ---------------------
  cpbwc-ipv4-syslog         15785  2016
  cpbwc-ipv6-ike            15799  2016
  cpbwc-ipv6-file-transfer  15797  8000
  cpbwc-ipv4-radius-ldap    15788  1024
  cpbwc-ipv6-dns            15802  128
  cpbwc-ipv6-dhcp           15803  1024

  $# show firewall-cp

  CP firewall policies
  --------------------
  IP Version  Source IP   Source Mask  Protocol  Start Port  End Port  Action          hits  contract
  ----------  ---------   -----------  --------  ----------  --------  --------------  ----  --------
  ipv6        any                      17        49170       49200     Permit          0
  ipv4        any                      17        1900        1900      Permit          0
  ipv4        any                      17        5999        5999      Permit          0

El comando anterior no muestra todas las reglas aplicadas en la controladora, sino sólo las configuradas explícitamente. La controladora tiene una alrga lista de reglas por defecto que pueden enumerarse con `show firewall-cp`_ *internal*::

  CP firewall policies
  --------------------
  IP Version  Source IP  Source Mask  Protocol  Start Port  End Port  Action          hits  contract
  ----------  ---------  -----------  --------  ----------  --------  --------------  ----  --------
  ipv4        any                     6         1723        1723      Permit          0
  ipv4        any                     17        1701        1701      Permit          0
  ipv4        any                     6         23          23        Deny            0     cpbwc-ipv4-telnet
  ipv4        any                     6         8084        8084      Deny            0
  ipv4        any                     6         3306        3306      Deny            0
  # ... sigue

.. _control_acceso_acl:

Control de acceso por interfaz
------------------------------

En ocasiones, se quiere realizar un control de acceso a la gestión diferente en función no sólo del origen del tráfico, sino de la interfaz / VLAN por la que llega. Por ejemplo, denegando cualquier tráfico de gestión que venga de una interfaz conectada a Internet, sea cual sea su IP origen.

Para estos casos se pueden usar ACLs de interfaz. Generalmente se limitará el acceso a los puertos siguientes:

- 22 (SSH)
- 23 (telnet)
- 4343 (HTTPS)

El puerto 443 no se recomienda restringirlo, porque es el que usa el servicio de portal cautivo. En cualquier caso, para gestión, cualquier acceso al puerto 443 es inmediatamente redirigido al puerto 4343, así que no es necesario bloquearlo.

**Nomenclatura de servicios**

Típicamente, a cada puerto UDP/TCP se le asigna un nombre de servicio que se puede usar como un alias en las ACLs. Los puertos TCP 22 y 23 tienen nombres de servicio predefinidos en las controladoras (*svc-ssh* y *svc-telnet* respectivamente), al puerto 4343 se recomienda asignarle también un nombre descriptivo, como *svc-https-4343*, con el comando `netservice`_::

  (config)$# netservice <servicio tcp 4343> tcp 4343

  # Comprobacion en running-config
  show run | include <servicio tcp 4343>
  Building configuration...
  netservice <servicio> tcp 4343

  # Comprobacion con comando "show"
  $# show netservice <servicio tcp 4343>

  Services
  --------
  Name                Protocol  Ports  ALG  Type
  ----                --------  -----  ---  ----
  <servicio tcp 4343> tcp       4343

**Subredes de gestión**

Para facilitar la construcción de ACLs, se recomienda agrupar las subredes de gestión bajo un *alias*, con el comando `netdestination`_::

  (config)$# netdestination <alias para el grupo de redes de gestion>
  (config-dest)$# network <subred> <mascara>
	            # ... repetir por cada subred de gestión

  # Por ejemplo:
  (config)$# netdestination <alias gestion>
  (config-dest)$# network 10.0.100.0/26
  (config-dest)$# network 10.0.200.64/26
	            # ...

  # Comprobación en running-config
  $# show run | begin "netdestination <alias gestion>"
  netdestination <alias gestion>
   network 10.0.100.0/26
   network 10.0.200.64/26
  !
  
  # Comprobacion con comando "show"
  $# show netdestination <alias gestion>

  Name: <alias gestion>

  Position  Type     IP addr       Mask-Len/Range
  --------  ----     -------       --------------
  1         network  10.0.100.0    255.255.255.192
  2         network  10.0.200.64   255.255.255.192

**ACL para bloque gestión**

Las ACLs para limitar el acceso a la gestión pueden construirse con el comando `ip access-list session`_ <nombre de acl>*. El comando entra en un submodo donde se configura cada regla.

La sintaxis de las reglas es muy extensa y para más detalle se remite a la documentación. En este apartado simplemente daremos un ejemplo que autoriza el acceso a los puertos de gestión desde las redes incluidas en el alias creado antes, y deniega el resto. El alias *localip* identifica las direcciones IP locales::

  (config) $# ip access-list session <nombre acl>
  #              Permitir SSH y HTTPS únicamente desde redes de gestión.
  #              Origen                    Destino       Servicio            Accion
  #              -----------------------   ------------- ------------------- ------
  (config-acl)$# alias <alias gestion>     alias localip <servicio tcp 4343> permit
  (config-acl)$# alias <alias gestion>     alias localip svc-ssh             permit
  (config-acl)$# any                       alias localip <servicio tcp 4343> deny
  (config-acl)$# any                       alias localip svc-ssh             deny
  (config-acl)$# any                       alias localip svc-telnet          deny
  (config-acl)$# any                       any   any                         permit

  # comprobación de la ACL en running-config:
  $# show running-config | begin "ip access-list session <nombre-acl>"
    alias <alias gestion> alias localip <servicio tcp 4343> permit
    alias <alias gestion> alias localip svc-ssh permit
    any alias localip <servicio tcp 4343> deny
    any alias localip svc-ssh deny
    any alias localip svc-telnet deny
	any any any permit

  # Comprobación con comando "show"
  $# show ip access-list <nombre acl>

  ip access-list session <nombre acl>
  NAT-GUEST
  ---------
  Priority  Source          Destination   Service  Application  Action
  --------  ------          -----------   -------  -----------  ------
  1         <alias gestion> localip       tcp      4343         permit
  2         <alias gestion> localip       tcp      22           permit
  3         any             localip       tcp      4343         permit
  4         any             localip       tcp      22           permit
  5         any             localip       tcp      23           permit
  6         any             any           any                   permit

.. _aplicacion_acl:

**Aplicación de ACL**

Las controladoras tienen dos tipos de interfaces, *trusted* y *untrusted*, que se introducen en el apartado :ref:`proposito_interfaces`. La lista de control de acceso anterior debe aplicarse a todas las interfaces *trusted*, en todas las VLANs *trusted* definidas en esa interfaz, con el comando `ip access-group`_ *<nombre de acl> session vlan <numero de vlan>* [#licencia_PEFNG]_::

  (config) $# interface Gigabit <slot>/<modulo>/<puerto>
  (config-if) $# ip access-group <nombre de la ACL> session vlan <numero de vlan>
  # Repetir para todas las VLANs trusted del puerto

**ACL Para bloque de gestión (caso branch)**

En el caso de las controladoras en modo branch, se recomienda ser mucho más estricto con las ACLs:

- Las únicas interfaces *trusted* deben ser las correspondientes a los uplinks (WAN, ADSL).
- Los uplinks típicamente tendrán una única VLAN, y estarán en modo acceso.
- El único tráfico entrante que tiene que acceder a las controladoras a través de esas VLANS es el tráfico del túnel IPSEC.

Para el caso branch, la lista de control de acceso de interfaz puede hacerse mucho más restrictiva, permitiendo sólo:

- DHCP (el direccionamiento de uplink de las Branches suele ser dinámico)
- ESP (IPSEC)
- UDP 500 y 4500 (IKE v2 / NAT-T)

.. code: bash

  ip access-list <nombre acl>
    any any svc-dhcp  permit 
    any any svc-natt permit
    any any svc-ike  permit
    any any svc-esp  permit
  !

La lista de control de acceso se aplicaría a interfaces y vlans *trusted*, igual que en el apartado anterior.

Control de acceso a gestión (Clearpass)
---------------------------------------

Una alternativa complementaria para limitar el acceso remoto a gestión sólo a unas redes particulares, tanto para entornos Master / Local como Branch, es el uso de Clearpass. Los intentos de autenticación de las controladoras incluyen el atributo *Calling-Station-ID*, con la dirección IP del dispositivo que intenta conectar:

.. image:: _static/Calling-Station-ID.*

El servicio de autenticación de Clearpass puede configurarse para que sólo autorice el acceso cuando esa dirección pertenezca a los rangos de gestión autorizados.

- Dicha configuración conseguiría el efecto de bloquear el acceso a gestión utilizando cualquier protocolo e interfaz desde redes no autorizadas, independientemente del rol del usuario, en interfaces *trusted* y *untrusted*, siempre que la autenticación remota funcione.
- No sería efectiva si se pierde contacto con Clearpass, y no se ha deshabilitado el failover a autenticación local con el comando `mgmt-user`_ *localauth-disable*.

Esta alternativa no requiere configuración particular en la controladora. La verificación de la configuración en Clearpass pertenece a otro documento.

Banners
-------

El banner de inicio de sesión se configura con la orden `banner motd`_ *<delimitador> <texto>*. El delimitador permite definir banners con múltiples líneas, por ejemplo::

  (config)#$ banner motd %
  Este banner tiene multiples lineas.
  Al haber usado el simbolo de porcentaje como delimitador,
  el banner continua hasta que lo encuentre.
  %

  $# show run | begin "banner motd"
  banner motd %
  "Sistema privado."
  "Prohibido el acceso."
  %
  !

  $# show banner

  Sistema privado.
  Prohibido el acceso.

..
   Acceso por consola (APs)
   ------------------------

   El acceso por el puerto de consola de los APs / RAPs está protegido por una contraseña que por defecto es aleatoria. La configuración de esa contraseña se realiza dentro del *system-profile* asignado al AP.

   Los *system-profiles* definidos en una controladora se enumeran con la orden `show ap system_profile`_::

   $# show ap system-profile

     AP system profile List
     ----------------------
     Name                            References  Profile Status
     ----                            ----------  --------------
     apsystemprofile1                4
     ... (lineas omitidas) ...
     apsystemprofileN                13
     default                         2

     Total:9

Servicios de red
================

Resolución DNS
--------------

Las controladoras utilizan DNS para distintos propósitos:

- Resolver direcciones de servicios de infraestructura (Radius, syslog, airwave etc).
- Resolver nombres de host o dominio configurados en alias (`netdestination`_), que se utilizan en listas de control de acceso.
- Conectar a servicios cloud (Aruba Activate, BrightCloud, etc).

DNS se habilita o inhabilita a nivel global con el comando `ip domain lookup`_::

  # Si el comando no aparece en la configuración, está en su valor por defecto: habilitado.
  $# show run | include "ip domain lookup"
  Building configuration...
  
  # Se puede comprobar explícitamente con "show ip domain-name"
  $# show ip domain-name

  IP domain lookup:       Enabled
  IP Host.Domain name:    <dominio local>

La lista de servidores DNS usados por la controladora se configuran con el comando `ip name-server`_. El comando puede repetirse varias veces para configurar múltiples servidores de nombres::

  $# show run | include "ip name-server"
  Building configuration...
  ip name-server 8.8.8.8
  ip name-server 8.8.4.4

Sincronización NTP
------------------

La zona horaria se configura con `clock timezone`_ *<nombre zona horaria> <offset respecto a UTC>*::

  $# Si no está configurada, la zona horaria por defecto es UTC +0
  $# show run | include "clock timezone"
  Building configuration...
  clock timezone CET +1

  $# show clock timezone
  
  clock timezone CET +1

El ajuste automático de horario de verano se habilita con `clock summer-time`_ *<nombre zona> recurring <fecha comienzo cambio> <fecha fin cambio> <offset utc>*. Las fechas de comienzo y fin del cambio se pueden especificar como *[first|last] <dia de la semana> <mes> <hora>*, por ejemplo *last sunday april 02:00*, o *last sunday october 02:00*::

  $# Si no está configurado, no hay horario de verano.
  $# show run | include "clock summer-time"
  Building configuration...
  clock summer-time CEST last sunday april 02:00 last sunday october 02:00 02

  $# show clock summer-time
  
  clock summer-time CEST last sunday april 02:00 last sunday october 02:00 02

La lista de servidores NTP con los que la controladora se sincronizará se configura con el comando `ntp server`_ *<direccion IP> [iburst] [key <key-id>]* (puede repetirse varias veces para incluir más de un servidor)::

  $# show run | include "ntp server"
  Building configuration...
  ntp server <IP o FQDN del servidor NTP>

Si el servidor NTP requiere autenticación, es necesario:

- Activar autenticación NTP con la orden `ntp authentication`_.
- Definir una clave de autenticación asociada a un *key-ID*, con el comando `ntp authentication-key`_ *<key-ID> md5 <hash MD5 de la clave>*.
- Habilitar la clave como confiable con el parámetro `ntp trusted-key`_ <ID de la clave>
- Incluir el parámetro *<key-ID>* al configurar el servidor con la orden `ntp server`_ *key <key-ID>*

.. code: bash

  # Si el comando no está configurado, no se usa autenticacion NTP
  $# show run | include "ntp authentication"
  Building configuration...
  ntp authentication

  $# show run | include "ntp authentication-key" 
  Building Configuration...
  ntp authentication-key <key-ID> md5 ********

  $# show run | include "ntp trusted-key"
  Building configuration...
  ntp trusted-key <key-ID>

  $# show run | include "ntp servers"
  Building configuration...
  ntp server <IP o FQDN del servidor NTP> key <key-ID>

El estado actual de la configuración de autenticación puede comprobarse con `show ntp status`_, y las claves NTP definidas, con `show ntp authentication-keys`_::

  $# show ntp authentication-keys

  Key Id       md5 secret
  --------     ----------
  <key-ID>     ********
  
  $# show ntp status

  Authentication:         enabled

No se puede marcar un servidor como preferente; la controladora elige el más adecuado en función del stratum y el retardo. La lista de servidores con los que ha sincronizado se puede obtener con el comando `show ntp servers`_ *[brief]*. El servidor seleccionado estará marcado con un "**\***"::

  $# show ntp servers
  
  NTP Server Table Entries
  ------------------------

  Flags:     * Selected for synchronization
             + Included in the final selection set
             # Selected for synchronization but distance exceeds maximum
             - Discarded by the clustering algorithmn
             = mode is client

    remote                                  local                                    st   poll   reach    delay     offset      disp
  =========================================================================================================================================
  *hora.rediris.es                          <ip de la controladora>                   1   64     367    0.00371    -0.000063    0.07468

El tiempo durante el cual la controladora mantiene en caché la resolución DNS para el nombre de los servidores RADIUS configurados con su FQDN es ajustable mediante la orden `aaa dns-query-interval`_ *<minutos>*::

  # Si no está configurado, el intervalo por defecto es 15 minutos
  $# show run | include "aaa dns-query-interval"
  Building configuration...

  # Se puede consultar el valor de este parametro con "show aaa dns-query-interval"   
  $# show aaa dns-query-internal
  
  DNS Query Interval  15 minutes  

La controladora puede proporcionar a su vez servicio NTP a dispositivos conectados a algunas de sus VLANs. El servicio NTP puede habilitarse o deshabilitarse con la orden *[no]* `ntp standalone`_ *vlan-range <lista de vlans>*::

  #$ Si no está configurado, la controladora no actua de servidor NTP
  show run | include "ntp standalone"
  Building configuration...
  ntp standalone vlan-range <lista de vlans>

Logging
-------

Las controladoras permiten enviar el log a un servidor syslog externo utilizando el puerto UDP 514. Los servidores a los que la controladora enviará el log se configuran con el comando `logging`_ *<ip address>*.

Los logs que genera la controladora se agrupan en *categorías*, y estos a su vez en *subcategorías* y *procesos*. Por cada categoría / subcategoría / proceso, es posible especificar el nivel de *severidad* mínimo.

Los mensajes sólo se enviarán al servidor si igualan o superan el nivel de severidad. La lista completa de severidades, categorías y subcategorías puede consultarse en la documentación del comando `logging level`_.

- La facility que usará la controladora se puede configurar a nivel global con el comando `logging facility`_ *<local0|local1|...|local7>*. 
- Las categorías y subcategorías se habilitan a nivel global con el comando `logging level`_ *<nivel> <categoria> [subcat <subcategoria>] [process <proceso>]*

.. code: bash

  # Si no está explícitamente configurada, la facility por defecto es "local0"
  $# show run | include "logging facility"
  Building configuration...
  logging facility local7

  # Ejemplo de configuración de logging en una controladora particular.
  $# show run | logging level
  logging level debugging security process authmgr
  logging level debugging security process crypto
  logging level warnings security subcat ids
  logging level warnings security subcat ids-ap
  logging level debugging security process crypto subcat ike
  logging level debugging system process bocmgr
  logging level debugging user
  logging level informational user process aaa subcat radius

La facility y niveles configurados a nivel global se listan con los comandos `show logging`_ *facility* y `show logging`_ *level verbose*::

  $# show logging facility

  Remote Logging Facility is local7

  $# show logging level verbose

  LOGGING LEVELS
  --------------
  Facility  Level          Sub Category  Process
  --------  -----          ------------  -------
  arm       warnings       N/A           N/A
  network   warnings       N/A           N/A
  security  warnings       N/A           N/A
  security  debugging      N/A           authmgr
  security  debugging      N/A           crypto
  security  warnings       ids           N/A
  security  warnings       ids-ap        N/A
  security  debugging      ike           crypto
  system    warnings       N/A           N/A
  system    debugging      N/A           bocmgr
  user      debugging      N/A           N/A
  user      informational  radius        aaa
  wireless  warnings       N/A           N/A
  
Los servidores de logging se configuran con el comando `logging`_ *<servidor de syslog>*, que permite los siguientes parámetros para cada servidor:

============================ ============================================== =================================================
Opcion                       Propósito                                      Valor por defecto
============================ ============================================== =================================================
facility <local0|...|local7> Facility para este servidor particular.        Valor global establecido por `logging facility`_.
level <nivel>                Nivel mínimo de severidad para este servidor.  Valor global establecido por `logging level`_.
type <categoria>             Categoría de eventos a enviar a este servidor. Todas las categorías activas. 
                             Puede repetirse la orden varias veces, para
                             incluir varias categorias distintas.
format [cef]                 Activar formato de log CEF ArcSight            No habilitado.
bsd-standard                 Usar formato BSD (RFC 3164)                    No habilitado.
============================ ============================================== =================================================

Los servidores de logging configurados, y sus parámetros, pueden listarse con `show logging`_ *server*::

  # La lista de servidores de logging se puede recuperar con "show logging server"
  $# show run | include logging
  Building configuration...
  # ... lineas omitidas
  logging 10.100.1.30 facility local2 type user

  $# show logging server

  Remote Server: 10.100.10.30

  FACILITY MAPPING TABLE
  ----------------------
  local-facility  severity  remote-facility  CEF Format  BSD RFC 3164 Compliance
  --------------  --------  ---------------  ----------  -----------------------
  user            All       local2           Disabled    Disabled

SNMP
----

Las controladoras soportan SNMP v1, v2c y v3. La **versión** de SNMP **no es configurable**. Por defecto, la controladora responde a peticiones en cualquier versión. Sólo está disponible acceso SNMP de **lectura** (no escritura). Las configuraciones relacionadas con SNMP que soporta la controladora son:

.. list-table::
   :header-rows: 1

   * - Configuración
     - Propósito
     - Comando "show"
   * - `hostname`_ *<nombre de host>*
     - Hostname SNMP
     - `show hostname`_
   * - `syscontact`_ *<contacto>*
     - Contacto SNMP
     - `show syscontact`_
   * - `syslocation`_ *<ubicacion>*
     - Ubicación SNMP
     - `show syslocation`_
   * - `snmp-server`_ *community <community v2c>*
     - Community SNMP (v2c)
     - `show snmp community`_
   * - `snmp-server`_ *engine-id <engine SNMPv3>*
     - Engine ID SNMPv3
     - `show snmp engine`_
   * - `snmp-server`_ *enable trap*
     - Habilitar o deshabilitar el envío de traps.
     - N/A
   * - `snmp-server`_ *trap [enable|disable] <trap>*
     - Activar o desactivar el envío de un trap particular.
     - `show snmp trap-list`_
   * - `snmp-server`_ *host ipaddr version [1|2c|3] <direccion IP> [udp-port <puerto UDP>]*
     - Dirección y puerto receptor traps                       
     - N/A
   * - `snmp-server`_ *trap source <dirección IP>*
     - IP origen para el envío de los traps
     - N/A
   * - `snmp-server`_ *user name <password> [auth-prot {md5|sha} priv-prot DES <password>]*
     - Credenciales de usuario (SNMPv3)
     - `show snmp user-table`_

La lista completa de traps disponibles debe obtenerse desde la controladora, ya que depende de la versión particular de software y sus MIBs. El comando para enumerar los traps disponibles es `show snmp trap-list`_. 

Los parámetros no tienen valores por defecto, si no aparecen en la configuración entonces la funcionalidad correspondiente no está habilitada. Puede comprobarse la configuración de los parámetros relacionados con SNMP mediante los comandos `show snmp community`_, `show snmp trap-host`_, `show snmp user-table`_::

  $# show hostname

  Hostname is ArubaMadrid

  $# show sycontact

  Syscontact is not configured

  $# show syslocation

  Location is not configured

  $# show snmp community 

  SNMP COMMUNITIES
  ----------------
  COMMUNITY   ACCESS     VERSION
  ---------   ------     -------
  ****        READ_ONLY  V1, V2c
  ****        READ_ONLY  V1, V2c

  $# show snmp engine-id

  SNMP engine ID: 000039e7000000a1c34db92d (Factory Default)

  $# show snmp trap-host

  SNMP TRAP HOSTS
  ---------------
  HOST     VERSION  SECURITY NAME  PORT  TYPE  TIMEOUT  RETRY
  ----     -------  -------------  ----  ----  -------  -----
  10.1.2.3 v2c      *****          161

  $# show snmp trap-list

  SNMP TRAP LIST
  --------------
  TRAP-NAME                                  CONFIGURABLE  ENABLE-STATE
  ---------                                  ------------  ------------
  authenticationFailure                      Yes           Enabled
  coldStart                                  Yes           Enabled
  linkDown                                   Yes           Enabled
  linkUp                                     Yes           Enabled
  # ... lineas omitidas

  $# show snmp user-table

  SNMP USER TABLE
  ---------------
  USER       AUTHPROTOCOL  PRIVACYPROTOCOL  FLAGS
  ----       ------------  ---------------  -----
  AirWave    SHA           DES              

Interfaces
==========

.. _proposito_interfaces:

Propósito
---------

Las interfaces físicas de la controladora, a efectos de seguridad, se clasifican en dos tipos:

- **untrusted**: Típicamente son las interfaces de acceso. A todos los dispositivos conectados a estas interfaces (a todas las MACs aprendidas) se les asigna un **rol**.

  El modo de asignar el rol al usuario es flexible: pueden usarse reglas de derivación por algunos atributos del endpoint (VLAN , IP, MAC), o puede usarse autenticación (por MAC, 802.1X, portal cautivo...).

  En cualquier caso, el rol es lo que determina las reglas de firewall que aplican al dispositivo. La naturaleza del rol es la de una lista blanca: Todo lo que no esté explícitamente permitido por el rol, está implícitamente denegado.

- **trusted**: Típicamente son las interfaces de infraestructura, que conectan al datacenter, la WAN o Internet. A los dispositivos conectados a estas interfaces no se les asignan roles. Las reglas de firewall que se les aplican en este caso son las configuradas en la ACL de la interfaz, si existe.

  A su vez, una interfaz *trusted* puede tener una o varias VLANs *trusted*, si está en modo 802.1Q. Si no hay una ACL configurada en la interfaz o en la VLAN, todo el tráfico está autorizado.

Como se introduce en el apartado de :ref:`control_acceso_acl`, las reglas de hardening se aplican a las interfaces *untrusted*. En las interfaces *trusted* aplican los roles que se hayan definido para cada tipo de usuario o dispositivo.

Para enumerar las interfaces activas y sus propiedades, se usan los comandos `show port`_ y `show interface`_ *gigabit <slot>/<modulo>/<puerto>*::

  # Enumeración de las interfaces de la controladora.
  # Los puertos "PC" son PortChannels
  $# show port status

  Port Status
  -----------
  Slot-Port  PortType  AdminState  OperState  PoE  Trusted  SpanningTree  PortMode  Speed     Duplex  SecurityError
  ---------  --------  ----------  ---------  ---  -------  ------------  --------  -----     ------  -------------
  0/0/0      GE        Enabled     Up         N/A  Yes      Disabled      Trunk     1 Gbps    Full    No
  0/0/1      GE        Enabled     Up         N/A  Yes      Disabled      Access    100 Mbps  Full    No
  0/0/2      GE        Enabled     Down       N/A  Yes      Disabled      Access    Auto      Auto    No
  0/0/3      GE        Enabled     Down       N/A  Yes      Disabled      Access    Auto      Auto    No
  0/0/4      GE        Enabled     Down       N/A  N/A      N/A           PC7       Auto      Auto    No
  0/0/5      GE        Enabled     Down       N/A  N/A      N/A           PC7       Auto      Auto    No
  PC7        PC        Enabled     Down       N/A  Yes      Disabled      Access    N/A       N/A     No

  # Para averiguar los puertos trusted:
  $# show port trusted 

  GE <slot>/<modulo>/<puerto1>
  GE <slot>/<modulo>/<puerto2>
  ...

  # Para enumerar las VLANs trusted en esos puertos
  $# show interface gigabit <slot>/<modulo>/<puerto1> trusted-vlan

  Name:  GE<slot>/<modulo>/<puerto1>
  Trusted Vlan(s)
  1-4094

  # Para averiguar cuales de las trusted VLANs estan activas en el puerto:
  # show interfaces gigabit <slot>/<modulo>/<puerto> switchport
  #
  # Ejemplo puerto en "Operational Mode: Access": Una sola VLAN
  # La VLAN a proteger es la identifica en "Access Mode VLAN:"
  $# show interfaces gigabit 0/0/13 switchport

  Name:  GE0/0/1
  Switchport:  Enabled
  Administrative mode:  static access 
  Operational mode:  static access 
  Administrative Trunking Encapsulation:  dot1q
  Operational Trunking Encapsulation:  dot1q
  Access Mode VLAN: 30 (VLAN0030)
  Trunking Native Mode VLAN: 1 (Default)
  Trunking Vlans Enabled: NONE 
  Trunking Vlans Active: NONE 

  # Ejemplo puerto en "Operational mode: trunk" (802.1Q)
  # Varias VLANs a proteger: Todas las de "Trunking VLANs Active:"
  $# show interfaces gigabit 0/0/0 switchport

  Name:  GE0/0/0
  Switchport:  Enabled
  Administrative mode:  trunk
  Operational mode:  trunk
  Administrative Trunking Encapsulation:  dot1q
  Operational Trunking Encapsulation:  dot1q
  Access Mode VLAN: 0 ((Inactive))
  Trunking Native Mode VLAN: 255 (VLAN0255)
  Trunking Vlans Enabled: 1-998,1000-4094
  Trunking Vlans Active: 1-12,99-103,211,254-255

Desactivación
-------------

Las interfaces que no estén en uso pueden desactivarse con un *shutdown* estándar dentro de la configuración de la interfaz::

  # Comprobacion de estado de interfaz en show running
  $# show running | begin "<slot>/<modulo>/<puerto>"
  Building configuration...
  interface gigabitethernet <slot>/<modulo>/<puerto>
    description "GE0/0/3"
    shutdown
    trusted
    trusted vlan 1-4094
  !
  
  # Comprobacion mediante show port status: admin state = Disabled
  $# show port status

  Port Status
  -----------
  Slot-Port  PortType  AdminState  OperState  PoE  Trusted  SpanningTree  PortMode  Speed     Duplex  SecurityError
  ---------  --------  ----------  ---------  ---  -------  ------------  --------  -----     ------  -------------
  # ... lineas omitidas
  0/0/3      GE        Disabled    Down       N/A  Yes      Disabled      Access    Auto      Auto    No
  # ... lineas omitida

Etiquetado
----------

A cada interfaz puede asignársele un nombre descriptivo con el parámetro *description* dentro de la configuración de la interfaz::

  # Comprobacion de descripción de interfaz en show running
  $# show running | begin "<slot>/<modulo>/<puerto>"
  Building configuration...
  interface gigabitethernet <slot>/<modulo>/<puerto>
    description "pruebas shutdown"
    shutdown
    trusted
    trusted vlan 1-4094
  !
  
  # Comprobacion mediante show interface
  $# show interface gigabit <slot>/<mod>/<puerto>
  # ... lineas omitidas
  Description: pruebas shutdown (Fiber Connector)
  # ... lineas omitidas

.. _modos de acceso: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/Chapters/CLI_Access.htm
.. _copy: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/copy.htm
.. _delete: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/delete.htm
.. _telnet: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/telnet_enable.htm
.. _roles de usuario administrador: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/mgmt-user.htm
.. _mgmt-user: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/mgmt-user.htm
.. _aaa password-policy mgmt: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/aaa_password_policy_mgmt.htm
.. _show aaa password-policy mgmt: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/show_aaa_password_policy.htm
.. _server groups: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm/Content/ArubaFrameStyles/1CommandList/aaa_server_group.htm
.. _aaa authentication mgmt: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/aaa_authentication_mgmt.htm
.. _enable bypass: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/enable_bypass.htm
.. _tiempo máximo de sesión web: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/Management_Utilities/WebUI_Session_Timer.htm
.. _show web-server: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/showwebserver.htm
.. _loginsession: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/loginsession.htm
.. _show ap system profile: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/show_ap_system_profile.htm
.. _web-server profile: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/web-server.htm
.. _show web-server profile: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/showwebserver.htm
.. _ip access-list session: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/ip_access_list_session.htm
.. _netservice: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/netservice.htm
.. _netdestination: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/netdestination.htm
.. _ip access-group: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/interface_fastethernet__.htm
.. _ip access-list session: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/ip_access_list_session.htm
.. _banner motd: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/banner_motd.htm
.. _ip domain lookup: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/ip_domain_lookup.htm
.. _show ip domain-name: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/ip_domain_lookup.htm
.. _ip name-server: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/ip_name_server.htm
.. _clock timezone: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/clock_timezone.htm
.. _clock summer-time: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/clock_summer_time.htm
.. _show clock: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/show_clock.htm
.. _ntp authentication: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/ntp_authentication.htm
.. _ntp standalone: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/ntp_standalone.htm
.. _ntp server: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/ntp_server.htm
.. _aaa dns-query-interval: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/aaa_dns_query_interval.htm
.. _show ntp servers: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/show_ntp_servers.htm
.. _ntp trusted-key: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/ntp_trusted_key.htm
.. _ntp authentication-key: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/ntp_authentication_key.htm
.. _ntp authenticate: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/ntp_authenticate.htm
.. _snmp-server: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/snmp_server.htm
.. _show ntp status: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/show_ntp_status.htm
.. _show ntp authentication-keys: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/show_ntp_authentication_keys.htm
.. _logging level: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/logging_level.htm
.. _logging level: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/logging_level.htm
.. _logging facility: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/logging_facility.htm
.. _logging: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/logging.htm
.. _show logging: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/show_logging.htm
.. _hostname: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/hostname.htm
.. _syscontact: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/syscontact.htm
.. _syslocation: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/syslocation.htm
.. _snmmp-server: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Content/ArubaFrameStyles/1CommandList/snmp_server.htm
.. _show hostname: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/show_syslocation.htm
.. _show syscontact: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/show_snmp_syscontact.htm
.. _show syslocation: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/show_syslocation.htm
.. _show snmp engine: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/show_snmp_engine_id.htm
.. _show snmp community: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/show_snmp_community.htm
.. _show snmp trap-host: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/show_snmp_trap_host.htm
.. _show snmp trap-list: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/show_snmp_trap_list.htm
.. _show snmp user-table: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/show_snmp_user_table.htm
.. _firewall: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/firewall.htm
.. _show interface: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/show_interface.htm
.. _show port: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/show_port.htm
.. _show firewall-cp: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/show_firewall_cp.htm
.. _show firewall: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/show_firewall.htm
.. _show cp-bwcontracts: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/show_cp_bwcontracts.htm
.. _firewall cp: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/firewall_cp.htm
.. _firewall cp-bandwidth-contract: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/firewall_cp_bandwidth_contract.htm
.. _cp-bandwidth-contract: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm#ArubaFrameStyles/1CommandList/cp_bandwidth_contract.htm

.. rubric:: Footnotes

.. [#omision_firewalls] Por simplicidad, se han omitido en el dibujo los firewalls / NATs perimetrales y entre zonas (DMZs).
.. [#tiempo_inactividad_web] El comando *user-absolute-session-timeout* está disponible desde la versión de ArubaOS 6.4.4.0.
.. [#licencia_PEFNG] Esta funcionalidad requiere de la licencia PEFNG.
.. [#diffie_hellman_2_vulnerable] Ver https://weakdh.org/imperfect-forward-secrecy-ccs15.pdf.
