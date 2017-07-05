#########################
Hardening de switches HPE
#########################

.. highlight:: bash

***************
Configuraciones
***************

Introducción
============

Este documento no es un manual de configuración ni sustituye a las guías de usuario. Su objetivo es servir al equipo de seguridad de la empresa como una referencia para:

- Identificar las funcionalidades de hardening que soportan los equipos,
- Expresar las políticas de seguridad en forma de parámetros de configuración para esas funcionalidades,
- Verificar de forma automática que esas configuraciones están aplicadas.

Acceso a la CLI
---------------

Para tener acceso remoto a la CLI del switch, es necesario utilizar un cliente telnet o SSH v2. Por defecto, la CLI soporta dos roles de usuario, **manager** y **operator**, asociados al usuario que inicia sesión.

  - El rol *manager* es el equivalente al modo *enable* en otros equipos. Proporciona acceso completo de lectura / escritura y es el **rol por defecto**.
  - El rol *operator* es el rol de sólo lectura / acceso limitado, que permite acceder únicamente a comandos show, contadores, y herramientas sencillas de troubleshooting (ping, traceroute, etc).

El switch incluye dos usuarios predefinidos, *manager* y *operator*, asociados a los respectivos roles anteriores, y **sin contraseña**. Los nombres de usuario y passwords predefinidos se pueden cambiar, así como añadir nuevos usuarios y nuevos roles. Estas funcionalidades se detallan en el apartado :ref:`acceso_administrativo`.

Copia de configuración
----------------------

La configuración local del switch puede enviarse a un servidor SFTP o TFTP externo, mediante el comando *copy*::

  # Copia de configuración activa a servidor SFTP.
  # Este comando solicita el password del usuario SFTP interactivamente.
  $# copy running-config sftp: user <usuario> <host> <filename>

Credenciales en la configuración
--------------------------------

Las credenciales almacenadas en el switch (passwords de usuario, secretos radius, communities SNMP, etc) pueden incluirse o no al hacer un volcado de la configuración. Si se incluyen, pueden listarse en texto plano o cifradas. El compartimiento es configurable mediante dos comandos.

===================== ==========================================
Comando               Efecto
===================== ==========================================
include-credentials   Incluye las credenciales al mostrar la
                      configuración, exportarla o copiarla.
encrypt-credentials   Cifra las credenciales mostradas en la
                      configuración
===================== ==========================================

A su vez, *include-credentials* puede estar activo pero no habilitado, porque haya estado habilitado antes y se haya desactivado sin haber grabado la configuración o sobreescrito las credenciales.

En función del estado de estos comandos, el comportamiento del switch es distinto y se resume en la siguiente tabla:

.. image:: _static/include-credentials.*

*encrypt-credentials* utiliza una clave secreta que por defecto es igual para todos los switches, para facilitar el backup y el copy-paste de configuración. La clave puede cambiarse, pero en ese caso debería cambiarse en todos los switches susceptibles de ser gestionados por las mismas herramientas.

El estado de *include-credentials* y *encrypt-credentials* puede comprobarse con los comandos::

  $# show include-credentials

  Stored in Configuration         : Yes
  Enabled in Active Configuration : Yes

  $# show encrypt-credentials

  Encryption    : Disabled
  Pre-shared Key: none

***********************
Mecanismos de hardening
***********************

.. _acceso_administrativo:

Acceso administrativo
=====================

Los switches tienen tres interfaces de gestión: consola local, consola remota sobre telnet/SSH, e interfaz web sobre HTTP/HTTPS. Por defecto, están habilitados los protocolos inseguros (telnet, http). Los protocolos inseguros pueden reemplazarse por sus versiones seguras (SSH, HTTPS) (`access_security_guide`_)::

  # La presencia de este comando indica que se ha desactivado telnet
  $# show running-config | include telnet-server
  no telnet-server

  # SSH está inhabilitado por defecto con el comando "no ip ssh".
  # Cuando se activa ssh, dicho comando desaparece de la configuración.
  # Para comprobar el estado de SSH, puede usarse "show ip ssh":
  $# show ip ssh

  SSH Enabled     : Yes                 Secure Copy Enabled : No
  TCP Port Number : 22                  Timeout (sec)       : 120
  Host Key Type   : RSA                 Host Key/Curve Size : 2048

  Ciphers : aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,
            aes192-cbc,aes128-ctr,aes128-cbc,3des-cbc
  MACs    : hmac-sha1-96,hmac-md5,hmac-sha1,hmac-md5-96

  Ses Type     | Source IP                                      Port
  --- -------- + ---------------------------------------------- -----
  1   console  |
  2   inactive |
  3   inactive |
  4   inactive |
  5   inactive |
  6   inactive |
  7   inactive |

  # La presencia de este comando indica que se ha desactivado HTTP (puerto 80)
  $# show running-config | include web-management
  no web-management

  # La presencia de estos comandos indica que se ha habilitado la
  # interfaz web HTTPS (puerto 443)
  $# show running-config | include web-management
  no web-management
  web-management ssl

  # El estado de la interfaz web puede consultarse con "show web-management"
  $# show web-management

  Web Management - Server Configuration

  HTTP Access    : Disabled
  HTTPS Access   : Enabled
  SSL Port       : 443
  Idle Timeout   : 600 seconds
  Management URL : http://h17007.www1.hpe.com/device_help
  Support URL    : https://www.hpe.com/us/en/networking.html
  User Interface : Improved

.. _roles_grupos:

Roles y grupos
--------------

En cualquiera de las interfaces de gestión, los switches reconocen dos roles por defecto:

===================== =================================================
rol                   Privilegios
===================== =================================================
manager               Acceso total. **Rol por defecto**.
operator              Acceso limitado (estado del equipo, contadores,
                      comandos sencillos de troubleshooting como
                      ping, tracert, etc)
===================== =================================================

Los dos roles por defecto existen en todos los switches y no necesitan ni admiten configuración de permisos (no se pueden modificar los permisos asociados a cada rol).

Además de estos *roles* predefinidos, el switch soporta hasta 64 **grupos** configurables. Los grupos son la base del mecanismo de **RBAC** (*Role Based Access Control*) soportado por estos switches, que permite limitar los comandos a los que tiene acceso un usuario.

Cada grupo permite definir una lista de *reglas* que controlan el acceso a diferentes apartados de la configuración del switch:

==================================== ===============================
Alcance                              Ejemplos de reglas del grupo
==================================== ===============================
Comandos particulares                command:ping
                                     command:configure
                                     command:interface;shutdown
Cualquier acción sobre VLANs         policy:vlan:100
                                     policy:vlan:101-103
Cualquier acción sobre interfaces    policy:interface:5
                                     policy:interface:5-6,9-11
Bloques completos de funcionalidades feature:rwx:ospf
                                     feature:r:radius
==================================== ===============================

Cuando RBAC está activo, cada usuario (excepto los predefinidos) tiene asociado uno de estos grupos, que determina qué está autorizado a hacer en el switch. La información detallada sobre las políticas posibles debe consultarse en el manual `access_security_guide`_, en el capítulo dedicado a RBAC.

El switch incluye 16 grupos **preconfigurados** para usar con RBAC, *Level-0* hasta *Level-15*. Los permisos asociados a cada grupo son modificables, y pueden listarse con el comando *show authorization group*::

  $# show authorization group

  Local Management Groups - Authorization Information


  Group Name            : default-security-group
  Group Privilege Level : 19

  Users
  ----------------

  Seq. Num.  | Permission Rule Expression                            Log
  ---------- + ---------- ------------------------------------------ -------
  1          | Permit     security-log                               Disable

  Group Name            : Level-0
  Group Privilege Level : 20

  Users
  ----------------

  Seq. Num.  | Permission Rule Expression                            Log
  ---------- + ---------- ------------------------------------------ -------
  999        | Permit     command:ping *                             Disable
  1000       | Permit     command:ping6 *                            Disable
  1001       | Permit     command:traceroute *                       Disable
  1002       | Permit     command:traceroute6 *                      Disable
  1003       | Permit     command:ssh *                              Disable
  1004       | Permit     command:telnet *                           Disable
  1005       | Deny       .*                                         Disable

  Group Name            : Level-1
  Group Privilege Level : 21

  # Resto de salida omitido...

Sin embargo, RBAC **no está activo por defecto**. Estará activo si existe el siguiente comando en la configuración (`access_security_guide`_)::

  # El comando "aaa authorization commands" indica que RBAC está activo en el switch.
  # Lo habitual es que esté configurado como "auto", para que use el mismo
  # mecanismo de autorización que se haya usado para la autenticación:
  #
  # - Autenticación local: grupos locales.
  # - Autenticación por Radius: grupo asignado por Radius.
  # - Autenticación por TACACS: comandos autorizados por TACACS.
  #
  $# show running-config | include "authorization commands"
  aaa authorization commands auto

  # Puede comprobarse el estado de RBAC con
  $# show authorization

  Status and Counters - Authorization Information

  Access Level Requiring Authorization : All

  Type     | Method
  -------- + ------
  Commands | Auto

Cuando un usuario inicia sesión, se le asigna un rol y, si RBAC está activo, un grupo. Tanto el estado de RBAC como el rol y el grupo al que pertenece el usuario determinan sus permisos:

  - Si el usuario es uno de los :ref:`usuarios_predefinidos`,

    - Puede acceder por línea de comandos o web.
    - Tiene el nivel de acceso que corresponda a su rol predefinido, *manager* u *operator*.
    - No tiene grupo, no está limitado por RBAC.

  - Si el usuario es uno de los :ref:`usuarios_locales`,

    - Puede acceder por línea de comandos - no por web.
    - Tiene el rol manager.
    - Si RBAC está activo, tiene un grupo asignado al usuario en la configuración, que limita los comandos que puede utilizar (a pesar de tener rol de manager).

  - En el caso de :ref:`usuarios_remotos`, son los atributos RADIUS los que determinan el rol y el grupo.

    - Si RBAC no está activo, las decisiones de acceso se basan sólo en el rol (*operator* / *manager*).
    - Si RBAC está activo, las decisiones se basan en rol y grupo, igual que para los usuarios locales.
    - Si el rol asignado es *operator*, el grupo no aplica.

.. _usuarios_predefinidos:

Usuarios predefinidos
---------------------

Por cada uno de los roles predefinidos, *operator* y *manager*, existe en el switch un único usuario predefinido. Estos usuarios predefinidos tienen acceso tanto a la línea de comandos como a la interfaz web. Por defecto, son:

  - usuario **manager**, asociado al rol *manager* y sin contraseña inicial.
  - usuario **operator**, asociado al rol *operator* y sin contraseña inicial.

El nombre del usuario asociado a cada rol predefinido, y su contraseña, se modifican con el comando de configuración *password*::

  # Lista de usuarios de gestión en la configuración activa
  $# show running-config | include password
  password operator user-name "operator" sha1 "ca5f9f6e41b239d8a99b700f**************"
  password manager user-name "manager" sha1 "ca5f9f6e41b239d8a99b700f8**************""

Si está activo el hash de contraseñas SHA-256, el formato del comando cambia ligeramente::

  $# show running-config | include password
  password operator user-name "operator" sha256 "d847a0a3e56ed1f2badea6afc81f024b5c76954057dbfd3684************"
  password manager user-name "admin" sha256 "d847a0a3e56ed1f2badea6afc81f024b5c76954057dbfd36842dcd************"
  password non-plaintext-sha256

El hash de contraseñas SHA256 ***no es compatible** con las :ref:`politicas_complejidad`, ni tampoco se soporta en switches con versiones de software anteriores a 16.02.0018.

Los roles y usuarios predefinidos no pueden borrarse. Si se borra el password de uno de estos usuarios, equivale a permitir acceso sin credenciales desde la consola a ese usuario.

Por este motivo se aconseja:

  - Cambiar los nombres de usuario por defecto
  - Asignar un password a ambos usuarios / roles.

.. _usuarios_locales:

Usuarios locales
----------------

Además de los usuarios predefinidos para los roles *manager* y *operator*, el switch admite crear *usuarios locales*. Estos usuarios sólo tienen acceso a la línea de comandos.

Cada usuario local puede tener varios atributos:

============== ===========================================================
Atributo       Descripción
============== ===========================================================
group          Grupo al que pertenece el usuario.
min-pwd-length Longitud minima del password, particular para este usuario.
aging-period   Caducidad de la cuenta, particular para este usuario.
============== ===========================================================

Los usuarios locales siempre tienen asignado un grupo (ver :ref:`roles_grupos`), aunque las restricciones asociadas el grupo sólo aplican si RBAC está activo. En otro caso, lo que aplica es el rol del usuario, que siempre es *manager*.

Las políticas de complejidad y expiración de passwords configuradas en el usuario complementan a las :ref:`politicas_complejidad` globales.

Los usuarios locales configurados en el switch, y sus políticas, se pueden extraer de la configuración::

  show running-config | include "authentication local-user"
  aaa authentication local-user "test" group "Level-1" password sha256 "d847a0a3e56ed1f2badea6afc81f024b5c76954057dbfd36842dcd**********"
  aaa authentication local-user "priv" group "Level-15" password sha256 "d847a0a3e56ed1f2badea6afc81f024b5c76954057dbfd36842dc**********"

.. _politicas_complejidad:

Políticas de complejidad
------------------------

El switch permite definir múltiples parámetros para la política de contraseñas de usuarios locales:

=========================================== ================================================================
Parámetro                                   Descripción
=========================================== ================================================================
password configuration-control              Habilita el uso de medidas de password-complexity y composition.
                                            Debe estar activo para que el resto de comandos funcione.
password complexity repeat-char-check       Prohibe más de tres caracteres repetidos.
password complexity repeat-password-check   Prohibe passwords repetidos.
password complexity user-name-check         Prohibe la inclusión del nombre de usuario o su inverso.
password complexity all                     Habilita todos los checks anteriores.
password composition lowercase              Número mínimo de minúsuculas, 2 - 15.
password composition uppercase              Número mínimo de mayúsculas, 2 - 15.
password composition specialcharacter       Número mínimo de caracteres especiales, 2 - 15.
password composition number                 Número mínimo de dígitos, 2 - 15.
password minimum-length                     Longitud mínima del password. 15 - 64 cuando complexity está
                                            habilitado, 0-64 en otro caso.
password configuration                      Habilita el uso de medidas de password aging, logon y history.
                                            Debe estar activo para que el resto de comandos funcione.
password configuration aging                Habilita la comprobación de caducidad de passwords.
password configuration aging-period         Caducidad aplicada a los passwords, 90 días por defecto.
password configuration history              Habilita almacenar un histórico de passwords anteriores.
password configuration history-record       Tamaño del histórico de passwords anteriores
password configuration update-interval-time Tiempo mínimo entre cambios de password.
password configuration alert-before-expiry  Configura un periodo de preaviso al usuario antes de que caduque
                                            su contraseña.
password configuration expired-user-login   Configura un periodo de gracia después de la caducidad de la
                                            contraseña, y un número máximo de intentos de autenticación
                                            durante ese periodo de gracia.
=========================================== ================================================================

La referencia completa de estos comandos puede consultarse en la Access Security Guide de la versión correspondiente (`access_security_guide`_). El estado de la configuración puede obtenerse con el comando *show password-configuration*::

  $# show password-configuration
  Global password control configuration

  Password control                     : Disabled
  Password history                     : Disabled
  Number of history records            : 8
  Password aging                       : Disabled
  Aging time                           : 90 days
  Early notice on password expiration  : 7 days
  Minimum password update interval     : 24 hours
  Expired user login                   : 3 login attempts in 30 days
  Password minimum length              : 0
  User login details checking          : Enabled
  Password composition
           Lower case                  : 2 characters
           Upper case                  : 2 characters
           Special character           : 2 characters
           Number                      : 2 characters
  Repeat password checking             : Disabled
  Username checking                    : Disabled
  Repeat characters checking           : Disabled

.. _usuarios_remotos:

Usuarios remotos
----------------

La autenticación remota puede realizarse contra RADIUS, utilizando grupos ordenados de servidores de autenticación. Los switches soportan dos mecanismos de validación de credenciales por Radius:

  - PAP: Las credenciales del usuario van en texto plano dentro del paquete Radius.
  - EAP-MsCHAPv2: Se usa EAP-MsCHAPv2 para validar las credenciales del usuario sin necesidad de enviarlas en texto plano.

En caso de pérdida de conectividad con los servidores radius, se puede establecer un método secundario de autenticación:

  - local: autenticación contra :ref:`usuarios_locales`
  - none: sin método secundario de autenticación
  - authorized: acceso permitido sin nombre de usuario ni contraseña.

Pueden asignarse distintos mecanismos de autenticación primario y secundario en función de:

  - El protocolo de acceso: consola, telnet, ssh y web.
  - El nivel de acceso: login (shell no privilegiado) o enable (shell privilegiado)

La creación de los *server groups* está fuera del alcance de este documento. Los server-groups se asignan a cada protocolo y tipo en los comandos *aaa authentication [console|telnet|ssh|web] [login|enable] [radius|peap-mschapv2] server-group <nombre del server-group> [local|none|authorized]*::

  $# show running-config | include "aaa authentication"
  aaa authentication telnet login radius server-group "rad-group" local
  aaa authentication telnet enable radius server-group "rad-group" local
  aaa authentication web login peap-mschapv2 server-group "rad-group"
  aaa authentication web enable peap-mschapv2 server-group "rad-group"

  # La configuración de autenticación de los protocolos "Console",
  # "Telnet", "Webui" y "SSH" pueden consultarse con el comando:
  $# show authentication

  Status and Counters - Authentication Information

  Login Attempts : 3
  Lockout Delay : 0
  Respect Privilege : Disabled
  Bypass Username For Operator and Manager Access : Disabled

                 | Login       Login        Login
  Access Task    | Primary     Server Group Secondary
  -------------- + ----------- ------------ ----------
  Console        | Local                    None
  Telnet         | Radius      rad-group    Local
  Port-Access    | Local                    None
  Webui          | PeapRadius  rad-group    None
  SSH            | Local                    None
  Web-Auth       | ChapRadius  radius       None
  MAC-Auth       | ChapRadius  radius       None
  SNMP           | Local                    None
  Local-MAC-Auth | Local                    None

                 | Enable      Enable       Enable
  Access Task    | Primary     Server Group Secondary
  -------------- + ----------- ------------ ----------
  Console        | Local                    None
  Telnet         | Radius      rad-group    Local
  Webui          | PeapRadius  rad-group    None
  SSH            | Local                    None



El proceso de control de acceso es:

  - Las intentos de inicio de sesión se autentican contra el grupo de servidores definido para el protocolo correspondiente (consola, telnet, ssh, web) y el tipo de autenticación **login**. Radius devuelve un rol y, opcionalmente, un grupo.
  - Si está configurado "*Respect Privilege*" en el switch, y el usuario tiene rol *manager*, accede directamente al shell de manager. En otro caso, accede al shell de operador.
  - Desde el shell de operador, el usuario puede ejecutar **enable** para acceder al shell de manager.
  - Las credenciales de enable se autentican contra el grupo de servidores definidos para el protocolo correspondiente (consola, telnet, ssh, web) y tipo de  autenticación **enable**
  - Si el usuario tiene rol *manager*, accede al shell de manager. En otro caso, se rechaza el acceso.
  - Si está habilitado RBAC (ver ref:`roles_grupos`), aunque el usuario tenga rol de manager y esté en la shell de manager, las acciones que puede ejecutar están limitadas por el grupo asignado por el Radius.

::

  # Bloque de configuración que activa la autenticación por servidor remoto.
  $# show run | begin "aaa authentication mgmt"
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


  aaa authentication login privilege-mode

El servidor remoto debe asignar el rol del usuario administrador mediante una VSA reconocida (*Aruba-Admin-Role*). En caso contrario, el usuario adquiere el rol configurado con la opción *default-role*. Es aconsejable que ese rol por defecto sea **no-access**.

Si el repositorio de autenticación lo admite, es posible utilizar MsCHAPv2 para la autenticación remota, de forma que las credenciales de usuario no vayan en claro (PAP) en el mensaje RADIUS. Esta medida no es necesaria si se utiliza TACACS para la autenticación.

Para activar *mchapv2*, se utiliza la opción **mchapv2** del bloque de configuración *aaa authentication mgmt*::

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

Password recovery
-----------------

Los switches HPE-Aruba tienen dos mecanismos de password recovery:

- Mediante el botón "Clear" en el frontal (*Clear Password*). Este botón restablece las cuentas de los usuarios predefinidos (*manager*, *operator*) y les borra el password, lo que permite acceder a la consola sin contraseña, y manteniendo el resto de la configuración del equipo intacta.
- Mediante contraseñas de un sólo uso generadas por el TAC, a partir de la MAC del equipo (*Password Recovery*).

El estado de los mecanismos puede consultarse con *show front-panel security*::

  $# show front-panel-security
  Clear Password       - Enabled
    Reset-on-clear      - Disabled
  Factory Reset        - Enabled
  Password Recovery    - Enabled

La capacidad de restablecer las contraseñas de administrador tan sólo con el botón de Clear puede desactivarse con el comando:

  $(config)# no front-panel-security password-clear

Reintentos de login
-------------------

El switch permite definir un tiempo de bloquea durante el cual no se permite al usuario reintentar el login, después de haber fallado un número de veces consecutivas.

El número máximo de reintentos, y el tiempo de lockout, se definen a nivel global con los comandos *aaa authentication num-attempts [intentos]* y *aaa authentication lockout-delay [segundos]*::

  $# show run | include "aaa authentication"
  aaa authentication num-attempts 5
  aaa authentication lockout-delay 30
  # Resto de salida omitido...

  $# show authentication

  Login Attempts : 5
  Lockout Delay : 30
  # Resto de salida omitido...


Tiempo de inactividad
---------------------

El tiempo de inactividad de sesiones se establece globalmente con la orden *console idle-timeout [0-7200 segundos]*. Adicionalmente, es posible especificar un segundo tiempo de inactividad específico para la consola, con *console idle-timeout serial-usb [0-7200 segundos]*::

  $# show run | include "idle-timeout"

  console idle-timeout 900
  console idle-timeout serial-usb 1200

En ese caso, la configuración puede validarse mediante la orden *show console*::

  $# show console

  #... texto omitido
  Global Session Idle Timeout (sec) [0] : 900
  Serial/USB Console Idle Timeout (sec) [not set/900] : 1200

La interfaz web utiliza un tiempo de inactividad distinto configurable mediante la orden *web-management idle-timeout [120-7200 segundos]*, que tiene un valor por defecto de **600 segundos**. Puede validarse con la orden *show web-management*::

  $# show web-management

  Web Management - Server Configuration

    HTTP Access    : Enabled
    HTTPS Access   : Disabled
    Idle Timeout   : 600 seconds
    Management URL : http://h17007.www1.hpe.com/device_help
    Support URL    : http://www.arubanetworks.com/products/networking/
    User Interface : Improved
    Listen Mode    : data

Suites de cifrado
-----------------

El acceso por gestión a SSH admite diversas suites de cifrado y algoritmos de MAC. Las suites y MACs habiltadas pueden validarse con el comando *show ip ssh*::

  $# show ip ssh

  SSH Enabled     : Yes                 Secure Copy Enabled : No
  TCP Port Number : 22                  Timeout (sec)       : 120
  Host Key Type   : RSA                 Host Key/Curve Size : 2048

  Ciphers : aes256-ctr,aes256-cbc,rijndael-cbc@lysator.liu.se,aes192-ctr,
            aes192-cbc,aes128-ctr,aes128-cbc,3des-cbc
  MACs    : hmac-sha1-96,hmac-md5,hmac-sha1,hmac-md5-96

  # Resto de salida omitida...

Los ciphers y MACs particulares pueden deshabilitarse con los comandos *no ip ssh cipher [aes256-ctr|aes256-cbc|...]* y *no ip mac [hmac-sha1-96|hmac-md5|...]*. Por defecto, todos están habilitados.

Restricción de acceso a gestión
-------------------------------

Es posible limitar los rangos de direcciones IP desde los que se podrá acceder a los diferentes servicios de gestión del switch (ssh, web, snmp...). La restricción es granular, y para cada rango de IP se puede especificar:

- El nivel de privilegio (manager u operador) a que se autoriza a dicho rango de IPs.
- El servicio o servicios a los que aplica: ssh, telnet, web, snmp, tftp o todos.

Los rangos autorizados aparecerán en la configuración activa, y pueden también consultarse explícitamente con la orden *show ip access-manager*::

  $# show run | inc authorized-managers
  ip authorized-managers 10.0.0.0 255.0.0.0 access manager
  ip authorized-managers 192.168.0.0 255.255.0.0 access manager
  ip authorized-managers 172.16.0.0 255.240.0.0 access manager

  $# show ip authorized-manager

  IPV4 Authorized Managers
  ------------------------

   Address : 10.0.0.0
   Mask    : 255.0.0.0
   Access  : Manager
   Access Method : all


   Address : 192.168.0.0
   Mask    : 255.255.0.0
   Access  : Manager
   Access Method : all


   Address : 172.16.0.0
   Mask    : 255.240.0.0
   Access  : Manager
   Access Method : all


Banners
-------

El banner de inicio de sesión se configura con la orden *banner motd *<delimitador> <texto>*. El delimitador permite definir banners con múltiples líneas, por ejemplo::

  (config)#$ banner motd %
  Este banner tiene multiples lineas.
  Al haber usado el simbolo de porcentaje como delimitador,
  el banner continua hasta que lo encuentre.
  %

  $# show run | begin "banner motd"
  banner motd "Este banner tiene multiples lineas.\nAl haber usado el simbolo de porcentaje como delimitador,\nel banner continua hasta que lo encuentre.\n"

  !

  $# show banner motd

  Este banner tiene multiples lineas.
  Al haber usado el simbolo de porcentaje como delimitador,
  el banner continua hasta que lo encuentre.


Servicios de red
================

Resolución DNS
--------------

Los switches utilizan DNS para distintos propósitos:

- Resolver direcciones de servicios de infraestructura (Radius, syslog, airwave etc).
- Conectar a Aruba Activate.

La lista de servidores DNS usados por el switch se configura con el comando *ip dns server-address priority [1|2] [direccion IP]*. El comando puede repetirse con dos prioridades distintas, el switch soporta hasta 2 servidores DNS::

  $# show run | include "ip dns server-address"
  ip dns server-address priority 1 8.8.8.8
  ip dns server-address priority 2 8.8.4.4


Sincronización NTP
------------------

La zona horaria se configura con *time timezone <offset respecto a UTC, minutos>*::

  $# Si no está configurada, la zona horaria por defecto es UTC +0
  $# show run | include "time timezone"
  time timezone 60

El ajuste automático de horario de verano se habilita con *time daylight-time-rule [zona]*, donde la zona es una de:

- Alaska
- continental-us-and-canada
- middle-europe-and-portugal
- southern-hemisphere
- western-europe
- user-defined

  $# Si no está configurado, no hay horario de verano.
  $# show run | include "time daylight"
  time daylight-time-rule western-europe

Para permitir la sincronización a través de NTP, en primer lugar es necesario habilitarla con **timesync ntp**::

  $# show run | inc timesync
  timesync ntp

La lista de servidores NTP con los que el switch se sincronizará se configura con el comando *ntp server <direccion IP> [iburst]* (puede repetirse varias veces para incluir más de un servidor)::

  $# show run | include "ntp server"
  Building configuration...
  ntp server 158.227.98.15 iburst
  ntp server 193.145.15.15 iburst

No se puede marcar un servidor como preferente; el switch elige el más adecuado en función del stratum y el retardo. El servidor con el que se ha sincronizado se puede obtener con el comando *show ntp status*::

  $# show ntp status

  NTP Status Information

  NTP Status             : Enabled         NTP Mode        : Unicast
  Synchronization Status : Synchronized    Peer Dispersion : 0.00000 sec
  Stratum Number         : 2               Leap Direction  : 0
  Reference Assoc ID     : 0               Clock Offset    : 0.00815 sec
  Reference ID           : 158.227.98.15   Root Delay      : 0.01519 sec
  Precision              : 2**-18          Root Dispersion : 0.53080 sec
  NTP Up Time            : 20d 4h 2m       Time Resolution : 400 nsec
  Drift                  : 0.00000 sec/sec

  System Time            : Wed Jul  5 16:48:13 2017
  Reference Time         : Wed Jul  5 16:31:28 2017

  
  
.. _access_security_guide: http://h20565.www2.hpe.com/portal/site/hpsc/template.PAGE/action.process/public/psi/manualsDisplay/?sp4ts.oid=1008605435&javax.portlet.action=true&spf_p.tpst=psiContentDisplay&javax.portlet.begCacheTok=com.vignette.cachetoken&spf_p.prp_psiContentDisplay=wsrp-interactionState%3DdocId%253Demr_na-c05365146%257CdocLocale%253Den_US&javax.portlet.endCacheTok=com.vignette.cachetoken

