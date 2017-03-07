Introducción
============

Alcance
-------

El objetivo de este documento es:

- Identificar las funcionalidades de los equipos y aplicaciones HPE-Aruba que puedan ser utilizadas para implementar las reglas de una política de hardening de dispositivos.
- Describir cómo configurar cada una de estas funcionalidades en distintos entornos.
- Realizar recomendaciones sobre dichas configuraciones, en los casos que aplique.
- Proporcionar un mecanismo, lo más automatizable posible, para verificar que la configuración de una funcionalidad se ha realizado de acuerdo a la política.

La definición de la política de seguridad concreta no forma parte del alcance del documento.

El conjunto de entornos incluidos en el alcance se resume en la siguiente tabla:

================================================ =============================================== =======================
Producto                                         Hardware                                        Firmware                
================================================ =============================================== =======================
:doc:`Controladoras Master/Local </controllers>` Aruba 3000, 7000, 7200                          6.4 / 6.5
:doc:`Controladoras Branch</controllers>`        Aruba 7000                                      6.4 / 6.5
:doc:`Switches Aruba MAS</switch_mas>`           S1500, S2500, S3500                             7.4
:doc:`Switches HPE-Aruba</switch_hpe>`           2930, 3810                                      16.02 / 16.03
:doc:`Software Gestión Airwave </amp>`           Físico o virtual                                Centos 6.X, Airwave 8.2
:doc:`Software NAC Clearpass </cppm>`            Físico o virtual                                Clearpass 6.6
================================================ =============================================== =======================

Referencias
-----------

- Controladoras:

  - `ArubaOS 6.5.X user guide`_
  - `ArubaOS 6.5.X CLI reference guide`_
  - `ArubaOS 6.5.X Web Help`_

.. _ArubaOS 6.5.X user guide: https://support.arubanetworks.com/Documentation/tabid/77/DMXModule/512/Command/Core_Download/Default.aspx?EntryId=23671
.. _ArubaOS 6.5.X CLI reference guide: https://support.arubanetworks.com/Documentation/tabid/77/DMXModule/512/Command/Core_Download/Default.aspx?EntryId=23673
.. _ArubaOS 6.5.X Web Help: http://www.arubanetworks.com/techdocs/ArubaOS_65x_WebHelp/Web_Help_Index.htm
  
- Switches Aruba MAS:

  - `ArubaOS 7.4 user guide`_
  - `ArubaOS 7.4 CLI reference guide`_

.. _Arubaos 7.4 user guide: https://support.arubanetworks.com/Documentation/tabid/77/DMXModule/512/Command/Core_Download/Default.aspx?EntryId=19463
.. _ArubaOS 7.4 CLI reference guide: https://support.arubanetworks.com/Documentation/tabid/77/DMXModule/512/Command/Core_Download/Default.aspx?EntryId=19450

- Switches HPE-Aruba:

  - `ArubaOS switch management and configuration guide`_
  - `ArubaOS switch feature and command index`_

.. _ArubaOS switch management and configuration guide: http://h20566.www2.hpe.com/portal/site/hpsc/template.PAGE/action.process/public/psi/manualsDisplay/?sp4ts.oid=1008995294&javax.portlet.action=true&spf_p.tpst=psiContentDisplay&javax.portlet.begCacheTok=com.vignette.cachetoken&spf_p.prp_psiContentDisplay=wsrp-interactionState%3DdocId%253Demr_na-c05161701%257CdocLocale%253Den_US&javax.portlet.endCacheTok=com.vignette.cachetoken
.. _ArubaOS switch feature and command index: http://h20566.www2.hpe.com/portal/site/hpsc/template.PAGE/action.process/public/psi/manualsDisplay/?sp4ts.oid=1008995294&javax.portlet.action=true&spf_p.tpst=psiContentDisplay&javax.portlet.begCacheTok=com.vignette.cachetoken&spf_p.prp_psiContentDisplay=wsrp-interactionState%3DdocId%253Demr_na-c05161698%257CdocLocale%253Den_US&javax.portlet.endCacheTok=com.vignette.cachetoken

- Airwave:

  - `Airwave 8.2 Aruba best practices`_
  - `Airwave 8.2.3 user guide`_

.. _Airwave 8.2 Aruba best practices: https://support.arubanetworks.com/Documentation/tabid/77/DMXModule/512/Command/Core_Download/Default.aspx?EntryId=23728
.. _Airwave 8.2.3 user guide: https://support.arubanetworks.com/Documentation/tabid/77/DMXModule/512/Command/Core_Download/Default.aspx?EntryId=24084

- Clearpass:

  - `Clearpass hardening guide v4`_
  - `Clearpass policy manager user guide`_
  - `Clearpass deployment guide`_

.. _Clearpass hardening guide v4: https://support.arubanetworks.com/Documentation/tabid/77/DMXModule/512/Command/Core_Download/Default.aspx?EntryId=20523
.. _Clearpass deployment guide: http://www.arubanetworks.com/techdocs/ClearPass/Aruba_DeployGd_HTML/Default.htm#HTML_Intro.htm%3FTocPath%3D_____1
.. _Clearpass policy manager user guide: http://www.arubanetworks.com/techdocs/ClearPass/6.6/PolicyManager/index.htm#CPPM_UserGuide/About%20ClearPass/Intro_ClearPass.htm
