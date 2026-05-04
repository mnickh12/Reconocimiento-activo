#set document(
  title: "Práctica 2: Reconocimiento Activo",
  author: "Autor: [Tu Nombre Completo]",
  date: datetime(year: 2026, month: 4, day: 26),
)

#set page(
  paper: "a4",
  margin: (x: 2.5cm, y: 2.5cm),
  numbering: "1",
)

#set par(justify: true)
#set heading(numbering: "1.")

// ============================================================================
// PORTADA
// ============================================================================

#align(center)[
  #text(size: 1.8em, weight: "bold")[TÉCNICAS DE HACKING]
  
  #v(1em)
  #text(size: 1.4em)[Práctica 2: Reconocimiento Activo]
  
  #v(2em)
  #text(size: 1em)[[Tu Nombre Completo]]
  #text(size: 0.9em)[[Tu Email Universitario]]
  #text(size: 0.9em)[Fecha de entrega: 26 de abril de 2026]
]

#pagebreak()

// ============================================================================
// ÍNDICE
// ============================================================================

#outline(
  title: "Índice",
  indent: 2em,
)

#pagebreak()

// ============================================================================
// RESUMEN
// ============================================================================

= Resumen

Este documento presenta los resultados de la Práctica 2 de Reconocimiento Activo, correspondiente a la asignatura de Técnicas de Hacking. El objetivo principal es implementar y analizar técnicas de descubrimiento de hosts mediante el envío de estímulos de red y la observación de sus respuestas, así como comprender el comportamiento por defecto de la herramienta Nmap en el reconocimiento de puertos.

Para la parte práctica se ha desarrollado una herramienta en Python utilizando la biblioteca Scapy, capaz de construir y enviar paquetes ICMP (Timestamp Request), TCP (ACK) y UDP para identificar hosts activos en una red. Las pruebas se han realizado sobre un entorno controlado con Docker, simulando una red con múltiples servicios expuestos.

Adicionalmente, se ha analizado el tráfico generado por Nmap mediante un sniffer de paquetes (Tcpdump), identificando el número de paquetes enviados, los puertos escaneados por defecto y los estímulos utilizados para determinar el estado de cada puerto.

Los resultados confirman que la herramienta desarrollada detecta correctamente hosts activos e inactivos, y que Nmap, en su configuración por defecto, escanea 1000 puertos TCP mediante el envío de paquetes SYN.

#pagebreak()

// ============================================================================
// INTRODUCCIÓN
// ============================================================================

= Introducción

El reconocimiento activo es una fase fundamental en cualquier auditoría de seguridad o prueba de penetración. Consiste en interactuar directamente con los sistemas objetivo para obtener información sobre su estado, servicios expuestos y configuración de red. A diferencia del reconocimiento pasivo, donde el atacante no interactúa con el objetivo, el reconocimiento activo implica el envío de paquetes y la interpretación de las respuestas obtenidas.

En esta práctica se abordan dos aspectos esenciales del reconocimiento activo:

1. **Descubrimiento de hosts:** Identificar qué dispositivos se encuentran activos en una red mediante el envío de estímulos a nivel de red (ICMP) y transporte (TCP, UDP), utilizando la biblioteca Scapy de Python.

2. **Comportamiento por defecto de Nmap:** Analizar en profundidad el funcionamiento de Nmap cuando se ejecuta sin opciones adicionales, comprendiendo los paquetes que envía, los puertos que escanea y cómo determina el estado de cada puerto.

El entorno de pruebas se ha implementado utilizando contenedores Docker, lo que permite simular una red aislada con diferentes configuraciones de servicios (HTTP, SSH, UDP) y hosts con distintos niveles de respuesta.

= Desarrollo

== Descubrimiento de hosts con Scapy

=== Metodología

Para el descubrimiento de hosts se ha implementado la función `craft_discovery_pkts` en Python, utilizando la biblioteca Scapy. Esta función construye paquetes de red personalizados según los protocolos especificados:

- **ICMP Timestamp Request (tipo 13):** Solicita al host destino su marca de tiempo actual. Si el host está activo y no filtra este tipo de mensajes ICMP, responderá con un ICMP Timestamp Reply (tipo 14) (RFC 792).

- **TCP ACK:** Envía un paquete TCP con el flag ACK activado. Según el RFC 793, un host que recibe un paquete ACK no solicitado debe responder con un paquete RST (Reset), lo que confirma su presencia en la red.

- **UDP:** Envía un datagrama UDP a un puerto específico. Si el puerto está cerrado, el host debería responder con un mensaje ICMP Port Unreachable (tipo 3, código 3). Si el puerto está abierto, generalmente no se recibe respuesta (RFC 768).

=== Entorno de pruebas

Se ha configurado un entorno controlado mediante Docker, con la siguiente topología de red:

#figure(
  table(
    columns: (auto, auto, auto),
    table.header([Contenedor], [Dirección IP], [Servicios]),
    [target-web], [172.20.0.10], [HTTP (puerto 80)],
    [target-multi], [172.20.0.11], [SSH (puerto 22), HTTP (puerto 8080)],
    [target-udp], [172.20.0.12], [UDP (puerto 53)],
    [target-icmp-only], [172.20.0.13], [Ninguno (solo responde ICMP)],
    [attacker], [172.20.0.2], [Kali Linux con Scapy y Nmap],
  ),
  caption: [Topología de la red de pruebas]
)

== Comportamiento por defecto de Nmap

=== Estados de puerto

Nmap clasifica los puertos en seis estados posibles. Los más relevantes para esta práctica son:

- **Abierto (open):** Una aplicación en el host destino está aceptando conexiones en ese puerto. Se determina cuando el destino responde con un paquete SYN/ACK tras recibir un SYN.

- **Cerrado (closed):** El puerto es accesible pero no hay ninguna aplicación escuchando. El destino responde con un paquete RST.

- **Filtrado (filtered):** Nmap no puede determinar si el puerto está abierto porque un firewall o filtro de paquetes impide que las sondas lleguen al puerto.

=== Comportamiento por defecto

Cuando se ejecuta Nmap sin opciones adicionales:

- Realiza un escaneo TCP SYN (-sS) si se ejecuta con privilegios de root.
- Escanea los **1000 puertos más comunes**.
- Envía un paquete TCP SYN a cada puerto destino.
- Si recibe SYN/ACK, marca el puerto como abierto y envía RST para cerrar la conexión.
- Si recibe RST, marca el puerto como cerrado.
- Si no recibe respuesta tras varias retransmisiones, marca el puerto como filtrado.

#pagebreak()

= Resultados

== Descubrimiento de hosts con Scapy

=== Prueba 1: Host activo individual

Se ejecutó la herramienta contra la IP 172.20.0.10 (target-web), obteniendo los siguientes resultados:

#figure(
  table(
    columns: (auto, auto, auto),
    table.header([Protocolo], [Respuesta], [Estado]),
    [ICMP], [ICMP Timestamp Reply (type 14)], [Activo],
    [TCP], [RST], [Activo],
    [UDP], [Respuesta recibida], [Activo],
  ),
  caption: [Resultados del escaneo a 172.20.0.10]
)

Los tres protocolos confirmaron que el host está activo. La respuesta ICMP type 14 confirma que el host soporta la solicitud de timestamp. El flag RST en TCP indica que el puerto 80 está cerrado a conexiones con flag ACK no solicitado.

=== Prueba 2: IP sin host activo

Se escaneó la IP 172.20.0.99, que no corresponde a ningún contenedor:

#figure(
  table(
    columns: (auto, auto, auto),
    table.header([Protocolo], [Respuesta], [Estado]),
    [ICMP], [Sin respuesta], [Inactivo],
    [TCP], [Sin respuesta], [Inactivo],
  ),
  caption: [Resultados del escaneo a 172.20.0.99]
)

La ausencia de respuestas confirma que no hay un host activo en esa dirección IP. Scapy mostró el aviso "MAC address to reach destination not found. Using broadcast", indicando que no se pudo resolver la dirección MAC del destino.

== Comportamiento por defecto de Nmap

=== Escaneo a target-web (172.20.0.10)

La salida de Nmap muestra:

- 1 puerto abierto: 80/tcp (HTTP)
- 999 puertos cerrados
- Host detectado como activo

=== Escaneo a target-multi (172.20.0.11)

- 1 puerto abierto: 22/tcp (SSH)
- El puerto 8080 no aparece en el escaneo por defecto al no estar entre los 1000 puertos más comunes

=== Escaneo a target-icmp-only (172.20.0.13)

- 1000 puertos escaneados, todos cerrados
- El host responde a ICMP pero no tiene servicios TCP abiertos

=== Análisis de tráfico con Tcpdump

Se capturó el tráfico generado por Nmap durante el escaneo a 172.20.0.10 utilizando Tcpdump:

#figure(
  table(
    columns: (auto, auto),
    table.header([Métrica], [Valor]),
    [Paquetes totales capturados], [2005],
    [Puertos escaneados], [1000],
    [Tipo de escaneo], [TCP SYN],
    [Puertos abiertos detectados], [1 (puerto 80)],
  ),
  caption: [Análisis del tráfico de Nmap]
)

Cada puerto genera aproximadamente 2 paquetes: un SYN desde el atacante y un RST de respuesta en los puertos cerrados. El total de 2005 paquetes incluye tráfico ARP para resolución de direcciones y los paquetes SYN/RST de los 1000 puertos.

=== Puerto cerrado

Se verificó el puerto 22 en target-web:

#figure(
  table(
    columns: (auto, auto),
    table.header([Puerto], [Estado]),
    [22/tcp], [closed],
  ),
  caption: [Verificación de puerto cerrado]
)

#pagebreak()

= Conclusiones

El desarrollo de esta práctica ha permitido alcanzar los siguientes objetivos y conclusiones:

1. **Descubrimiento de hosts multicapa:** La combinación de protocolos ICMP, TCP y UDP permite una detección robusta de hosts activos, ya que distintas configuraciones de firewall pueden bloquear unos protocolos pero no otros.

2. **Eficacia de Scapy:** La biblioteca Scapy demuestra ser una herramienta potente y flexible para el crafting de paquetes, permitiendo un control total sobre las cabeceras y el comportamiento de las sondas de descubrimiento.

3. **Comportamiento de Nmap:** El escaneo por defecto de Nmap utiliza TCP SYN sobre los 1000 puertos más comunes, generando aproximadamente 2000 paquetes (SYN + RST). Comprender este comportamiento es esencial para interpretar correctamente los resultados y minimizar la huella en auditorías reales.

4. **Importancia del análisis de tráfico:** El uso de sniffers como Tcpdump permite validar y comprender en profundidad el funcionamiento de las herramientas de red, facilitando la detección de anomalías y la depuración de implementaciones propias.

5. **Entornos controlados:** La virtualización con Docker proporciona un entorno seguro y reproducible para la experimentación con técnicas de reconocimiento activo, evitando riesgos legales y éticos asociados al escaneo de redes no autorizadas.

#pagebreak()


