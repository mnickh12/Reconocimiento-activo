# Reconocimiento Activo - Práctica 2

Repositorio para la Práctica 2 de Técnicas de Hacking: Reconocimiento Activo. Implementa descubrimiento de hosts con Scapy y análisis del comportamiento por defecto de Nmap en un entorno Docker controlado.

## Requisitos

- Docker y Docker Compose
- Python 3.10+

## Uso

```bash
# Clonar y levantar entorno
git clone https://github.com/mnickh12/Reconocimiento-activo.git
cd Reconocimiento-activo
docker-compose up -d

# Entrar al contenedor atacante
docker exec -it attacker bash

# Instalar dependencias
apt-get update && apt-get install -y python3 python3-pip iputils-ping nmap
pip3 install scapy

# Ejecutar descubrimiento de hosts
cd /root/src
python3 host_discovery.py

Herramientas
Scapy - Crafting de paquetes ICMP, TCP y UDP

Nmap - Escaneo de puertos

Docker - Entorno virtualizado

Tcpdump - Análisis de tráfico

Aviso legal
Todas las pruebas realizadas en entorno controlado con Docker. El uso de estas técnicas sobre sistemas sin autorización es ilegal.