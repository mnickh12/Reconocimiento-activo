#!/usr/bin/env python3
"""
host_discovery.py - Herramienta de descubrimiento de hosts activos usando Scapy

Esta implementación permite realizar descubrimiento de hosts mediante:
- ICMP Timestamp Request (tipo 13)
- TCP ACK (puerto configurable)
- UDP (puerto configurable)

Autor: Práctica 2 - Reconocimiento activo
Entorno: Docker con redes aisladas
"""

from scapy.all import *
import time
from datetime import datetime

# Configuración global
VERBOSE = True


def craft_discovery_pkts(protocolos, ip_range, puerto=80, num_paquetes=None):
    """
    Construye paquetes para descubrimiento de hosts activos
    
    Parámetros:
    -----------
    protocolos : str o list
        Lista con hasta 3 protocolos ["UDP", "TCP", "ICMP"] o string individual
        Ejemplos: "ICMP", ["TCP", "UDP"], ["ICMP", "TCP", "UDP"]
    
    ip_range : str
        Rango de IPs en formato Scapy (ej: "192.168.1.1", "192.168.1.0/24")
    
    puerto : int (opcional)
        Puerto para capa de transporte TCP/UDP (default: 80)
    
    num_paquetes : dict (opcional)
        Diccionario con claves los protocolos y valores número de paquetes
        Ejemplo: {"ICMP": 2, "TCP": 1, "UDP": 3}
        Si no se pasa, se construye 1 paquete por protocolo
    
    Retorna:
    --------
    list : Lista de paquetes Scapy construidos
    """
    
    paquetes = []
    
    # Convertir string a lista si es necesario
    if isinstance(protocolos, str):
        protocolos = [protocolos]
    
    # Validar que no haya más de 3 protocolos
    if len(protocolos) > 3:
        print(f"[!] Advertencia: Se solicitaron {len(protocolos)} protocolos. Limitando a 3.")
        protocolos = protocolos[:3]
    
    # Configurar número de paquetes por protocolo
    if num_paquetes is None:
        num_paquetes = {proto: 1 for proto in protocolos}
    
    # Crear paquetes según cada protocolo
    for proto in protocolos:
        proto_upper = proto.upper()
        num_pkts = num_paquetes.get(proto, 1)
        
        if VERBOSE:
            print(f"[*] Construyendo {num_pkts} paquete(s) para {proto_upper}")
        
        for i in range(num_pkts):
            if proto_upper == "UDP":
                # Paquete UDP: Capa IP + UDP + payload
                # Se usa puerto destino configurable y puerto origen aleatorio
                pkt = IP(dst=ip_range) / UDP(dport=puerto, sport=random.randint(1024, 65535)) / Raw(load=f"DISCOVERY_UDP_{i}")
                paquetes.append(pkt)
                
            elif proto_upper == "TCP":
                # Paquete TCP con flag ACK (reconocimiento)
                # Flag ACK indica que es parte de una conexión establecida
                pkt = IP(dst=ip_range) / TCP(dport=puerto, sport=random.randint(1024, 65535), flags="A")
                paquetes.append(pkt)
                
            elif proto_upper == "ICMP":
                # Paquete ICMP Timestamp Request (tipo 13, código 0)
                # Solicita timestamp del host destino
                pkt = IP(dst=ip_range) / ICMP(type=13, code=0)
                paquetes.append(pkt)
                
            else:
                print(f"[!] Protocolo no soportado: {proto_upper}")
                print(f"    Protocolos válidos: UDP, TCP, ICMP")
    
    return paquetes


def enviar_y_recibir(paquetes, timeout=2, protocolo="TCP"):
    """
    Envía paquetes y recibe respuestas usando sr() o sr1()
    
    Parámetros:
    -----------
    paquetes : list
        Lista de paquetes Scapy a enviar
    timeout : int
        Tiempo de espera para respuestas (segundos)
    protocolo : str
        Protocolo para ajustar comportamiento (UDP necesita más tiempo)
    
    Retorna:
    --------
    tuple : (respuestas, no_respuestas) o respuesta individual
    """
    
    if not paquetes:
        return [], []
    
    # Ajustar timeout para UDP (necesita más tiempo)
    if protocolo.upper() == "UDP":
        timeout = timeout + 2
    
    if VERBOSE:
        print(f"[*] Enviando {len(paquetes)} paquete(s) con timeout {timeout}s")
    
    try:
        # Enviar paquetes y recibir respuestas
        respuestas, no_respuestas = sr(paquetes, timeout=timeout, verbose=False, retry=0)
        return respuestas, no_respuestas
    except Exception as e:
        print(f"[!] Error al enviar paquetes: {e}")
        return [], []


def descubrir_hosts_activos(ip_range, protocolos=None, puerto=80, verbose=True):
    """
    Descubre hosts activos en un rango de IP usando los protocolos especificados
    
    Parámetros:
    -----------
    ip_range : str
        Rango de IPs a escanear (ej: "172.20.0.0/24" o "172.20.0.10")
    protocolos : list
        Lista de protocolos a utilizar (default: ["ICMP", "TCP"])
    puerto : int
        Puerto para TCP/UDP (default: 80)
    verbose : bool
        Mostrar información detallada
    
    Retorna:
    --------
    list : Lista de IPs activas encontradas
    dict : Diccionario con detalles de cada host activo
    """
    
    global VERBOSE
    VERBOSE = verbose
    
    if protocolos is None:
        protocolos = ["ICMP", "TCP"]  # Por defecto ICMP y TCP
    
    hosts_activos = set()
    detalles_hosts = {}
    
    print(f"\n{'='*60}")
    print(f"INICIANDO DESCUBRIMIENTO DE HOSTS")
    print(f"Rango: {ip_range}")
    print(f"Protocolos: {protocolos}")
    print(f"Puerto: {puerto}")
    print(f"{'='*60}\n")
    
    for proto in protocolos:
        print(f"\n[→] Probando con protocolo: {proto.upper()}")
        print(f"{'-'*40}")
        
        # Construir paquetes para este protocolo
        paquetes = craft_discovery_pkts(proto, ip_range, puerto)
        
        if not paquetes:
            print(f"[-] No se pudieron construir paquetes para {proto}")
            continue
        
        # Enviar y recibir respuestas
        respuestas, no_resp = enviar_y_recibir(paquetes, timeout=2, protocolo=proto)
        
        # Procesar respuestas
        num_respuestas = len(respuestas)
        if num_respuestas > 0:
            print(f"[+] {proto}: {num_respuestas} respuesta(s) recibida(s)")
            
            for respuesta in respuestas:
                # Extraer información del paquete recibido
                pkt_enviado = respuesta[0]
                pkt_recibido = respuesta[1]
                ip_origen = pkt_recibido.src
                ip_destino = pkt_enviado.dst
                
                hosts_activos.add(ip_origen)
                
                # Guardar detalles
                if ip_origen not in detalles_hosts:
                    detalles_hosts[ip_origen] = {
                        "protocolos": [],
                        "respuestas": []
                    }
                
                detalles_hosts[ip_origen]["protocolos"].append(proto.upper())
                
                # Analizar tipo de respuesta según protocolo
                if proto.upper() == "ICMP" and ICMP in pkt_recibido:
                    tipo_icmp = pkt_recibido[ICMP].type
                    detalles_hosts[ip_origen]["respuestas"].append(f"ICMP type {tipo_icmp}")
                    print(f"  ✓ {ip_origen} → Respuesta ICMP (type {tipo_icmp})")
                    
                elif proto.upper() == "TCP" and TCP in pkt_recibido:
                    flags = pkt_recibido[TCP].flags
                    detalles_hosts[ip_origen]["respuestas"].append(f"TCP flags {flags}")
                    print(f"  ✓ {ip_origen} → Respuesta TCP (flags {flags})")
                    
                elif proto.upper() == "UDP" and UDP in pkt_recibido:
                    detalles_hosts[ip_origen]["respuestas"].append("Respuesta UDP")
                    print(f"  ✓ {ip_origen} → Respuesta UDP")
                    
                else:
                    detalles_hosts[ip_origen]["respuestas"].append("Respuesta recibida")
                    print(f"  ✓ {ip_origen} → Respondió")
        else:
            print(f"[-] {proto}: No se recibieron respuestas")
        
        # Pequeña pausa entre protocolos para no saturar
        time.sleep(0.5)
    
    return list(hosts_activos), detalles_hosts


def escaneo_con_timeout(ip, protocolos=["ICMP"], timeout=1):
    """
    Escaneo simple de una IP individual con timeout específico
    
    Útil para probar hosts individuales rápidamente
    """
    resultados = {}
    
    for proto in protocolos:
        pkt = craft_discovery_pkts(proto, ip, puerto=80)
        if pkt:
            respuesta = sr1(pkt[0], timeout=timeout, verbose=False)
            resultados[proto] = respuesta is not None
            
            if VERBOSE:
                estado = "ACTIVO" if respuesta else "INACTIVO"
                print(f"  {proto}: {ip} → {estado}")
    
    return resultados


def generar_reporte(hosts_activos, detalles_hosts, tiempo_inicio, ip_range):
    """
    Genera un reporte formateado de los resultados del escaneo
    """
    
    tiempo_total = time.time() - tiempo_inicio
    
    print(f"\n{'='*60}")
    print(f"REPORTE FINAL DE DESCUBRIMIENTO")
    print(f"{'='*60}")
    print(f"Rango escaneado: {ip_range}")
    print(f"Tiempo total: {tiempo_total:.2f} segundos")
    print(f"Hosts activos encontrados: {len(hosts_activos)}")
    
    if hosts_activos:
        print(f"\nLista de hosts activos:")
        for i, host in enumerate(sorted(hosts_activos), 1):
            print(f"  {i}. {host}")
        
        print(f"\nDetalles por host:")
        for host in sorted(hosts_activos):
            detalles = detalles_hosts.get(host, {})
            protocolos = detalles.get("protocolos", [])
            respuestas = detalles.get("respuestas", [])
            print(f"\n  📍 {host}")
            print(f"     Protocolos que respondieron: {', '.join(set(protocolos))}")
            for resp in respuestas:
                print(f"     └─ {resp}")
    else:
        print(f"\n[-] No se encontraron hosts activos en el rango especificado")
    
    print(f"\n{'='*60}\n")


# ============================================================================
# PRUEBAS Y EJEMPLOS DE USO
# ============================================================================

def pruebas_automaticas():
    """
    Ejecuta pruebas automáticas para verificar el funcionamiento
    """
    print("\n" + "="*60)
    print("EJECUTANDO PRUEBAS AUTOMÁTICAS")
    print("="*60)
    
    pruebas_pasadas = 0
    pruebas_fallidas = 0
    
    # Prueba 1: Construcción de paquetes ICMP
    print("\n[Prueba 1] Construcción paquete ICMP")
    try:
        pkt = craft_discovery_pkts("ICMP", "192.168.1.1")
        assert len(pkt) == 1
        assert ICMP in pkt[0]
        assert pkt[0][ICMP].type == 13
        print("  ✓ OK - Paquete ICMP construido correctamente")
        pruebas_pasadas += 1
    except Exception as e:
        print(f"  ✗ FAIL - {e}")
        pruebas_fallidas += 1
    
    # Prueba 2: Construcción de paquetes TCP
    print("\n[Prueba 2] Construcción paquete TCP")
    try:
        pkt = craft_discovery_pkts("TCP", "192.168.1.1", puerto=443)
        assert len(pkt) == 1
        assert TCP in pkt[0]
        assert pkt[0][TCP].dport == 443
        print("  ✓ OK - Paquete TCP construido correctamente")
        pruebas_pasadas += 1
    except Exception as e:
        print(f"  ✗ FAIL - {e}")
        pruebas_fallidas += 1
    
    # Prueba 3: Construcción de paquetes UDP
    print("\n[Prueba 3] Construcción paquete UDP")
    try:
        pkt = craft_discovery_pkts("UDP", "192.168.1.1", puerto=53)
        assert len(pkt) == 1
        assert UDP in pkt[0]
        assert pkt[0][UDP].dport == 53
        print("  ✓ OK - Paquete UDP construido correctamente")
        pruebas_pasadas += 1
    except Exception as e:
        print(f"  ✗ FAIL - {e}")
        pruebas_fallidas += 1
    
    # Prueba 4: Múltiples protocolos
    print("\n[Prueba 4] Múltiples protocolos")
    try:
        pkt = craft_discovery_pkts(["ICMP", "TCP"], "192.168.1.1")
        assert len(pkt) == 2
        print("  ✓ OK - Paquetes múltiples construidos correctamente")
        pruebas_pasadas += 1
    except Exception as e:
        print(f"  ✗ FAIL - {e}")
        pruebas_fallidas += 1
    
    # Prueba 5: Número variable de paquetes
    print("\n[Prueba 5] Número variable de paquetes")
    try:
        num = {"ICMP": 3, "TCP": 2}
        pkt = craft_discovery_pkts(["ICMP", "TCP"], "192.168.1.1", num_paquetes=num)
        assert len(pkt) == 5
        print("  ✓ OK - Número variable de paquetes funcionando")
        pruebas_pasadas += 1
    except Exception as e:
        print(f"  ✗ FAIL - {e}")
        pruebas_fallidas += 1
    
    # Resumen de pruebas
    print(f"\n{'='*40}")
    print(f"RESUMEN PRUEBAS: {pruebas_pasadas} pasadas, {pruebas_fallidas} fallidas")
    print(f"{'='*40}")
    
    return pruebas_pasadas, pruebas_fallidas


def pruebas_con_docker():
    """
    Pruebas específicas para el entorno Docker del docker-compose.yml
    """
    print("\n" + "="*60)
    print("PRUEBAS CON ENTORNO DOCKER")
    print("="*60)
    print("IPs esperadas activas: 172.20.0.10, 172.20.0.11, 172.20.0.12, 172.20.0.13")
    print("IP inactiva esperada: 172.20.0.99")
    
    # Lista de IPs a probar
    ips_docker = {
        "172.20.0.10": "target-web (HTTP)",
        "172.20.0.11": "target-multi (SSH+HTTP)",
        "172.20.0.12": "target-udp (UDP/53)",
        "172.20.0.13": "target-icmp-only (solo ICMP)",
        "172.20.0.99": "IP inexistente (debe fallar)"
    }
    
    resultados_test = {}
    
    for ip, descripcion in ips_docker.items():
        print(f"\n[Test] {descripcion} - {ip}")
        print("-" * 40)
        
        # Probar con ICMP
        pkt_icmp = craft_discovery_pkts("ICMP", ip)
        resp_icmp = sr1(pkt_icmp[0], timeout=2, verbose=False)
        
        # Probar con TCP (puerto 80)
        pkt_tcp = craft_discovery_pkts("TCP", ip, puerto=80)
        resp_tcp = sr1(pkt_tcp[0], timeout=2, verbose=False)
        
        estado_icmp = "✓ ACTIVO" if resp_icmp else "✗ INACTIVO"
        estado_tcp = "✓ ACTIVO" if resp_tcp else "✗ INACTIVO"
        
        print(f"  ICMP: {estado_icmp}")
        print(f"  TCP:  {estado_tcp}")
        
        resultados_test[ip] = {
            "descripcion": descripcion,
            "icmp": resp_icmp is not None,
            "tcp": resp_tcp is not None
        }
    
    # Resumen
    print(f"\n{'='*40}")
    print("RESUMEN PRUEBAS DOCKER")
    print(f"{'='*40}")
    activos = sum(1 for r in resultados_test.values() if r["icmp"] or r["tcp"])
    print(f"Hosts detectados como activos: {activos}/5")
    
    return resultados_test


# ============================================================================
# MAIN - Punto de entrada del script
# ============================================================================

if __name__ == "__main__":
    
    print("""
    ╔══════════════════════════════════════════════════════════════╗
    ║     HOST DISCOVERY TOOL - Práctica 2 Reconocimiento Activo   ║
    ║                   Implementación con Scapy                   ║
    ╚══════════════════════════════════════════════════════════════╝
    """)
    
    # ========== PRUEBA 1: Host activo individual ==========
    print("\n" + "§"*60)
    print("PRUEBA 1: Escaneo a host activo individual (172.20.0.10)")
    print("§"*60)
    
    tiempo_inicio = time.time()
    hosts_activos, detalles = descubrir_hosts_activos(
        ip_range="172.20.0.10",
        protocolos=["ICMP", "TCP", "UDP"],
        puerto=80,
        verbose=True
    )
    generar_reporte(hosts_activos, detalles, tiempo_inicio, "172.20.0.10")
    
    
    # ========== PRUEBA 2: IP sin host activo ==========
    print("\n" + "§"*60)
    print("PRUEBA 2: Escaneo a IP sin host activo (172.20.0.99)")
    print("§"*60)
    
    tiempo_inicio = time.time()
    hosts_activos, detalles = descubrir_hosts_activos(
        ip_range="172.20.0.99",
        protocolos=["ICMP", "TCP"],
        puerto=80,
        verbose=True
    )
    generar_reporte(hosts_activos, detalles, tiempo_inicio, "172.20.0.99")
    
    
    # ========== PRUEBA 3: Rango completo de red ==========
    print("\n" + "§"*60)
    print("PRUEBA 3: Escaneo de rango completo (172.20.0.0/24)")
    print("§"*60)
    
    tiempo_inicio = time.time()
    hosts_activos, detalles = descubrir_hosts_activos(
        ip_range="172.20.0.0/24",
        protocolos=["ICMP", "TCP"],
        puerto=80,
        verbose=True
    )
    generar_reporte(hosts_activos, detalles, tiempo_inicio, "172.20.0.0/24")
    
    
    # ========== PRUEBA 4: Escaneo rápido con timeout ==========
    print("\n" + "§"*60)
    print("PRUEBA 4: Escaneo rápido con timeout reducido")
    print("§"*60)
    
    print("\n[Test rápido] Probando 172.20.0.10 con timeout 1s:")
    resultado = escaneo_con_timeout("172.20.0.10", ["ICMP", "TCP"], timeout=1)
    
    print("\n[Test rápido] Probando 172.20.0.99 con timeout 1s:")
    resultado = escaneo_con_timeout("172.20.0.99", ["ICMP", "TCP"], timeout=1)
    
    
    # ========== PRUEBAS AUTOMÁTICAS ==========
    pruebas_automaticas()
    
    
    # ========== PRUEBAS CON DOCKER ==========
    # Descomentar si se ejecuta dentro del contenedor Docker
    # pruebas_con_docker()
    
    
    print("\n" + "="*60)
    print("FIN DEL SCRIPT - Todas las pruebas completadas")
    print("="*60 + "\n")