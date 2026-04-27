# Descripción del Problema

## Contexto operativo

En un equipo de seguridad blue team, uno de los flujos de trabajo más repetitivos y costosos en tiempo es la investigación de Indicadores de Compromiso (IOCs). Cuando un sistema de detección alerta sobre una IP sospechosa, un hash de fichero desconocido o un dominio en una conexión saliente, el analista debe:

1. Abrir VirusTotal y buscar manualmente el IOC.
2. Abrir AbuseIPDB para comprobar el historial de reportes.
3. Consultar Shodan para ver qué puertos y servicios expone esa IP.
4. Revisar AlienVault OTX para ver si aparece en pulsos de amenaza activos.
5. Verificar MalwareBazaar o URLhaus si es un hash o URL.
6. Consolidar mentalmente todos los resultados y redactar un informe.

Este proceso, repetido decenas de veces al día, consume entre 5 y 15 minutos por IOC y es propenso a errores y omisiones.

## Definición del problema

> **¿Cómo automatizar la correlación multi-fuente de IOCs y hacer accesible el resultado de forma inmediata a cualquier analista, sin necesidad de acceder manualmente a cada plataforma?**

## Requisitos funcionales clave

| Requisito | Descripción |
|---|---|
| RF-01 | Aceptar IPs (v4/v6), hashes (MD5/SHA1/SHA256), dominios y URLs como entrada. |
| RF-02 | Aceptar ficheros de logs y extraer los IOCs automáticamente. |
| RF-03 | Consultar en paralelo al menos 5 fuentes de TI. |
| RF-04 | Calcular un score de amenaza 0-100 con reglas documentadas. |
| RF-05 | Generar un análisis en lenguaje natural en español usando IA generativa. |
| RF-06 | Presentar los resultados en un dashboard web accesible desde internet. |
| RF-07 | Almacenar el historial de consultas para referencia futura. |

## Requisitos no funcionales

| Requisito | Descripción |
|---|---|
| RNF-01 | Tiempo de respuesta < 15 segundos para un IOC individual. |
| RNF-02 | Las API keys no deben exponerse nunca en el repositorio ni en los logs. |
| RNF-03 | El sistema debe degradarse graciosamente si una fuente no responde (sin romper la respuesta). |
| RNF-04 | Despliegue reproducible con un solo comando (`docker compose up`). |

## Tipos de IOC soportados

| Tipo | Ejemplos | Fuentes consultadas |
|---|---|---|
| IPv4 / IPv6 | `185.220.101.45`, `::1` | VT, AbuseIPDB, Shodan, OTX, GreyNoise |
| Hash MD5 | `d41d8cd98f00b204e9800998ecf8427e` | VT, MalwareBazaar, OTX |
| Hash SHA1 | `da39a3ee5e6b4b0d3255bfef95601890afd80709` | VT, MalwareBazaar, OTX |
| Hash SHA256 | `e3b0c44298fc1c...` | VT, MalwareBazaar, OTX |
| Dominio / FQDN | `malware.evil.com` | VT, OTX, URLhaus |
| URL | `https://evil.com/payload.exe` | VT, URLhaus |
