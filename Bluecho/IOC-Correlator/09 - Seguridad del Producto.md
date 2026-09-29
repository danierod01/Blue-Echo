# 09 — Seguridad del Producto

> Alimenta el apartado **7 (Seguridad del producto)** de la memoria de la Práctica 3.
> Responde a las seis preguntas que exige el enunciado: modelo de amenazas, gestión
> de secretos, autenticación/control de acceso, validación de entradas, dependencias y
> datos personales.

## 1. Alcance y activos a proteger

Blue-Echo es una plataforma web de análisis de IOCs desplegada en internet
(blueecho.es, VPS Hetzner). Los **activos** que hay que proteger son:

| Activo | Por qué importa |
|---|---|
| **API keys de las fuentes de TI** (VirusTotal, AbuseIPDB, Shodan, OTX, GreyNoise, Groq, Anthropic…) | Son la credencial de mayor valor. Si se filtran, un tercero agota nuestras cuotas gratuitas o incurre en coste (Anthropic/Groq). |
| **Clave de acceso a la aplicación** (`BLUE_ECHO_API_KEY`) | Controla quién puede usar la herramienta. |
| **Historial de escaneos** (SQLite) | Contiene los IOCs consultados: revela qué investiga el analista y puede incluir IPs (dato personal). |
| **Disponibilidad del servicio** | Un SOC depende de que la herramienta responda. |
| **El propio host/VPS** | Compromiso del contenedor o del servidor. |

**¿Quién podría atacarlo?** Un atacante oportunista en internet (escaneo masivo de
la IP/dominio), un usuario no autorizado que quiera consumir las cuotas de las APIs,
y —de forma indirecta— contenido malicioso que llega como *entrada* (ficheros de log
o PCAP subidos, IOCs manipulados, respuestas de las APIs externas).

## 2. Modelo de amenazas (STRIDE)

| Categoría STRIDE | Amenaza concreta | Mitigación implementada |
|---|---|---|
| **S**poofing (suplantación) | Alguien usa la API sin ser un usuario legítimo | Autenticación por cabecera `X-API-Key`; comparación en **tiempo constante** con `hmac.compare_digest` (evita *timing attacks*). Rutas protegidas con la dependency `require_api_key`. |
| **T**ampering (manipulación) | Manipular peticiones o el tráfico en tránsito | **HTTPS/TLS** con Let's Encrypt (Certbot, auto-renovación). Validación y normalización de toda entrada antes de procesarla. Pydantic valida los cuerpos JSON. |
| **R**epudiation (repudio) | Un actor niega haber hecho una consulta | Persistencia del historial con timestamp (`created_at`) en BD y **atribución por token**: cada escaneo se guarda con el token que lo creó (`ScanResult.api_key`), y cada token lleva una etiqueta identificativa (`ApiKey.label`). |
| **I**nformation Disclosure (fuga de información) | Filtrado de API keys o de datos internos | Secretos solo por variables de entorno, nunca en el código ni en el repo (`.gitignore`). El backend no se publica al exterior (`expose`, no `ports`): único punto de entrada Nginx:80/443. Errores controlados que no exponen trazas internas. |
| **D**enial of Service (denegación) | Saturar la API o agotar recursos/cuotas | **Rate limiting por IP** (`slowapi`): límites por endpoint (`/auth/verify` 5/min, escaneo configurable). **Límite de tamaño de fichero** en uploads (`MAX_UPLOAD_SIZE_MB`, HTTP 413). Semáforo de 5 peticiones concurrentes a las fuentes. Timeouts en todas las llamadas HTTP externas. |
| **E**levation of Privilege (elevación) | Ejecutar código o salir del contenedor | Contenedor backend corre como **usuario no root** (`appuser`). Imagen `slim` multi-stage (menos superficie). Dependencias auditadas sin CVEs conocidos (§6). Sin `eval`/deserialización de datos no confiables en el flujo de la app. |

## 3. Gestión de secretos

- **Dónde viven:** todas las claves se leen de variables de entorno (fichero `.env`),
  nunca hardcodeadas. Cada conector obtiene su clave con `os.getenv(...)` a través de
  `BaseConnector.api_key`.
- **Cómo se evita que acaben en el repo:** `.gitignore` excluye `.env`, `.env.*`,
  `*.env` (salvo `.env.example`), además de `*.pem`, `*.key`, `*.crt` y `*.db`. El
  repositorio solo contiene `.env.example` con **valores ficticios/vacíos**.
- **Comparación segura:** la validación de la clave de aplicación usa
  `hmac.compare_digest`, no `==`, para no filtrar información por tiempo de respuesta.
- **Pendiente/recomendación:** verificar con `git log`/escáner que nunca se subió un
  secreto real en el historial (el enunciado exige revocar + limpiar historial si así
  fuera). Acción de comprobación manual antes de la entrega.

## 4. Autenticación y control de acceso

- **Autenticación:** cabecera `X-API-Key` requerida en todos los endpoints de datos.
  El endpoint público `/api/auth/verify` (usado por el login del frontend) comprueba la
  clave y está limitado a 5 intentos/minuto por IP para frenar fuerza bruta.
- **Modelo de acceso:** dos niveles. (1) `BLUE_ECHO_API_KEY` es la **clave maestra**;
  (2) además, cualquiera con el `ADMIN_SECRET` puede generar en `/invite` **tokens de
  acceso personales** (`secrets.token_urlsafe(32)`) con una etiqueta identificativa,
  almacenados en la tabla `ApiKey`. Cada token ve **solo su propio historial**
  (aislamiento por token; el detalle de un escaneo ajeno devuelve 404, no 403, para no
  revelar su existencia). Es el patrón *Personal Access Token* (como GitHub/Stripe). Si
  `BLUE_ECHO_API_KEY` no está configurada, la app entra en **modo desarrollo sin
  restricciones** (documentado); en producción **debe** estar fijada.
- **Aislamiento de red:** el backend FastAPI no se expone al host (`expose: 8000` en la
  red interna de Docker); Nginx es el único punto de entrada y hace de reverse proxy.
- **Limitación honesta:** al ser clave única no hay trazabilidad por usuario ni control
  de acceso granular (RBAC). Documentado como decisión de alcance; RBAC + usuarios queda
  en el roadmap de trabajo futuro.

## 5. Validación de entradas

- **IOCs:** `utils/validators.py` detecta y valida el tipo (IPv4/IPv6, MD5/SHA1/SHA256,
  dominio, URL) antes de consultar nada; una entrada no reconocida devuelve **422** con
  mensaje descriptivo, no un error interno. Longitud del campo `ioc` acotada.
- **Ficheros de log:** el extractor (`extractor.py`) parsea por regex sin ejecutar
  contenido; límite de tamaño configurable (413 si se supera).
- **PCAP:** se detecta el tipo por *magic bytes* (`is_pcap`) y se enruta al endpoint
  correcto; el análisis con scapy es de solo lectura del fichero.
- **Respuestas de APIs externas:** se tratan como **no confiables**. Todos los conectores
  parsean defensivamente y ante una respuesta inesperada devuelven `parse_error` en vez
  de asumir datos válidos (p. ej. el fix de MalwareBazaar de esta práctica: una
  respuesta malformada ya no se reporta como "limpio").
- **Errores HTTP:** timeouts, 429, 403 y respuestas vacías se capturan de forma
  centralizada en `BaseConnector`; nunca se propaga una excepción sin controlar.

## 6. Dependencias

- Auditoría realizada el **2026-09-25** con `pip-audit` (backend) y `npm audit` (frontend).
- **Resultado:** de **31 vulnerabilidades → 0** en backend y **2 → 0** en frontend.
- **Actualizaciones aplicadas:** fastapi 0.115.6→0.141.1 (+ starlette 1.7.0),
  python-multipart 0.0.20→0.0.32 (DoS en multipart), python-dotenv→1.2.3, scapy
  2.6.1→2.7.0 (RCE por pickle en sesiones `-s`, no usado por la app), pytest→9.0.3,
  react-router-dom 6→7.18.4 (open redirect). Validado con los 262 tests + build.
- **Reproducible:** versiones fijadas en `requirements.txt` y `package-lock.json`.
- **Recomendación de continuidad:** activar Dependabot en GitHub y volver a correr
  `pip-audit`/`npm audit` antes de congelar el código para la entrega.

## 7. Datos personales

- **Qué se trata:** direcciones **IP** consultadas como IOC. Bajo el RGPD, una IP puede
  considerarse dato personal cuando permite identificar (indirectamente) a una persona.
- **Finalidad:** análisis de amenazas (interés legítimo de seguridad defensiva).
- **Minimización:** no se recogen datos de usuarios finales (no hay cuentas, ni nombres,
  ni correos); solo los IOCs que el analista introduce voluntariamente.
- **Retención:** el historial se guarda en SQLite en un volumen persistente; **no hay
  purga automática** — recomendación: definir un TTL/retención y un borrado del historial.
- **Protección:** acceso tras autenticación, tráfico cifrado (HTTPS), BD no expuesta al
  exterior. Para pruebas y vídeo se usan **IOCs públicos/ficticios**, nunca datos reales
  de terceros (exigencia del enunciado).

## 8. Resumen de controles y gaps

**Implementado:** auth X-API-Key (comparación constante), tokens personales por invitación
con **historial aislado por token** (404 ante recursos ajenos), rate limiting por IP,
HTTPS, límite de tamaño de subida, validación de entradas, parseo defensivo de fuentes,
secretos fuera del repo, contenedor no root, backend no expuesto, dependencias sin CVEs.

**Gaps conocidos (documentados como trabajo futuro):**
- CORS por defecto `*` → restringir a `https://blueecho.es` en producción.
- Multiusuario por token con etiqueta, sin RBAC completo (no hay roles diferenciados ni
  revocación/expiración de tokens desde la UI) → mejora de trabajo futuro.
- Sin política de retención/purga del historial.
- Verificación manual pendiente de que el historial de git no contiene secretos reales.
- `ADMIN_SECRET`: al configurarlo se habilita `/invite`; debe ser fuerte y rotarse si se filtra.
