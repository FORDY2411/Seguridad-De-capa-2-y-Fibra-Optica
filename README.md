
# 🛡️ Seguridad en Capa Física (Capa 1): Fibra Óptica, Fiber Tapping y Detección de Anomalías

![Certificación](https://img.shields.io/badge/CompTIA-Network%2B%20(N10--009)-red?style=flat-square)
![Framework](https://img.shields.io/badge/MITRE%20ATT%26CK-T1040%20%7C%20T1200-orange?style=flat-square)
![Enfoque](https://img.shields.io/badge/Enfoque-Red%20Team%20%26%20Blue%20Team-blue?style=flat-square)
![Stack](https://img.shields.io/badge/Stack-PowerShell%20%7C%20Python%203-green?style=flat-square)

## 📋 Resumen Ejecutivo

Este laboratorio técnico analiza los fundamentos de transmisión en redes de fibra óptica y desmonta el mito operativo de que *"la fibra óptica es físicamente inhackeable"*. Mediante la auditoría de interfaces locales en Windows y la simulación de telemetría óptica (**DOM/DDM**) en Python, se demuestra cómo un atacante puede ejecutar una derivación óptica pasiva (**Fiber Tapping**) sin interrumpir el servicio, y cómo un equipo defensivo puede detectarla y mitigarla combinando controles en **Capa 1** y **Capa 2**.

### 🎯 Objetivos del Laboratorio
* Auditar atributos de capa física (`MediaType`, `PhysicalMediaType`, `LinkSpeed`) de adaptadores de red activos mediante consola.
* Diferenciar especificaciones técnicas, alcances y estándares IEEE entre fibra **Monomodo (SMF)** y **Multimodo (MMF)**.
* Desarrollar un prototipo de detección de intrusiones óptico basado en atenuación de potencia de recepción (**RX dBm**).
* Aplicar el principio de defensa en profundidad mediante seguridad física y cifrado de enlace **MACsec (`IEEE 802.1AE`)**.

---

## 🧩 Mapeo de Amenazas (MITRE ATT&CK & CompTIA N10-009)

| Marco / Estándar | Identificador / Dominio | Aplicación en este Laboratorio |
| :--- | :--- | :--- |
| **MITRE ATT&CK** | `T1040` — *Network Sniffing* | Captura pasiva de tráfico en claro mediante extracción de fotones por micro-curvatura (*macrobending*). |
| **MITRE ATT&CK** | `T1200` — *Hardware Additions* | Inserción física de un acoplador óptico (*clip-on coupler*) en bandejas de empalme o cableado expuesto. |
| **CompTIA N10-009** | *1.0 Networking Concepts* | Medios físicos de transmisión, estándares `1000BASE-SX/LX`, `10GBASE-SR/LR` y mitigación en Capa 2. |

---

## 🧠 Base Técnica: Monomodo vs. Multimodo

| Característica | Fibra Multimodo (MMF) | Fibra Monomodo (SMF) |
| :--- | :--- | :--- |
| **Diámetro del núcleo** | ~50 o 62.5 micras | ~8.3 a 10 micras |
| **Fuente de luz** | LED o láser VCSEL | Láser de alta precisión |
| **Alcance típico** | Corto (hasta ~300–550 m) | Largo (decenas de km) |
| **Fenómeno limitante** | Dispersión modal | Atenuación por distancia extrema |
| **Estándares IEEE clave** | `1000BASE-SX`, `10GBASE-SR` | `1000BASE-LX`, `10GBASE-LR` |
| **Color de chaqueta** | Naranja (OM1/OM2) / Aqua (OM3/OM4) | Amarilla |

---

## 🛠️ Desarrollo Práctico y Evidencias

### Fase 1: Auditoría de Interfaz Física Local (Windows PowerShell)

Para inspeccionar cómo el sistema operativo identifica el medio físico de transmisión activo, se ejecutó el siguiente *cmdlet* en PowerShell con privilegios de administrador (filtrando únicamente campos no sensibles para preservar la privacidad):

```powershell
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | Format-List Name, InterfaceDescription, LinkSpeed, MediaType, PhysicalMediaType
```

#### 📊 Resultados Obtenidos
* **Interfaz activa:** `Wi-Fi` (`Realtek 8821CE Wireless LAN 802.11ac PCI-E NIC`)
* **Velocidad de enlace (`LinkSpeed`):** `390 Mbps`
* **Medio físico (`MediaType` / `PhysicalMediaType`):** `Native 802.11`

> **Análisis técnico:** La salida confirma que el equipo opera sobre un medio inalámbrico estándar `IEEE 802.11` (radiofrecuencia), a diferencia de interfaces cableadas de cobre (`802.3`) o enlaces ópticos troncales mediante transceptores SFP/SFP+.

!<img width="1212" height="459" alt="FibraOPtica paso1" src="https://github.com/user-attachments/assets/53e6a9a1-caab-4eb7-86cd-d1975126ea54" />


---

### Fase 2: Simulación de Detección de Fiber Tapping (`fiber_ids.py`)

Un atacante con acceso físico a una canalización o *patch panel* puede inducir una micro-curvatura controlada sobre la fibra para desviar una fracción mínima de luz hacia un fotodetector externo. Para simular la detección temprana de este vector, se implementó [`fiber_ids.py`](./fiber_ids.py), monitorizando la telemetría **DOM/DDM** de un transceptor `10GBASE-LR`:

```python
import time

# Lecturas simuladas de potencia óptica RX (en dBm) cada segundo
# Rango normal para 10GBASE-LR: -1.0 dBm a -14.4 dBm (línea base estable: -3.2 dBm)
lecturas_rx_dbm = [-3.2, -3.1, -3.3, -3.2, -6.8, -6.9, -19.5]
baseline = -3.2

print("[*] Iniciando monitoreo DOM/DDM en interfaz troncal SFP+ (10GBASE-LR)...")
for segundo, rx in enumerate(lecturas_rx_dbm, start=1):
    atenuacion = abs(rx - baseline)
    if rx < -14.4:
        estado = "CRITICO: Perdida total de senal (Posible corte de fibra o DoS)"
    elif atenuacion >= 3.0:
        estado = f"ALERTA DE SEGURIDAD: Caida subita de {atenuacion:.1f} dB (Posible Fiber Tap por curvatura)"
    else:
        estado = "OK: Nivel optico estable"
    print(f"[T+{segundo}s] RX Power: {rx} dBm -> {estado}")
    time.sleep(0.5)
```

#### 💻 Salida Esperada en Consola
```text
[*] Iniciando monitoreo DOM/DDM en interfaz troncal SFP+ (10GBASE-LR)...
[T+1s] RX Power: -3.2 dBm -> OK: Nivel optico estable
[T+2s] RX Power: -3.1 dBm -> OK: Nivel optico estable
[T+3s] RX Power: -3.3 dBm -> OK: Nivel optico estable
[T+4s] RX Power: -3.2 dBm -> OK: Nivel optico estable
[T+5s] RX Power: -6.8 dBm -> ALERTA DE SEGURIDAD: Caida subita de 3.6 dB (Posible Fiber Tap por curvatura)
[T+6s] RX Power: -6.9 dBm -> ALERTA DE SEGURIDAD: Caida subita de 3.7 dB (Posible Fiber Tap por curvatura)
[T+7s] RX Power: -19.5 dBm -> CRITICO: Perdida total de senal (Posible corte de fibra o DoS)
```

#### 🔍 Análisis de la Anomalía (`T+5s`)
* **Detección basada en línea base (*Baseline*):** Aunque `-6.8 dBm` permanece dentro de la sensibilidad operativa del módulo `10GBASE-LR` (`-1.0 dBm` a `-14.4 dBm`), una atenuación abrupta de `3.6 dB` respecto al estado estable (`-3.2 dBm`) delata una manipulación física en el medio.
* **Criterio ofensivo de sigilo (*Stealth*):** Un atacante calibra la curvatura para provocar esa caída moderada y precisa en lugar de llevar la potencia a `-19.5 dBm`. Si supera el umbral crítico, el enlace cae (`Link Down`), disparando alertas inmediatas de disponibilidad en el NOC y exponiendo la intrusión.

---

### Fase 3: Arquitectura Defensiva y Hardening

1. **Cifrado de Capa 2 — MACsec (`IEEE 802.1AE`):**
   * Protege el tráfico punto a punto entre switches o routers directamente por hardware a velocidad de línea (*wire-speed*).
   * Cifra toda la trama Ethernet e incorpora validación de integridad (ICV), inutilizando cualquier captura óptica pasiva.
2. **Telemetría Proactiva (SNMP + DOM/DDM):**
   * Configurar umbrales de advertencia (*Warning Thresholds*) ante variaciones repentinas de potencia `RX/TX` antes de que ocurra una interrupción del enlace.
3. **Controles de Seguridad Física:**
   * Canalizaciones blindadas, cuartos de telecomunicaciones con control de acceso estricto y precintos de seguridad en bandejas de fibra.

---

## 📌 Conclusiones y Lecciones Aprendidas

* **La seguridad física es el cimiento de Zero Trust:** Confiar exclusivamente en las propiedades físicas de un medio de transmisión (como la ausencia de radiación electromagnética en la fibra) genera puntos ciegos críticos si un atacante obtiene acceso físico a la infraestructura.
* **El monitoreo de anomalías supera a los umbrales estáticos:** En operaciones de defensa (Blue Team), esperar a que un servicio caiga (`Link Down`) suele ser demasiado tarde. Detectar desviaciones sutiles sobre una línea base permite identificar ataques sigilosos en curso.
* **Defensa en profundidad por capas:** Incluso ante un compromiso físico en Capa 1, la implementación de cifrado robusto en Capa 2 (**MACsec**) o Capa 3 (**IPsec**) garantiza la confidencialidad e integridad de los datos en tránsito.

---
