# Etapa 2
## Caso de Estudio: CWE-306 en Diferentes Contextos
### Escenario
Se identifica una **DEBILIDAD tipo CWE-306**:
- **CWE-306:** Missing Authentication for Critical Function
- **Significado:** La aplicación permite realizar transferencias de dinero o cambiar permisos de usuarios sin requerir contraseña o identidad.

---

## Pregunta A: ¿Por qué es más "caro" ignorar CWE-306 en pagos vs. noticias?


#### Portal de Pagos (CRÍTICO)

| Dimensión | Impacto |
|-----------|---------|
| **Pérdida Directa** | Transferencias no autorizadas = dinero saliendo de la empresa |
| **Cumplimiento Regulatorio** | PCI-DSS, leyes bancarias, GDPR |
| **Continuidad de Negocio** | Congelación de cuentas, pérdida de operaciones |
| **Confianza del Cliente** | Pérdida de clientes, demandas civiles |
| **Costo de Remediación** | Reembolsos + investigación forense + reparación de reputación |


---

#### Portal de Noticias (BAJO)

| Dimensión | Impacto |
|-----------|---------|
| **Pérdida Directa** | Reputación afectada, pero sin pérdida monetaria directa |
| **Cumplimiento** | GDPR si hay datos personales, pero menos crítico |
| **Continuidad** | Daño de apariencia no afecta operaciones críticas |
| **Costo de Remediación** | Restaurar contenido + revisar logs |

---

### Fórmula  Riesgo = Probabilidad × Severidad × Impacto Económico

```
CWE-306 en Pagos:
Riesgo = 0.9 (alta probabilidad) × 10 (crítico) × $4,000,000 (multa) = $36,000,000

CWE-306 en Noticias:
Riesgo = 0.8 (alta probabilidad) × 5 (moderado) × $50,000 (reputación) = $200,000
```

---

## Pregunta B: ¿Cómo SSO ayuda a cumplir con APO12 (Gestión de Riesgos)?

### APO12: Gestión de Riesgos (COBIT)

**Objetivo:** Identificar, analizar y mitigar riesgos relacionados con TI de manera continua.

---

### Sin SSO (Estado Caótico)

```
Escenario: Empresa con 10 aplicaciones críticas

├─ Portal de Pagos → Base de datos de usuarios local
├─ Sistema de RR.HH. → Base de datos de usuarios local
├─ CRM → Base de datos de usuarios local
├─ ... (7 aplicaciones más)
└─ Cada una con su propia autenticación

Problemas de APO12:
├─ Imposible auditar: ¿Quién accedió a qué sistema cuándo?
├─ Revocación lenta: Si un empleado se va, esperar 10 cambios de password
├─ Inconsistencia: Un usuario en una BD no existe en otra
├─ Alto riesgo de CWE-306: Cada sistema puede tener vulnerabilidades
└─ Incumplimiento: Difícil demostrar cumplimiento en auditorías
```

---

### Con SSO (Estado Controlado - Cumple APO12)

```
Arquitectura Centralizada:

                    ┌──────────────────┐
                    │  SSO Central     │
                    │ (Active Directory│
                    │  o Okta)         │
                    └────────┬─────────┘
                             │
        ┌────────────────────┼────────────────────┐
        │                    │                    │
   ┌─────────┐          ┌─────────┐          ┌──────────┐
   │ Pagos   │          │ RR.HH.  │          │   CRM    │
   └─────────┘          └─────────┘          └──────────┘

Beneficios para APO12:
├─ Logging centralizado: TODOS los accesos registrados en un lugar
├─ Auditoría completa: Rastrear "usuario X accedió a sistema Y el 2026-03-26 a las 14:30"
├─ Revocación inmediata: Un click = usuario revocado de todos los sistemas
├─ Identidades consistentes: Un solo usuario = mismo acceso en todas partes
├─ CWE-306 centralizado: Una sola BD de autenticación = una sola vulnerabilidad a proteger
└─ Cumplimiento demostrable: Reportes automáticos para auditorías
```

---

### Cómo SSO Reduce Riesgos (APO12.2 - Análisis de Riesgos)

| Control COBIT | Sin SSO | Con SSO |
|---------------|---------|---------|
| **Identificación de Riesgos** | 10 sistemas = 10× puntos de fallo | 1 sistema = 1 punto crítico controlado |
| **Medición de Riesgos** | Imposible: logs distribuidos | Fácil: logs centralizados |
| **Mitigación** | Lenta: cambiar en cada sistema | Rápida: cambiar una sola vez |
| **Cumplimiento** | Difícil: datos dispersos | Fácil: reportes automáticos |

**Beneficio Administrativo:** Los administradores pueden demostrar **cumplimiento de gobernanza** mediante reportes automáticos en lugar de recopilar datos de 10 fuentes.

---

## Pregunta C: ¿Vulnerabilidad Crítica - Atender Inmediatamente o Esperar a Actualización Mensual?

### Escenario
- **Vulnerabilidad:** CWE-306 (Missing Authentication)
- **Sistema:** Portal de Pagos
- **Impacto:** Permite a atacante ganar privilegios de administrador
- **Pregunta:** ¿Inmediato o mensual?

---

### Respuesta: **INMEDIATAMENTE (Crítico)**

---

### Análisis desde COBIT 2019

#### 1. Severidad del Riesgo

```
CVSS Score Calculation:
- Ataque sin autenticación (Severity: 10)
- Impacto en confidencialidad: Alto
- Impacto en integridad: Alto (cambio de datos)
- Impacto en disponibilidad: Alto (podría borrar datos)
- Complejidad: Baja (no requiere exploit sofisticado)

CVSS Base Score: 9.8 - CRÍTICO 
```

#### 2. Apetito de Riesgo (APO12.1)

COBIT establece que **cada organización define un apetito de riesgo aceptable**:

```
Riesgo Aceptado: < CVSS 7.0
Riesgo Actual: CVSS 9.8
Estado: ❌ SUPERA EL APETITO DE RIESGO
```

#### 3. Decisión según BAI06 (Gestión de Cambios)

COBIT contempla **excepciones en ciclos de cambio regulares**:

| Situación | Ciclo Normal | Ciclo de Emergencia |
|-----------|--------------|-------------------|
| **Vulnerabilidad CVSS < 7.0** | Próxima actualización mensual | ✓ Cumple con ciclo |
| **Vulnerabilidad CVSS 7.0-8.9** | Próxima semana | Cambio acelerado |
| **Vulnerabilidad CVSS 9.0+** | ❌ Esperar es negligencia | CAMBIO INMEDIATO |
| **Impacto: Pérdida financiera directa** | | **MÁXIMA PRIORIDAD** |

---

### ¿Por qué NO esperar a ciclo mensual?

**Riesgo de Espera (por cada día de demora):**

```
Día 1-2: Riesgo controlado (pocos atacantes saben)
Día 3-5: Riesgo crece (se divulga en forums de hacking)
Día 7+: Riesgo EXTREMO (malware automatizado explotando)
+
```


---
