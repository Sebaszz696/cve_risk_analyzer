# Etapa 3:

**Objetivo:** Asociar 5 debilidades técnicas (CWE) con 3 objetivos de gobernanza COBIT 2019.

### Mapeo Principal

| CWE | Objetivo | Razón |
|-----|----------|-------|
| **CWE-20** - Validación Incorrecta | **B. BAI03** | Error de construcción en validación |
| **CWE-306** - Sin Autenticación | **C. DSS05** | Control de seguridad (autenticación) ausente |
| **CWE-119** - Buffer Overflow | **B. BAI03** | Error de diseño de memoria |
| **CWE-89** - SQL Injection | **B. BAI03** | Falta validación de entrada |
| **CWE-79** - XSS | **C. DSS05** | Control de protección de datos ausente |

---

## Objetivos COBIT 2019 Definidos

### A. APO12 - Gestionar el Riesgo
Identificar, analizar y mitigar riesgos de TI que afecten objetivos empresariales.

### B. BAI03 - Gestionar la Identificación y Construcción de Soluciones
Diseñar y construir sistemas correctamente, validando requisitos de seguridad durante desarrollo.

### C. DSS05 - Gestionar los Servicios de Seguridad
Proteger información contra accesos no autorizados mediante controles de autenticación, autorización y protección.

---

## Debilidades Técnicas (CWE)

| CWE | Descripción | Ejemplo | Mapeo |
|-----|-------------|---------|-------|
| **CWE-20** | Validación incorrecta de entrada | Aceptar números negativos en campo positivo | → BAI03 |
| **CWE-306** | Ausencia de autenticación | Cambiar contraseña sin verificar identidad | → DSS05 |
| **CWE-119** | Buffer overflow | Array[10] accesible en posición 15 | → BAI03 |
| **CWE-89** | Inyección SQL | `SELECT * FROM users WHERE id = [input]` | → BAI03 |
| **CWE-79** | Cross-site Scripting (XSS) | `<script>alert('hacked')</script>` en comentario | → DSS05 |

---
