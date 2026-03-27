# cve_risk_analyzer

Analiza vulnerabilidades CVE y evalúa riesgos no financieros de TI usando NIST y COBIT 2019. Extrae métricas de vulnerabilidades (CVSS, CWE, CPEs).

## Requisitos

- Python 3.8+
- Dependencias: ver [requirements.txt](requirements.txt)

## Instalación

```bash
pip install -r requirements.txt
```

## Uso

```bash
python cve_analyzer.py <CVE-ID>
```

**Ejemplo:**

```bash
python cve_analyzer.py CVE-2021-44228
```

## Salida

El script imprime por consola:

| Campo | Descripción |
|---|---|
| Descripción | Descripción en inglés de la vulnerabilidad |
| CVSS v3.1 | Score de Explotabilidad, Impacto, Base Score, Severity, Vector String |
| CPE (criteria) | Productos y versiones afectadas |
| CWE (weaknesses) | Tipos de debilidad asociados |

## Fuente de datos

API pública del NIST NVD: `https://services.nvd.nist.gov/rest/json/cves/2.0`
Sebastian Velasquez
