"""
CVE Risk Analyzer - Etapa 1
Consulta la API de NIST NVD y extrae métricas clave de una vulnerabilidad CVE.
"""

import sys
import json
import requests


NIST_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_cve(cve_id: str) -> dict:
    """Consulta la API de NIST NVD y retorna el JSON de la vulnerabilidad."""
    params = {"cveId": cve_id}
    response = requests.get(NIST_API_URL, params=params, timeout=15)
    response.raise_for_status()
    data = response.json()

    vulnerabilities = data.get("vulnerabilities", [])
    if not vulnerabilities:
        raise ValueError(f"No se encontró información para {cve_id}")

    return vulnerabilities[0].get("cve", {})


def extract_description(cve_data: dict) -> str:
    """Extrae la descripción en inglés de la vulnerabilidad."""
    descriptions = cve_data.get("descriptions", [])
    for desc in descriptions:
        if desc.get("lang") == "en":
            return desc.get("value", "N/A")
    return descriptions[0].get("value", "N/A") if descriptions else "N/A"


def extract_cvss_metrics(cve_data: dict) -> dict:
    """Extrae métricas CVSS v3.1."""
    metrics = cve_data.get("metrics", {})
    cvss_list = metrics.get("cvssMetricV31", [])

    if not cvss_list:
        return {}

    cvss = cvss_list[0]
    cvss_data = cvss.get("cvssData", {})

    return {
        "exploitabilityScore": cvss.get("exploitabilityScore", "N/A"),
        "impactScore": cvss.get("impactScore", "N/A"),
        "baseScore": cvss_data.get("baseScore", "N/A"),
        "baseSeverity": cvss_data.get("baseSeverity", "N/A"),
        "vectorString": cvss_data.get("vectorString", "N/A"),
    }


def extract_cpe(cve_data: dict) -> list[str]:
    """Extrae los criterios CPE de las configuraciones."""
    cpe_criteria = []
    configurations = cve_data.get("configurations", [])

    for config in configurations:
        for node in config.get("nodes", []):
            for match in node.get("cpeMatch", []):
                criteria = match.get("criteria")
                if criteria:
                    cpe_criteria.append(criteria)

    return cpe_criteria


def extract_cwe(cve_data: dict) -> list[str]:
    """Extrae los valores CWE de las debilidades."""
    cwe_values = []
    weaknesses = cve_data.get("weaknesses", [])

    for weakness in weaknesses:
        for desc in weakness.get("description", []):
            value = desc.get("value")
            if value:
                cwe_values.append(value)

    return cwe_values


def analyze_cve(cve_id: str) -> None:
    """Orquesta la consulta y muestra los resultados formateados."""
    print(f"\n{'='*60}")
    print(f"  Análisis CVE: {cve_id}")
    print(f"{'='*60}\n")

    cve_data = fetch_cve(cve_id)

    # Descripción
    description = extract_description(cve_data)
    print(f"DESCRIPCIÓN:\n  {description}\n")

    # Métricas CVSS v3.1
    cvss = extract_cvss_metrics(cve_data)
    print("MÉTRICAS CVSS v3.1:")
    if cvss:
        print(f"  Score de Explotabilidad : {cvss['exploitabilityScore']}")
        print(f"  Score de Impacto        : {cvss['impactScore']}")
        print(f"  Base Score              : {cvss['baseScore']}")
        print(f"  Base Severity           : {cvss['baseSeverity']}")
        print(f"  Vector String           : {cvss['vectorString']}")
    else:
        print("  No se encontraron métricas CVSS v3.1")
    print()

    # CPE
    cpe_list = extract_cpe(cve_data)
    print("CPE (criteria):")
    if cpe_list:
        for cpe in cpe_list:
            print(f"  - {cpe}")
    else:
        print("  No se encontraron entradas CPE")
    print()

    # CWE
    cwe_list = extract_cwe(cve_data)
    print("CWE (weaknesses):")
    if cwe_list:
        for cwe in cwe_list:
            print(f"  - {cwe}")
    else:
        print("  No se encontraron debilidades CWE")
    print()


def main():
    if len(sys.argv) != 2:
        print("Uso: python cve_analyzer.py <CVE-ID>")
        print("Ejemplo: python cve_analyzer.py CVE-2021-44228")
        sys.exit(1)

    cve_id = sys.argv[1].strip().upper()

    if not cve_id.startswith("CVE-"):
        print(f"Error: El formato debe ser CVE-AÑO-NUMERACIÓN (ej. CVE-2021-44228)")
        sys.exit(1)

    analyze_cve(cve_id)


if __name__ == "__main__":
    main()
