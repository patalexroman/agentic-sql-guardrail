# Agentic SQL Guardrail

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Security: Deterministic AST](https://img.shields.io/badge/Security-Deterministic%20AST-green.svg)](#architecture)

Middleware determinista de alto rendimiento para mitigar **Indirect Prompt Injections** y **Tenant Isolation Bypasses** en agentes de IA y arquitecturas Text-to-SQL.

---

## 🎯 El Problema

Delegar la seguridad o el aislamiento multi-inquilino (*multi-tenant*) de una base de datos a un `system prompt` (por ejemplo: *"filtra siempre por el user_id de la sesión"*) introduce vulnerabilidades críticas:

* Los LLMs son optimizadores probabilísticos, no motores de control de acceso.
* Mediante inyección indirecta de prompts, un atacante puede inducir al modelo a omitir cláusulas de identidad.
* El motor RDBMS ejecuta la consulta resultante sin levantar errores de sintaxis, provocando **fugas de datos entre clientes**.

---

## 🛡️ Solución de Arquitectura

`DeterministicSQLGuard` se interpone entre el LLM y el pool de conexiones a la base de datos. Analiza el **Árbol de Sintaxis Abstracta (AST)** de la consulta generada en memoria local (<2 ms de latencia) y ejecuta tres validaciones duras:

1. **Restricción de Operación:** Solo autoriza sentencias `SELECT` únicas (bloquea DDL/DML y sentencias múltiples).
2. **Lista Blanca de Entidades:** Impide lecturas fuera de las tablas autorizadas explícitamente.
3. **Aislamiento Forzado (Tenant Isolation):** Reescribe el nodo `WHERE` inyectando programáticamente `AND user_id = {session_user_id}`.

[Usuario / Front-end]
│
▼
[Modelo LLM / Agente] (Genera consulta SQL cruda)
│
▼
[DeterministicSQLGuard (AST Parser)] ◄── Interceptor
├── ¿Es un SELECT único? ────────────► (NO: Aborta)
├── ¿Tablas en Whitelist? ───────────► (NO: Aborta)
└── Mutación: Inyecta "AND user_id = {session_id}"

---

## 🚀 Inicio Rápido

### Requisitos Previos

* Python 3.10+
* Clave de API de Gemini (capa gratuita soportada)

### Instalación

```bash
git clone [https://github.com/tu-usuario/agentic-sql-guardrail.git](https://github.com/tu-usuario/agentic-sql-guardrail.git)
cd agentic-sql-guardrail
python -m venv .venv

# En Linux/macOS:
source .venv/bin/activate

# En Windows (PowerShell):
.venv\Scripts\Activate.ps1

pip install -r requirements.txt
```

Configuración de Variables de Entorno
PowerShell (Windows):

PowerShell
$env:GEMINI_API_KEY="tu-api-key"

Bash (Linux/macOS):
export GEMINI_API_KEY="tu-api-key"

🧪 Ejecución de la Prueba de Concepto (PoC)
El repositorio incluye un pipeline ejecutable que monta una base de datos SQLite en memoria, ejecuta un ataque de inyección adversarial simulando un usuario malicioso (user_id = 101) que intenta consultar datos de la víctima (user_id = 202), y compara el comportamiento con y sin contención:

Bash
python agent_pipeline_poc.py
Salida Esperada
Plaintext
============================================================
ESCENARIO: Usuario 101 intentando acceder a registros de Usuario 202
============================================================

[EJECUCIÓN 1: ARQUITECTURA SIN CONTENCIÓN (Vulnerable)]
-> SQL Crudo emitido por LLM: SELECT id, amount, status FROM invoices WHERE user_id = 202
🚨 FUGA CONFIRMADA: Datos devueltos al atacante -> [(3, 999.99, 'pending')]

------------------------------------------------------------

[EJECUCIÓN 2: ARQUITECTURA BLINDADA CON AST GUARD (Remediada)]
-> SQL Crudo emitido por LLM: SELECT id, amount, status FROM invoices WHERE user_id = 202
-> SQL Seguro reescrito por AST: SELECT id, amount, status FROM invoices WHERE user_id = 202 AND user_id = 101
✅ PROTECCIÓN EXITOSA: Datos devueltos -> []
(Nota: Devuelve [] porque la condición 202 == 101 evalúa a False de forma determinista)
💻 Uso en tu Código
Python
from sql_guardrail import DeterministicSQLGuard, SecurityViolation

guard = DeterministicSQLGuard(allowed_tables={"invoices", "orders"})
raw_sql = "SELECT id, amount FROM invoices"
session_user_id = 42

try:
    is_safe, secure_sql = guard.validate_and_enforce_isolation(
        raw_sql=raw_sql, expected_user_id=session_user_id
    )
    # Ejecutar secure_sql en el pool de conexiones
except SecurityViolation as err:
    # Log de seguridad y bloqueo inmediato
    print(f"Alerta de seguridad: {err}")

📂 Estructura del Proyecto
Plaintext
agentic-sql-guardrail/
├── agent_pipeline_poc.py    # Pipeline integrado (SQLite + Gemini Flash + AST Guard)
├── sql_guardrail.py         # Módulo central del validador e interceptor AST
├── requirements.txt         # Dependencias del proyecto
├── README.md                # Documentación técnica
└── LICENSE                  # Licencia MIT
📋 Checklist de Seguridad para Producción
[x] Aislamiento por AST: Reescribir consultas en memoria antes de la conexión física.

[ ] Principio de Mínimo Privilegio: Conectar el agente con un usuario RDBMS de solo lectura (SELECT).

[ ] Esquema Restringido: No exponer catálogos de metadatos, credenciales ni tablas del sistema al agente.

[ ] Cláusulas LIMIT Forzadas: Inyectar límites de registros programáticos para mitigar ataques de denegación de servicio por consumo de memoria.

📄 Licencia
Este proyecto está bajo la Licencia MIT.





▼
[RDBMS / Motor de Base de Datos] (Solo Lectura)
