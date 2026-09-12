from typing import Set, Tuple
import sqlglot
from sqlglot import exp


class SecurityViolation(Exception):
    """Excepción lanzada cuando el agente genera una consulta no autorizada."""
    pass


class DeterministicSQLGuard:
    def __init__(self, allowed_tables: Set[str]):
        # Lista blanca estricta de tablas permitidas
        self.allowed_tables = {t.lower() for t in allowed_tables}

    def validate_and_enforce_isolation(
        self, raw_sql: str, expected_user_id: int
    ) -> Tuple[bool, str]:
        """
        1. Valida que sea únicamente una operación de lectura (SELECT).
        2. Verifica que las tablas consultadas estén en la lista blanca.
        3. Fuerza el aislamiento de usuario inyectando o validando WHERE user_id = X.
        """
        try:
            # Parsear la consulta a un Árbol de Sintaxis Abstracta (AST)
            parsed_expressions = sqlglot.parse(raw_sql, read="sqlite")
        except Exception as e:
            raise SecurityViolation(f"Error de sintaxis SQL. Consulta inválida: {e}")

        # Evitar ataques de múltiples declaraciones (ej: SELECT 1; DROP TABLE users;)
        if len(parsed_expressions) != 1:
            raise SecurityViolation("Violación de seguridad: Múltiples sentencias SQL detectadas.")

        expression = parsed_expressions[0]

        # Regla 1: Validar que sea exclusivamente una lectura (SELECT)
        if not isinstance(expression, exp.Select):
            raise SecurityViolation(
                f"Operación no permitida: {expression.key.upper()}. Solo se autorizan consultas SELECT."
            )

        # Regla 2: Lista blanca estricta de tablas
        referenced_tables = {table.name.lower() for table in expression.find_all(exp.Table)}
        unauthorized_tables = referenced_tables - self.allowed_tables
        if unauthorized_tables:
            raise SecurityViolation(
                f"Acceso denegado a tablas no autorizadas: {', '.join(unauthorized_tables)}"
            )

        # Regla 3: Aislamiento forzado (Tenant Isolation) a nivel de AST
        # En lugar de confiar en el WHERE del LLM, inyectamos la cláusula obligatoria por código
        mandatory_condition = f"user_id = {expected_user_id}"
        secured_query = expression.where(mandatory_condition, copy=True)

        return True, secured_query.sql(dialect="sqlite")


# --- Demostración y Pruebas de Estrés ---

if __name__ == "__main__":
    guard = DeterministicSQLGuard(allowed_tables={"invoices", "orders"})
    current_session_user_id = 42

    print("=== CASO 1: Consulta legítima sin filtro del LLM ===")
    prompt_sql_1 = "SELECT id, amount, status FROM invoices"
    try:
        _, safe_sql = guard.validate_and_enforce_isolation(prompt_sql_1, current_session_user_id)
        print("SQL Original: ", prompt_sql_1)
        print("SQL Ejecutado:", safe_sql)
    except SecurityViolation as e:
        print("Bloqueado:", e)

    print("\n=== CASO 2: Intento de Inyección Destructiva (DROP TABLE) ===")
    prompt_sql_2 = "DROP TABLE users"
    try:
        _, safe_sql = guard.validate_and_enforce_isolation(prompt_sql_2, current_session_user_id)
        print("SQL Ejecutado:", safe_sql)
    except SecurityViolation as e:
        print("Bloqueado exitosamente:", e)

    print("\n=== CASO 3: Acceso a tabla sensible fuera de lista blanca ===")
    prompt_sql_3 = "SELECT name, api_key FROM users"
    try:
        _, safe_sql = guard.validate_and_enforce_isolation(prompt_sql_3, current_session_user_id)
        print("SQL Ejecutado:", safe_sql)
    except SecurityViolation as e:
        print("Bloqueado exitosamente:", e)

    print("\n=== CASO 4: Intento de bypass de inquilino (intentando ver datos del usuario 99) ===")
    # El LLM intenta consultar datos de otro usuario por manipulación del prompt
    prompt_sql_4 = "SELECT amount FROM invoices WHERE user_id = 99"
    try:
        _, safe_sql = guard.validate_and_enforce_isolation(prompt_sql_4, current_session_user_id)
        print("SQL Original: ", prompt_sql_4)
        print("SQL Ejecutado:", safe_sql)
        # Nota cómo el parser reescribe la condición combinándola lógicamente con AND
    except SecurityViolation as e:
        print("Bloqueado:", e)