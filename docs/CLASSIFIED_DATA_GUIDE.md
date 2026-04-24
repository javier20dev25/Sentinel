# Sentinel: Guía de Gestión de Datos Clasificados

Esta guía detalla el protocolo para manejar información sensible y archivos protegidos dentro del ecosistema Sentinel.

---

## 1. El Concepto de "Archivo Clasificado"

En Sentinel, un archivo o directorio se considera **Clasificado** cuando ha sido añadido a la lista de protección. Esto garantiza que:
1. Sentinel bloquee cualquier intento de subir el archivo a repositorios remotos (GitHub/GitLab).
2. El motor de reglas (`scan`) aplique heurísticas de "Silencio Táctico" sobre estos archivos.
3. Los agentes de IA deban tratar el contenido con precaución extrema.

---

## 2. Cómo Clasificar Información

Para proteger un activo sensible:

```bash
sentinel protected add path/to/sensitive_file.txt
```

Esto genera un `ID` único para el activo y lo registra en la base de datos de gobernanza local.

### Cuándo clasificar:
- Archivos `.env` o de configuración con secretos.
- Llaves SSH (`id_rsa`).
- Documentos de diseño de seguridad interna.
- Credenciales de bases de datos o APIs.

---

## 3. Protocolo de Desclasificación (Humano-Único)

> [!CAUTION]
> **REGLA DE ORO**: La desclasificación de activos es una acción reservada exclusivamente para operadores humanos.

### Restricciones para Agentes de IA:
- Un agente de IA **NUNCA** debe ejecutar `sentinel protected remove`.
- Si un agente detecta que un archivo necesario para la ejecución está bloqueado, debe **informar al humano** y solicitar que este realice la desclasificación manualmente.

### Procedimiento para Humanos:
1. Listar los activos para encontrar el ID:
   ```bash
   sentinel protected list
   ```
2. Remover la protección usando el ID:
   ```bash
   sentinel protected remove <ID>
   ```

---

## 4. Auditoría de Activos Protegidos

Sentinel mantiene un registro de auditoría de cada operación sobre activos clasificados en `~/.sentinel/audit.jsonl`. 

- **Evento `PROTECT`**: Registra quién y cuándo clasificó un archivo.
- **Evento `UNPROTECT`**: Registra la desclasificación. Si este evento ocurre sin una instrucción humana directa en el historial de comandos, se considera una **Violación de Política de Seguridad**.

---

## 5. Oracle Mode y Archivos Clasificados

Cuando Sentinel escanea archivos clasificados y detecta una amenaza, el **Oracle Mode** entra en acción:
- Si el usuario no está verificado (vía `gh auth`), los detalles técnicos de la vulnerabilidad en el archivo clasificado serán **redactados**.
- Esto previene que un atacante use Sentinel para descubrir qué secretos o fallos hay dentro de un archivo al que no debería tener acceso detallado.
