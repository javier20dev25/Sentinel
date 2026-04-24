# Sentinel Safe Modification Guide (v3.7)

Este documento es una guía crítica para administradores de seguridad y equipos de DevOps que deseen personalizar el motor de decisión de Sentinel. El ajuste incorrecto de los parámetros de riesgo puede crear "puntos ciegos" que permitan la entrada de malware en el pipeline.

## 1. Ajuste de Umbrales (Thresholds)

El umbral determina qué tan "paranoico" es Sentinel.
- **ALERTA**: Nunca establezca un umbral por debajo de **0.50**. Un umbral bajo puede causar un bloqueo sistémico ante cualquier ruido mínimo de herramientas externas.
- **RECOMENDACIÓN**: Para entornos bancarios o de infraestructura crítica, el umbral de `strict` debe mantenerse entre **0.55 y 0.65**.

## 2. Gestión de la Matriz de Confianza

Los factores de confianza (`ConfidenceMatrix`) reflejan cuánto cree Sentinel en el origen de una señal.
- **NUNCA** eleve la confianza de `external:ai` por encima de **0.80**. Las señales de IA son inherentemente probabilísticas y propensas a alucinaciones de seguridad.
- **HIERRO**: La confianza de `internal` siempre debe ser >= 0.95 para garantizar que las detecciones determinísticas de Sentinel tengan precedencia.

## 3. Integridad del Modelo de Correlación (Dampening)

El amortiguador evita la fatiga de alertas, pero puede ser abusado por un atacante.
- **PELIGRO**: No baje el factor `samePackage` por debajo de **0.40**. Si lo hace, un paquete con 10 vulnerabilidades críticas podría puntuar menos que un solo hallazgo interno, permitiendo ataques de supply chain complejos.

## 4. Hard Overrides (Reglas Intocables)

Sentinel está diseñado para que ciertas detecciones superen cualquier arbitraje estadístico.
- No modifique la regla que bloquea hallazgos **CRITICAL** internos.
- Si desactiva el bloqueo de amenazas internas críticas, está convirtiendo a Sentinel en un sistema puramente informativo, perdiendo su función de "Gatekeeper".

## 5. Procedimiento de Cambio Seguro

1. **Simulación**: Ejecute Sentinel con el nuevo perfil sobre un repositorio de prueba que contenga hallazgos conocidos (test-bench).
2. **Auditoría de Falsos Negativos**: Verifique que el nuevo perfil no haya dejado pasar ninguna amenaza que el perfil anterior detectaba.
3. **Rollout Gradual**: Aplique los cambios primero en entornos de `dev` antes de actualizar los pipelines de `prod`.
