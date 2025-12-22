# 🛡️ Container Audit Botiquín

Herramienta integral de **Ciberseguridad** diseñada para analistas y equipos de DevSecOps. Este script automatiza la auditoría de contenedores siguiendo principios de **Security by Design**.

## 🚀 Características principales
- **Análisis Estático (Linter):** Evaluación de Dockerfiles mediante `Hadolint`.
- **Escaneo de Vulnerabilidades (SCA):** Detección de CVEs y secretos con `Trivy`.
- **Hardening de Infraestructura:** Auditoría basada en el estándar **CIS Benchmark**.
- **Seguridad en Tiempo Real:** Monitorización de alertas con `Falco`.
- **Modo Zero-Trust:** Auditoría total automatizada.
- **Interfaz Silenciosa:** Terminal limpia con indicadores visuales de progreso.

## 🛠️ Instalación y Uso
1. Clonar: `git clone https://github.com/TU_USUARIO/container-audit-botiquin.git`
2. Permisos: `chmod +x container-audit-toolkit.sh`
3. Ejecutar: `./container-audit-toolkit.sh -z`

## 🚧 Roadmap y Mejoras Futuras
El proyecto está en desarrollo constante. Próximamente:
- [ ] Integración de alertas vía Webhooks (Slack/Discord).
- [ ] Soporte para auditoría de Kubernetes (K8s).
- [ ] Exportación de reportes en formato HTML/PDF.
- [ ] Escaneo de secretos mejorado con reglas personalizadas.
- [ ] Mejora de reportes para integracion con Wazuh.

## 🤝 Contribuciones
¿Has encontrado un bug o tienes una idea? ¡Tus aportaciones son bienvenidas!
- Abre un **Issue** para discutir mejoras.
- Envía un **Pull Request** con tus cambios.

## 👤 Autor
**Alejandro fernandes aka vernizus** - *Analista de Ciberseguridad*
Enfocado en la optimización de infraestructura y seguridad desde el diseño.
¡Cualquier sugerencia es bienvenida para seguir mejorando esta herramienta!
