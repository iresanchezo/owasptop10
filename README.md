# OWASP Top 10 4devs

Una aplicación web educativa interactiva que proporciona información detallada sobre los 10 riesgos de seguridad web más críticos según OWASP.

## Descripción

OWASP Top 10 4devs es una herramienta educativa diseñada para desarrolladores, estudiantes y profesionales de ciberseguridad. Permite explorar y comprender las vulnerabilidades de seguridad web más comunes, sus impactos, ejemplos prácticos y soluciones recomendadas.

## Características principales

- **Múltiples categorías de seguridad:**
  - OWASP Top 10 (Riesgos web generales)
  - OWASP Top 10 Mobile (Riesgos específicos para aplicaciones móviles)
  - OWASP Top 10 LLM (Riesgos relacionados con modelos de lenguaje)

- **Información detallada por vulnerabilidad:**
  - Descripción clara y comprensible
  - Ejemplos reales de explotación
  - Evaluación de riesgo (probabilidad e impacto)
  - Exposición/consecuencias potenciales
  - Soluciones y mejores prácticas de remediación
  - Referencias a CWE (Common Weakness Enumeration)

- **Interfaz intuitiva:**
  - Navegación lateral izquierda con categorías
  - Panel derecho con referencias CWE relacionadas
  - Diseño responsivo y amigable
  - Contenido principal con toda la información

- **Diseño educativo:**
  - Lenguaje claro y accesible
  - Estructura organizada y fácil de navegar
  - Enlaces a recursos oficiales de OWASP

## Tecnologías utilizadas

- **Frontend:** HTML5, CSS3, JavaScript (Vanilla)
- **Estilos:** CSS personalizado con variables CSS y flexbox
- **Arquitectura:** Single Page Application (SPA)
- **Fuentes:** Google Fonts (Montserrat Alternates)

## Estructura del proyecto

```
├── index.html          # Página principal HTML
├── script.js           # Lógica de navegación y renderizado dinámico
├── app.js              # Archivo principal de la aplicación
├── styles.css          # Estilos CSS de la aplicación
├── package.json        # Configuración del proyecto Node.js
├── eslint.config.js    # Configuración de ESLint
├── resources/          # Recursos estáticos (logos, imágenes)
└── README.md           # Este archivo
```

## Instalación

1. Clonar o descargar el repositorio
2. No se requieren dependencias especiales para ejecutar la aplicación
3. Abrir `index.html` en el navegador web

### Desarrollo

Para desarrollo, se utiliza ESLint para mantener la calidad del código:

```bash
npm install
npm test
```

## Cómo usar

1. Abrir la aplicación en el navegador
2. Seleccionar una categoría desde el menú superior (Home, OWASP Top 10, Mobile, LLM)
3. Explorar las vulnerabilidades desde la lista lateral
4. Leer la información detallada en el panel central
5. Consultar los CWEs relacionados en el panel derecho

## Contenido educativo

Cada vulnerabilidad incluye:

- **ID y Nombre:** Identificador único y nombre de la vulnerabilidad
- **Descripción:** Explicación clara del riesgo de seguridad
- **Ejemplos:** Casos prácticos de explotación
- **Riesgo:** Evaluación de probabilidad e impacto
- **Exposición:** Posibles consecuencias del ataque
- **Soluciones:** Medidas de remediación y mejores prácticas
- **Referencias CWE:** Enlaces a debilidades comunes asociadas

## Recursos y enlaces

- [OWASP Foundation](https://owasp.org/)
- [OWASP Cheat Sheets Series](https://cheatsheetseries.owasp.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)

## Nota

Este es un proyecto educativo diseñado para mejorar la conciencia sobre seguridad web. Se recomienda usar la información aquí proporcionada como base para aprender más sobre seguridad y consultar recursos oficiales de OWASP.
