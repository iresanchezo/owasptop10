# OWASP Top 10

Aplicación web educativa e interactiva que explica los riesgos de seguridad más importantes de OWASP para aplicaciones web, móviles y modelos de lenguaje.

## Descripción

Este proyecto es una herramienta formativa enfocada en desarrolladores, estudiantes y profesionales de ciberseguridad. Ofrece explicaciones claras de las vulnerabilidades, ejemplos de explotación, riesgos asociados y recomendaciones de mitigación.

## Características principales

- **Categorías cubiertas:**
  - OWASP Top 10 Web
  - OWASP Top 10 Mobile
  - OWASP Top 10 LLM
- **Contenidos educativos:**
  - Descripción de la vulnerabilidad
  - Ejemplos prácticos de explotación
  - Evaluación de riesgo (impacto y probabilidad)
  - Exposición y consecuencias potenciales
  - Soluciones y buenas prácticas
  - Referencias CWE relevantes
- **Funciones interactivas:**
  - Menú de navegación superior con secciones Home, OWASP Top 10, Mobile, LLM, Quiz, Lab y Progreso
  - Quiz OWASP por niveles (Junior, Mid, Senior) con preguntas de selección, retroalimentación y desbloqueo de niveles según su puntuación
  - Lab de Seguridad con ejercicios de código para encontrar líneas vulnerables, pistas y comprobación automática
  - Lista lateral de categorías y búsqueda en tiempo real
  - Panel derecho con CWE relacionados
  - Modo oscuro activable
  - Seguimiento de progreso de lectura
- **Diseño responsivo:**
  - Interfaz adaptable a pantallas grandes y móviles
  - Sidebar móvil con overlay y accesibilidad mejorada

## Tecnologías utilizadas

- HTML5
- CSS3
- JavaScript vanilla
- Google Fonts (Montserrat Alternates)
- Tabler Icons (CDN)

## Estructura del proyecto

```
├── index.html          # Página principal HTML
├── script.js           # Lógica principal de la aplicación
├── styles.css          # Estilos CSS
├── app.js              # Archivo auxiliar / punto de entrada del paquete
├── package.json        # Configuración del proyecto Node.js
├── eslint.config.js    # Configuración de ESLint
├── resources/          # Imágenes y recursos estáticos
└── README.md           # Documentación del proyecto
```

## Requisitos

- Navegador moderno con JavaScript habilitado
- Conexión a internet para cargar fuentes y el paquete de iconos desde CDN

## Instalación y uso

1. Clonar o descargar el repositorio.
2. Abrir `index.html` directamente en el navegador.
3. No se requiere servidor ni dependencias adicionales para ejecutar la aplicación.

> Si desea usar ESLint localmente, instale las dependencias con `npm install`.

## Uso de la aplicación

1. Abra la aplicación en el navegador.
2. Use el menú superior para cambiar entre Home, OWASP Top 10, Mobile, LLM, Quiz, Lab y Progreso.
3. Seleccione una categoría en la barra lateral para ver su contenido.
4. Utilice el campo de búsqueda para filtrar vulnerabilidades.
5. Active el modo oscuro con el botón del encabezado.
6. Revise los CWEs relacionados en el panel derecho.8. Acceda a las secciones Quiz y Lab para practicar con preguntas y ejercicios interactivos.

## Quiz y Lab

- **Quiz OWASP:** seleciona nivel Junior, Mid o Senior para responder 10 preguntas de seguridad. El sistema ofrece retroalimentación inmediata, muestra resultados y desbloquea niveles superiores si alcanzas el umbral mínimo.
- **Lab de Seguridad:** elige un nivel y revisa fragmentos de código reales. Marca las líneas que crees inseguras, utiliza pistas y comprueba tus respuestas con una evaluación automática. El progreso de la sesión se guarda y permite avanzar según aciertos.
## Contenido educativo

Cada sección de vulnerabilidad puede incluir:

- **ID y nombre**
- **Descripción**
- **Ejemplos de explotación**
- **Riesgo e impacto**
- **Exposición/consecuencias**
- **Soluciones y mitigaciones**
- **Referencias CWE**

## Recursos útiles

- [OWASP Foundation](https://owasp.org/)
- [OWASP Cheat Sheet Series](https://cheatsheetseries.owasp.org/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP Mobile Top 10](https://owasp.org/www-project-mobile-top-10/)
- [OWASP Top 10 LLM](https://owasp.org/www-project-top-10-for-large-language-model-applications/)

## Nota

Este proyecto es exclusivamente educativo y busca fomentar la conciencia en seguridad. Use la información como punto de partida y consulte las fuentes oficiales de OWASP para profundizar.
