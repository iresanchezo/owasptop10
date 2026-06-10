// script.js
// Lógica de navegación y renderizado dinámico para OWASP Top 10 4devs

// Datos OWASP Top 10 normal (categorías 1-10)
const owaspTop10 = {
  categories: [
    {
      id: 'A01',
      name: 'Broken Access Control',
      description: 'Las restricciones sobre lo que los usuarios pueden hacer no siempre se aplican correctamente. Los atacantes pueden explotar estas fallas para acceder a funcionalidades y/o datos no autorizados.',
      examples: [
        'Un usuario cambia el ID de una URL y accede a los datos de otro usuario.',
        'Un empleado sin permisos accede al panel de administración.',
        'Un cliente puede ver o modificar pedidos de otros clientes.'
      ],
      risk: 'Alto',
      impact: 'Acceso no autorizado a datos o funciones',
      likelihood: 'Alta',
      cwes: ["CWE-284", "CWE-285"],
      exposure: [
        'Acceso no autorizado a datos sensibles de otros usuarios.',
        'Modificación o eliminación de información ajena.',
        'Escalada de privilegios y control total de la aplicación.',
        'Compromiso de la privacidad y reputación de la organización.'
      ],
      solution: [
        'Aplicar el principio de mínimo privilegio.',
        'Validar permisos en el servidor, no solo en la interfaz.',
        'Revisar periódicamente roles y permisos.',
        'Restringir el acceso a recursos sensibles mediante autorización.'
      ]
    },
    {
      id: 'A02',
      name: 'Cryptographic Failures',
      description: 'Fallas relacionadas con la criptografía, como la exposición de datos sensibles debido a una protección inadecuada.',
      examples: [
        'Contraseñas almacenadas en texto plano.',
        'Datos personales enviados por HTTP en lugar de HTTPS.',
        'Uso de algoritmos de cifrado obsoletos como MD5 o SHA-1.'
      ],
      risk: 'Alto',
      impact: 'Exposición o manipulación de datos sensibles',
      likelihood: 'Alta',
      cwes: ["CWE-311", "CWE-319"],
      exposure: [
        'Datos sensibles pueden quedar accesibles sin protección fuerte.',
        'Información en tránsito puede ser interceptada y leída.',
        'Contraseñas o claves pueden perder su confidencialidad.',
        'El sistema puede ser vulnerado a través de cifrado débil o mal uso de certificados.'
      ],
      solution: [
        'Cifrar los datos sensibles en tránsito y reposo.',
        'Utilizar algoritmos de cifrado actualizados.',
        'Gestionar correctamente las claves criptográficas.',
        'Obligar al uso de HTTPS/TLS.'
      ]
    },
    {
      id: 'A03',
      name: 'Injection',
      description: `El código malicioso se mezcla con datos normales y el servidor lo ejecuta como si fuera parte de la aplicación.
Los tipos de inyección más comunes son:

- SQL Injection (inyecciones en consultas a bases de datos)
- Command Injection (ejecución de comandos del sistema)
- LDAP Injection (inyecciones en consultas LDAP)
- XML Injection (inyecciones en consultas XML)
- Code Injection (inyección de código ejecutable)
`,
      injectionTypeCwes: [
        { type: 'SQL Injection', cwe: 'CWE-89' },
        { type: 'Command Injection', cwe: 'CWE-78' },
        { type: 'LDAP Injection', cwe: 'CWE-90' },
        { type: 'XML Injection', cwe: 'CWE-74' },
        { type: 'Code Injection', cwe: 'CWE-94' }
      ],
      examples: [
        "Introducir cadenas maliciosas en un formulario de login para acceder sin credenciales.",
        'Ejecutar comandos del sistema mediante una entrada manipulada.',
        'Alterar una consulta SQL para extraer datos de la base de datos.'
      ],
      risk: 'Alto',
      impact: 'Ejecución de comandos no deseados o robo de información',
      likelihood: 'Alta',
      cwes: ["CWE-89", "CWE-74"],
      exposure: [
        'Ordenes maliciosas pueden ejecutarse en la base de datos.',
        'Se pueden extraer datos privados directamente de la aplicación.',
        'El atacante puede manipular respuestas o lógica interna.',
        'La integridad del sistema queda comprometida por entradas no validadas.'
      ],
      solution: [
        'Utilizar consultas parametrizadas (prepared statements).',
        'Validar y sanitizar las entradas de usuario.',
        'Evitar construir consultas mediante concatenación de texto.',
        'Aplicar el principio de mínimo privilegio en bases de datos.'
      ]
    },
    {
      id: 'A04',
      name: 'Insecure Design',
      description: 'El diseño no considera amenazas claras y crea agujeros de seguridad desde el principio.',
      examples: [
        'Una aplicación bancaria permite transferencias sin límite de importe.',
        'No existe validación para evitar compras masivas automatizadas.',
        'Una funcionalidad crítica no requiere autenticación.'
      ],
      risk: 'Alto',
      impact: 'Vulnerabilidades difíciles de corregir y mal diseño de seguridad',
      likelihood: 'Media',
      cwes: ["CWE-676", "CWE-749"],
      exposure: [
        'La seguridad es reactiva en lugar de parte del diseño.',
        'Errores de lógica quedan descubiertos solo en producción.',
        'Falta control de requisitos seguros desde el inicio.',
        'Los componentes críticos pueden ser inseguros por mala arquitectura.'
      ],
      solution: [
        'Incorporar la seguridad desde la fase de diseño.',
        'Realizar análisis de riesgos y modelado de amenazas.',
        'Definir requisitos de seguridad claros.',
        'Revisar la arquitectura antes del desarrollo.'
      ]
    },
    {
      id: 'A05',
      name: 'Security Misconfiguration',
      description: 'Configuraciones inseguras o valores por defecto dejan la aplicación vulnerable a ataques conocidos.',
      examples: [
        'Mantener las credenciales por defecto del sistema.',
        'Dejar habilitado el modo depuración en producción.',
        'Exponer directorios o archivos sensibles públicamente.'
      ],
      risk: 'Alto',
      impact: 'Acceso no autorizado a datos, administración o recursos internos',
      likelihood: 'Alta',
      cwes: ["CWE-16", "CWE-306"],
      exposure: [
        'Configuraciones abiertas permiten acceso no deseado a servicios y recursos.',
        'Funciones administrativas pueden quedar expuestas sin protección.',
        'La aplicación puede usar valores por defecto inseguros o no cambiar claves.',
        'Errores de configuración permiten ataques fáciles y conocidos.'
      ],
      solution: [
        'Eliminar configuraciones por defecto.',
        'Mantener sistemas y aplicaciones actualizados.',
        'Deshabilitar servicios innecesarios.',
        'Revisar periódicamente las configuraciones de seguridad.'
      ]
    },
    {
      id: 'A06',
      name: 'Vulnerable and Outdated Components',
      description: 'Componentes de terceros desactualizados o con vulnerabilidades conocidas siguen presentes en la aplicación y pueden explotarse fácilmente.',
      examples: [
        'Utilizar una librería con vulnerabilidades conocidas sin actualizar.',
        'Ejecutar una versión antigua del servidor web.',
        'Mantener un plugin desactualizado con fallos de seguridad públicos.'
      ],
      risk: 'Alto',
      impact: 'Explotación de fallas conocidas en librerías, frameworks o plugins',
      likelihood: 'Alta',
      cwes: ["CWE-1104", "CWE-1327"],
      exposure: [
        'Librerías y dependencias antiguas pueden tener vulnerabilidades ya publicadas.',
        'Un componente inseguro puede abrir la puerta a ransomware, fuga de datos o toma de control.',
        'La aplicación queda expuesta a ataques conocidos y fáciles de automatizar.',
        'La falta de actualización aumenta el tiempo de exposición frente a correcciones disponibles.'
      ],
      solution: [
        'Mantener librerías y dependencias actualizadas.',
        'Inventariar los componentes utilizados.',
        'Monitorizar vulnerabilidades conocidas.',
        'Eliminar software que ya no se utiliza.'
      ]
    },
    {
      id: 'A07',
      name: 'Identification and Authentication Failures',
      description: 'Los mecanismos de autenticación o gestión de sesiones no se aplican correctamente, lo que permite suplantar usuarios o acceder sin credenciales válidas.',
      examples: [
        'Permitir contraseñas débiles como "123456".',
        'No bloquear cuentas tras múltiples intentos fallidos.',
        'Mantener sesiones activas durante largos periodos sin expiración.'
      ],
      risk: 'Alto',
      impact: 'Suplantación de identidad, acceso a cuentas y sesiones comprometidas',
      likelihood: 'Alta',
      cwes: ["CWE-287", "CWE-384", "CWE-613"],
      exposure: [
        'Los atacantes pueden tomar el control de cuentas de usuarios legítimos.',
        'Las sesiones pueden fijarse o permanecer válidas más de lo debido.',
        'La recuperación de contraseñas o la verificación de identidad puede ser débil.',
        'Se compromete la confianza y la integridad de la aplicación.'
      ],
      solution: [
        'Implementar autenticación multifactor (MFA).',
        'Exigir contraseñas robustas.',
        'Bloquear cuentas tras varios intentos fallidos.',
        'Gestionar correctamente las sesiones de usuario.'
      ]
    },
    {
      id: 'A08',
      name: 'Software and Data Integrity Failures',
      description: 'La aplicación no verifica adecuadamente la integridad del software, los datos o las actualizaciones, permitiendo manipulaciones maliciosas.',
      examples: [
        'Instalar actualizaciones sin verificar su procedencia.',
        'Descargar dependencias de repositorios no confiables.',
        'Permitir que un atacante modifique el proceso de despliegue.'
      ],
      risk: 'Alto',
      impact: 'Manipulación de datos, actualizaciones no confiables o cargas maliciosas',
      likelihood: 'Media',
      cwes: ["CWE-345", "CWE-353", "CWE-502"],
      exposure: [
        'Los datos o paquetes de despliegue pueden ser alterados en tránsito o almacenamiento.',
        'Las actualizaciones o plugins pueden venir de fuentes no verificadas.',
        'La deserialización de entradas no confiables puede provocar ejecuciones inesperadas.',
        'Se rompe la confianza en la integridad de la aplicación y su contenido.'
      ],
      solution: [
        'Verificar la integridad de archivos y actualizaciones.',
        'Firmar digitalmente el código.',
        'Proteger los procesos CI/CD.',
        'Validar el origen de las dependencias externas.'
      ]
    },
    {
      id: 'A09',
      name: 'Security Logging and Monitoring Failures',
      description: 'La app no registra ni detecta eventos de seguridad de forma suficiente, dificultando la identificación y respuesta ante incidentes.',
      examples: [
        'No registrar intentos fallidos de inicio de sesión.',
        'No generar alertas ante accesos sospechosos.',
        'Detectar una brecha de seguridad meses después por falta de monitorización.'
      ],
      risk: 'Medio',
      impact: 'Incidentes no detectados y tiempos de respuesta muy largos',
      likelihood: 'Media',
      cwes: ["CWE-223", "CWE-532", "CWE-778"],
      exposure: [
        'Los ataques pueden pasar desapercibidos durante mucho tiempo.',
        'No hay evidencia útil para investigar un incidente o una filtración.',
        'La respuesta ante compromisos puede ser lenta o inexistente.',
        'La organización pierde visibilidad sobre la seguridad operativa.'
      ],
      solution: [
        'Registrar eventos de seguridad relevantes.',
        'Monitorizar accesos y actividades sospechosas.',
        'Configurar alertas automáticas.',
        'Revisar periódicamente los registros.'
      ]
    },
    {
      id: 'A10',
      name: 'Server-Side Request Forgery',
      description: 'El servidor realiza peticiones a direcciones URL controladas por un atacante, pudiendo acceder a recursos internos o externos no previstos.',
      examples: [
        'Permitir que el usuario introduzca cualquier URL para que el servidor la consulte.',
        'Acceder a servicios internos a través de URLs manipuladas.',
        'Obtener información de recursos internos que no deberían ser accesibles desde Internet.'
      ],
      risk: 'Alto',
      impact: 'Acceso a servicios internos, metadatos o recursos sensibles del servidor',
      likelihood: 'Media',
      cwes: ["CWE-918", "CWE-20"],
      exposure: [
        'Un atacante puede forzar peticiones a servicios internos y extraer información confidencial.',
        'Se pueden escanear puertos, acceder a APIs internas o provocar cargas externas.',
        'La aplicación actúa como proxy no autorizado para terceros.',
        'Se expone la infraestructura subyacente a ataques y filtraciones.'
      ],
      solution: [
        'Validar y restringir las URLs permitidas.',
        'Utilizar listas blancas de destinos autorizados.',
        'Segmentar la red para limitar accesos internos.',
        'Bloquear peticiones hacia servicios internos innecesarios.'
      ]
    }
  ],
  cwes: {
    "CWE-16": "Configuration",
    "CWE-20": "Improper Input Validation",
    "CWE-74": "Improper Neutralization of Special Elements in Output Used by a Downstream Component",
    "CWE-89": "SQL Injection",
    "CWE-223": "Omission of Security-relevant Information",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-311": "Missing Encryption of Sensitive Data",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-345": "Insufficient Verification of Data Authenticity",
    "CWE-353": "Missing Support for Integrity Check",
    "CWE-384": "Session Fixation",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-613": "Insufficient Session Expiration",
    "CWE-676": "Use of Potentially Dangerous Function",
    "CWE-749": "Incomplete Requirements",
    "CWE-778": "Insufficient Logging",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1104": "Use of Unmaintained Third Party Components",
    "CWE-1327": "Binding to an Unrestricted IP Address",
    "CWE-284": "Improper Access Control",
    "CWE-285": "Improper Authorization"
  }
};

// Datos OWASP Top 10 Mobile (solo 1-5)
const owaspMobile = {
  categories: [
    {
      id: 'M01',
      name: 'Uso incorrecto de la plataforma',
      description: 'La app usa mal permisos, APIs o servicios del sistema, lo que abre huecos de seguridad específicos de móvil.',
      risk: 'Alto',
      impact: 'Permite acceso a funciones o datos que no debería tener la app',
      likelihood: 'Alta',
      cwes: ["CWE-269", "CWE-284"],
      exposure: [
        'Permisos excesivos permiten a la app acceder a datos y funciones sin control.',
        'APIs inseguras abren puertas a fugas de datos o suplantación.',
        'El uso indebido de componentes del sistema puede exponer información privada.',
        'La app puede ser manipulada para ejecutar acciones no previstas.'
      ]
      ,
      examples: [
        'La app solicita permisos de ubicación y acceso a contactos sin justificación.',
        'Uso de APIs privadas o no documentadas que exponen funciones sensibles.',
        'Un Intent mal validado permite abrir actividades protegidas desde otra app.'
      ],
      solution: [
        'Solicitar únicamente los permisos estrictamente necesarios en tiempo de uso.',
        'Utilizar APIs públicas y revisar las guías de seguridad de la plataforma.',
        'Validar y filtrar intents/deep links entrantes.',
        'Revisar y auditar el uso de permisos y APIs en pruebas de seguridad.'
      ]
    },
    {
      id: 'M02',
      name: 'Almacenamiento inseguro de datos',
      description: 'Información sensible se guarda sin cifrar o en lugares accesibles por otras apps.',
      risk: 'Alto',
      impact: 'Robo de credenciales, mensajes o datos personales',
      likelihood: 'Alta',
      cwes: ["CWE-312", "CWE-922"],
      exposure: [
        'Credenciales y tokens pueden ser robados de almacenamiento local.',
        'Datos personales quedan accesibles a otras apps o usuarios del dispositivo.',
        'Información sin cifrar puede ser copiada o filtrada fácilmente.',
        'Se pierde control sobre la confidencialidad de la información guardada.'
      ]
      ,
      examples: [
        'Guardar tokens de sesión en SharedPreferences sin cifrar.',
        'Archivos sensibles en almacenamiento externo accesible por otras apps.',
        'Credenciales hardcoded dentro del APK.'
      ],
      solution: [
        'Cifrar datos sensibles en reposo usando KeyStore/Keychain.',
        'Evitar almacenamiento en texto plano; usar almacenamiento interno protegido.',
        'No hardcodear credenciales ni keys en el código o recursos.',
        'Eliminar datos sensibles cuando no sean necesarios y usar Wipes seguros.'
      ]
    },
    {
      id: 'M03',
      name: 'Comunicación insegura',
      description: 'Los datos viajan sin cifrado o con certificados débiles entre la app y el servidor.',
      risk: 'Alto',
      impact: 'Intercepción y manipulación de información en tránsito',
      likelihood: 'Alta',
      cwes: ["CWE-319", "CWE-295"],
      exposure: [
        'Los datos pueden ser interceptados en la red sin cifrado.',
        'Mensajes y peticiones pueden ser modificados en tránsito.',
        'Información sensible puede ser leída por atacantes externos.',
        'Las sesiones y autenticaciones pueden ser secuestradas.'
      ]
      ,
      examples: [
        'Conexiones HTTP sin TLS para APIs que manejan datos sensibles.',
        'No validar certificados TLS o aceptar certificados autofirmados en producción.',
        'No usar certificate pinning cuando procede en entornos móviles.'
      ],
      solution: [
        'Forzar TLS/HTTPS en todas las comunicaciones y usar TLS moderno.',
        'Validar correctamente certificados y evitar aceptación ciega de certificados.',
        'Considerar certificate pinning según el riesgo y gestionar su rotación.',
        'Usar bibliotecas seguras para manejar conexiones y controlar ciphers débiles.'
      ]
    },
    {
      id: 'M04',
      name: 'Autenticación insegura',
      description: 'La app no verifica bien al usuario o guarda mal las credenciales.',
      risk: 'Alto',
      impact: 'Secuestro de cuentas y suplantación de identidad',
      likelihood: 'Alta',
      cwes: ["CWE-287", "CWE-384"],
      exposure: [
        'Cuentas pueden ser secuestradas o accesos no autorizados realizados.',
        'El atacante puede suplantar identidad de usuarios legítimos.',
        'Sesiones pueden permanecer abiertas sin verificación correcta.',
        'Se rompe la confianza en la aplicación y la seguridad del usuario.'
      ]
      ,
      examples: [
        'Tokens de sesión sin expiración almacenados indefinidamente en el dispositivo.',
        'No aplicar MFA para operaciones sensibles.',
        'Enviar tokens en URLs que quedan en historiales o logs.'
      ],
      solution: [
        'Implementar MFA para accesos y acciones críticas.',
        'Gestionar ciclos de vida de tokens: expiración y refresh seguros.',
        'No exponer tokens en URLs y usar almacenamiento seguro para ellos.',
        'Aplicar comprobaciones de reautenticación para operaciones sensibles.'
      ]
    },
    {
      id: 'M05',
      name: 'Criptografía insuficiente',
      description: 'Algoritmos débiles o manejo pobre de claves deja los datos protegidos solo de nombre.',
      risk: 'Alto',
      impact: 'Datos sensibles expuestos incluso si parecen cifrados',
      likelihood: 'Media',
      cwes: ["CWE-326", "CWE-327"],
      exposure: [
        'Datos cifrados con métodos débiles pueden descifrarse fácilmente.',
        'Información en reposo o tránsito puede quedar expuesta.',
        'Claves mal gestionadas comprometen toda la protección.',
        'La app puede dar falsa sensación de seguridad mientras los datos quedan vulnerables.'
      ]
      ,
      examples: [
        'Uso de MD5 o SHA1 para proteger contraseñas o datos sensibles.',
        'Claves y secretos incluidos en el código o en recursos no protegidos.',
        'Implementaciones cripto caseras en lugar de librerías auditadas.'
      ],
      solution: [
        'Usar algoritmos y modos modernos (ej. AES-GCM) y librerías probadas.',
        'Almacenar claves en KeyStore/Keychain, no en código ni recursos.',
        'Evitar mecanismos cripto caseros; apoyarse en APIs de la plataforma.',
        'Revisar periódicamente prácticas cripto y rotar claves cuando corresponda.'
      ]
    },
    {
      id: 'M06',
      name: 'Integridad del código y manipulación',
      description: 'El código de la app puede ser alterado o el binario modificado (tampering), permitiendo modificar comportamientos o eliminar protecciones.',
      risk: 'Alto',
      impact: 'La app puede comportarse de forma maliciosa o desactivar controles de seguridad',
      likelihood: 'Media',
      cwes: ["CWE-119", "CWE-284"],
      exposure: [
        'El atacante puede inyectar código o modificar el binario para evadir controles.',
        'Protecciones como detección de root/jailbreak pueden ser desactivadas.',
        'Se pueden introducir backdoors o funcionalidades ocultas en la app.'
      ],
      examples: [
        'Un atacante parchea el APK/IPA para eliminar verificaciones de licencia.',
        'Modificación del binario para exfiltrar datos a un servidor malicioso.'
      ],
      solution: [
        'Aplicar firmas y verificaciones de integridad en tiempo de ejecución.',
        'Implementar detección de manipulación y medidas anti-tamper.',
        'Distribuir builds firmados y verificar firmas antes de ejecutar actualizaciones.'
      ]
    },
    {
      id: 'M07',
      name: 'Ingeniería inversa y exposición del código',
      description: 'La app puede ser descompilada o analizada, exponiendo secretos, lógica interna o vectores de ataque.',
      risk: 'Alto',
      impact: 'Se divulgan secretos y se facilita la creación de exploits',
      likelihood: 'Alta',
      cwes: ["CWE-200", "CWE-532"],
      exposure: [
        'Recuperación de claves o credenciales embebidas en el código.',
        'Descubrimiento de lógica de negocio sensible que facilita ataques.'
      ],
      examples: [
        'Extraer claves API embebidas dentro del APK tras descompilarlo.',
        'Analizar la lógica de cifrado implementada de forma insegura.'
      ],
      solution: [
        'Ofuscar el código y minimizar la exposición de strings sensibles.',
        'No incluir secretos en el binario; usar almacenes seguros. ',
        'Aplicar controles de empaquetado y protección contra ingeniería inversa.'
      ]
    },
    {
      id: 'M08',
      name: 'Manipulación del entorno de ejecución',
      description: 'El entorno del dispositivo (root/jailbreak, emuladores o hooks) permite modificar la ejecución y el comportamiento de la app.',
      risk: 'Medio',
      impact: 'Permite escalación de privilegios y eludir controles de seguridad',
      likelihood: 'Media',
      cwes: ["CWE-732", "CWE-284"],
      exposure: [
        'Funciones de la app pueden bypassearse en dispositivos manipulados.',
        'Se permite la ejecución de código no autorizado dentro de la app.'
      ],
      examples: [
        'Un atacante con root modifica archivos de configuración para desactivar validaciones.',
        'Uso de frameworks de hooking para interceptar y alterar llamadas internas.'
      ],
      solution: [
        'Detectar entornos root/jailbreak y tomar medidas adecuadas.',
        'Aplicar reforzamiento de integridad y cifrado de datos críticos.',
        'Realizar pruebas en entornos simulados y reales para detectar bypasses.'
      ]
    },
    {
      id: 'M09',
      name: 'Fugas por interacciones con otras apps',
      description: 'Comunicación insegura con otras apps o componentes del sistema puede filtrar información o permitir escalada.',
      risk: 'Medio',
      impact: 'Exposición de datos entre aplicaciones y abuso de componentes',
      likelihood: 'Media',
      cwes: ["CWE-200", "CWE-276"],
      exposure: [
        'Contenido sensible pasa a otras apps a través de Intents, Content Providers o archivos temporales.',
        'Otra app puede invocar actividades o servicios de forma no autorizada.'
      ],
      examples: [
        'Un Content Provider sin controles permite leer datos de la app desde otra app.',
        'Deep links expuestos permiten que otras apps lancen flujos no autorizados.'
      ],
      solution: [
        'Restringir y validar accesos a Content Providers y componentes expuestos.',
        'Usar permisos a nivel de manifest y chequear llamantes antes de actuar.',
        'No compartir archivos sensibles sin control de acceso y usar URIs temporalmente firmadas.'
      ]
    },
    {
      id: 'M10',
      name: 'Funcionalidad redundante o de desarrollo',
      description: 'Funciones de debug, backdoors o endpoints de prueba quedan presentes en producción y pueden ser explotadas.',
      risk: 'Medio',
      impact: 'Acceso no intencionado a funciones internas y datos',
      likelihood: 'Media',
      cwes: ["CWE-200", "CWE-306"],
      exposure: [
        'Endpoints de test o funcionalidades ocultas pueden usarse para obtener control o datos.',
        'Backdoors intencionales o no eliminados facilitan compromisos.'
      ],
      examples: [
        'Un endpoint de administración de pruebas permanece activo en producción.',
        'Herramientas de debugging habilitadas que exponen funciones internas.'
      ],
      solution: [
        'Eliminar código y endpoints de desarrollo antes de desplegar a producción.',
        'Revisar builds y pipelines para separar entornos de test y producción.',
        'Auditar releases para detectar funcionalidades no documentadas.'
      ]
    }
  ],
  cwes: {
    "CWE-20": "Improper Input Validation",
    "CWE-269": "Improper Privilege Management",
    "CWE-284": "Improper Access Control",
    "CWE-287": "Improper Authentication",
    "CWE-295": "Improper Certificate Validation",
    "CWE-312": "Cleartext Storage of Sensitive Information",
    "CWE-319": "Cleartext Transmission of Sensitive Information",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-922": "Insecure Storage of Sensitive Information",
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-200": "Information Exposure",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-384": "Session Fixation"
  }
};

// Datos OWASP Top 10 LLM (solo 1-5)
const owaspLLM = {
  categories: [
    {
      id: 'LLM01',
      name: 'Inyección de instrucciones',
      description: 'Si alguien logra engañar al modelo con prompts o datos maliciosos, puede hacer que responda mal o ejecute instrucciones peligrosas.',
      risk: 'Alto',
      impact: 'Respuestas peligrosas o filtración de datos no deseada',
      likelihood: 'Alta',
      cwes: ["CWE-20", "CWE-74"],
      exposure: [
        'El modelo puede ejecutar o priorizar instrucciones maliciosas.',
        'Respuestas pueden volverse peligrosas, incorrectas o dañinas.',
        'Se compromete la confiabilidad del sistema al aceptar instrucciones no válidas.',
        'El flujo de conversación puede ser desviado hacia comportamientos no deseados.'
      ]
      ,
      examples: [
        'Un prompt adversario que induce al modelo a revelar datos internos o claves.',
        'Instrucciones que hacen al modelo enviar comandos o recomendaciones peligrosas.',
        'Transformar una entrada aparentemente inocua en una orden maliciosa para el agente.'
      ],
      solution: [
        'Sanitizar y normalizar entradas antes de construir prompts para el modelo.',
        'Aplicar filtros y reglas que bloqueen instrucciones peligrosas o privilegiadas.',
        'Limitar las acciones que el modelo puede sugerir o ejecutar en sistemas conectados.',
        'Entrenar y evaluar con ejemplos adversariales y políticas de seguridad.'
      ]
    },
    {
      id: 'LLM02',
      name: 'Fuga de datos',
      description: 'El modelo puede enviar información sensible en una respuesta, aunque no debería explicitarla.',
      risk: 'Alto',
      impact: 'Divulgación de credenciales, secretos o datos personales',
      likelihood: 'Media',
      cwes: ["CWE-200", "CWE-212"],
      exposure: [
        'Se pueden revelar credenciales, secretos o datos sensibles.',
        'Información privada de usuarios puede salir en la respuesta.',
        'La confianza en el sistema se pierde por exposiciones no intencionadas.',
        'Datos internos pueden filtrarse a través de ejemplos o contextos del prompt.'
      ]
      ,
      examples: [
        'El modelo devuelve un token o clave que apareció en el contexto del prompt.',
        'Responde con fragments de conversaciones anteriores que contienen PII.',
        'Incluye información de otros usuarios por error en respuestas generadas.'
      ],
      solution: [
        'Filtrar y enmascarar PII y secretos antes de enviar contexto al modelo.',
        'Aplicar controles de salida que detecten y bloqueen divulgaciones sensibles.',
        'Limitar la retención de contexto y auditar qué datos se utilizan para prompts.',
        'Controlar acceso a logs y resultados que puedan contener datos sensibles.'
      ]
    },
    {
      id: 'LLM03',
      name: 'Alucinaciones',
      description: 'El modelo inventa hechos o datos que no existen y los presenta como si fueran verdad.',
      risk: 'Medio',
      impact: 'Información incorrecta que puede tomar malas decisiones',
      likelihood: 'Alta',
      cwes: ["CWE-20", "CWE-749"],
      exposure: [
        'Se genera información falsa presentada como cierta.',
        'Decisiones basadas en respuestas incorrectas pueden provocar errores graves.',
        'Usuarios pueden confiar en datos inventados sin verificar su veracidad.',
        'El producto puede perder credibilidad y causar impactos reputacionales.'
      ]
      ,
      examples: [
        'El modelo inventa una cifra o cita que no existe para apoyar una respuesta.',
        'Genera detalles técnicos erróneos que llevan a decisiones inseguras.',
        'Crea referencias o links ficticios que parecen plausibles.'
      ],
      solution: [
        'Implementar verificación externa (fact-checking) para respuestas críticas.',
        'Usar RAG (retrieval-augmented generation) con fuentes confiables cuando proceda.',
        'Habilitar mecanismos que indiquen incertidumbre o confianza en la respuesta.',
        'Ajustar parámetros del modelo y entrenar para reducir alucinaciones.'
      ]
    },
    {
      id: 'LLM04',
      name: 'Exposición de información privada',
      description: 'Responde con datos de usuarios, historial o material sensible que no debía mostrar.',
      risk: 'Alto',
      impact: 'Violación de privacidad y pérdida de confianza',
      likelihood: 'Media',
      cwes: ["CWE-200", "CWE-359"],
      exposure: [
        'El modelo puede devolver datos que deberían mantenerse confidenciales.',
        'Privacidad de usuarios y clientes queda en riesgo.',
        'Información sensible del historial o contexto puede ser divulgada.',
        'Se puede incumplir la normativa de protección de datos.'
      ]
      ,
      examples: [
        'El modelo incluye el email o dirección de un usuario en una respuesta.',
        'Revela fragmentos del historial de otro cliente en una conversación.',
        'Devuelve claves API o credenciales que estaban en el contexto.'
      ],
      solution: [
        'Enmascarar o eliminar PII del contexto antes de pasarlo al modelo.',
        'Implementar controles de acceso y políticas de privacidad sobre el contexto.',
        'Auditar y revisar logs para detectar exposiciones accidentales.',
        'Aplicar límites y reglas en las respuestas que identifiquen y bloqueen PII.'
      ]
    },
    {
      id: 'LLM05',
      name: 'Manipulación de contexto',
      description: 'El prompt o el historial se alteran para conducir al modelo a un resultado inseguro.',
      risk: 'Alto',
      impact: 'Comportamiento no autorizado o divulgación de respuestas peligrosas',
      likelihood: 'Media',
      cwes: ["CWE-74", "CWE-94"],
      exposure: [
        'El modelo puede ser guiado hacia respuestas inseguras o indebidas.',
        'Se puede provocar la divulgación de información no autorizada.',
        'El comportamiento del sistema puede cambiar sin aviso.',
        'Se facilita el abuso del modelo mediante prompts maliciosos.'
      ],
      examples: [
        'Incluir instrucciones contradictorias en el historial para forzar acciones inseguras.',
        'Insertar fragmentos que engañen al modelo para que revele secretos presentes en contexto.'
      ],
      solution: [
        'Normalizar y validar el historial antes de construir el prompt final.',
        'Limitar la influencia de mensajes de baja confianza en el contexto.',
        'Aplicar tokens de seguridad y reglas que ignoren entradas sospechosas.'
      ]
    },
    {
      id: 'LLM06',
      name: 'Envenenamiento de datos (Data Poisoning)',
      description: 'Datos de entrenamiento o fine-tuning manipulados introducen sesgos, backdoors o comportamientos maliciosos en el modelo.',
      risk: 'Alto',
      impact: 'El modelo actúa de forma controlada por adversarios o genera resultados sesgados',
      likelihood: 'Media',
      cwes: ["CWE-20", "CWE-1228"],
      exposure: [
        'Inyección de ejemplos maliciosos en datasets públicos o pipelines de reentrenamiento.',
        'Backdoors que activan comportamientos solo con ciertas señales en el prompt.'
      ],
      examples: [
        'Entrenar con datos manipulados que inducen al modelo a filtrar información tras un gatillo.',
        'Sesgar resultados para favorecer contenidos específicos en función de entradas adversarias.'
      ],
      solution: [
        'Validar y sanear datasets de entrenamiento y fuentes de datos.',
        'Monitorizar métricas de desviación y realizar pruebas adversariales durante el entrenamiento.',
        'Mantener cadenas de custodia y firmas para datos de entrenamiento.'
      ]
    },
    {
      id: 'LLM07',
      name: 'Toxicidad y contenido dañino',
      description: 'El modelo puede generar discurso de odio, instrucciones para daño o contenido inapropiado.',
      risk: 'Alto',
      impact: 'Daño a usuarios, responsabilidad legal y reputacional',
      likelihood: 'Alta',
      cwes: ["CWE-602", "CWE-629"],
      exposure: [
        'Generación de consejos peligrosos o instrucciones de daño.',
        'Difusión de mensajes ofensivos o discriminatorios.'
      ],
      examples: [
        'Responder con instrucciones para fabricar dispositivos peligrosos.',
        'Generar contenido que incite al odio contra un grupo protegido.'
      ],
      solution: [
        'Aplicar filtros de seguridad y modelos de clasificación de contenido tóxico.',
        'Limitar y revisar respuestas en dominios sensibles mediante revisión humana.',
        'Entrenar con datos que reduzcan sesgos y toxicidad.'
      ]
    },
    {
      id: 'LLM08',
      name: 'Abuso de generación de código',
      description: 'El modelo puede generar código vulnerable, malware o comandos que, si se ejecutan, dañen sistemas.',
      risk: 'Medio',
      impact: 'Despliegue de código inseguro o ejecución de comandos dañinos',
      likelihood: 'Alta',
      cwes: ["CWE-94", "CWE-918"],
      exposure: [
        'Generación de scripts con comandos peligrosos sin advertencias.',
        'Sugerencias de código que facilitan inyecciones o vulnerabilidades.'
      ],
      examples: [
        'El modelo sugiere un script que borra logs o exfiltra datos.',
        'Genera snippets con validación insuficiente que introducen XSS/SQLi.'
      ],
      solution: [
        'Filtrar y revisar recomendaciones de código antes de su uso en producción.',
        'Agregar advertencias y verificación automática de seguridad en código generado.',
        'Limitar la ejecución automática de código generado por modelos.'
      ]
    },
    {
      id: 'LLM09',
      name: 'Gestión y acceso al modelo',
      description: 'Controles débiles sobre quién puede acceder, actualizar o consultar el modelo exponen capacidades y datos confidenciales.',
      risk: 'Alto',
      impact: 'Acceso no autorizado, exfiltración o manipulación del modelo',
      likelihood: 'Media',
      cwes: ["CWE-284", "CWE-306"],
      exposure: [
        'Usuarios no autorizados consultan o descargan el modelo o sus artefactos.',
        'Acceso a endpoints de administración sin autenticación robusta.'
      ],
      examples: [
        'Credenciales débiles en APIs que permiten invocar el modelo de forma masiva.',
        'Permisos excesivos para personal que puede alterar parámetros del modelo.'
      ],
      solution: [
        'Aplicar control de acceso granular y autenticación fuerte para APIs del modelo.',
        'Auditar y limitar quién puede actualizar pesos o pipelines de entrenamiento.',
        'Registrar y monitorizar llamadas al modelo y cambios de configuración.'
      ]
    },
    {
      id: 'LLM10',
      name: 'Cadenas de suministro y dependencias',
      description: 'Modelos, librerías o weights de terceros comprometidos introducen riesgos en la solución final.',
      risk: 'Medio',
      impact: 'Inyección de fallos o backdoors mediante dependencias comprometidas',
      likelihood: 'Media',
      cwes: ["CWE-1104", "CWE-494"],
      exposure: [
        'Weights o librerías de terceros con código malicioso integradas en el servicio.',
        'Puntos de actualización que pueden reemplazar modelos sin verificación.'
      ],
      examples: [
        'Descargar un modelo de fuentes no verificadas que contiene comportamientos maliciosos.',
        'Dependencias de librerías que ejecutan callbacks remotos no esperados.'
      ],
      solution: [
        'Verificar firmas y la integridad de modelos y dependencias antes de usarlos.',
        'Mantener inventario de dependencias y monitorizar alertas de seguridad.',
        'Usar fuentes confiables y rutinas de revisión para incorporar modelos externos.'
      ]
    }
  ],
  cwes: {
    "CWE-20": "Improper Input Validation",
    "CWE-74": "Improper Neutralization of Special Elements in Output Used by a Downstream Component",
    "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
    "CWE-200": "Information Exposure",
    "CWE-212": "Improper Handling of Extra Numeric Values",
    "CWE-359": "Exposure of Private Personal Information Through Data Query Logic",
    "CWE-749": "Incomplete Requirements",
    "CWE-1228": "API / Function Errors"
  }
};

// Estado global
let currentSection = 'home'; // home | top10 | mobile | llm
let selectedCategory = null;

// Elementos
const navBtns = document.querySelectorAll('.nav-btn');
const leftSidebar = document.getElementById('leftSidebar');
const rightSidebar = document.getElementById('rightSidebar');
const mainContent = document.getElementById('mainContent');
const edgeLeftToggle = document.getElementById('edgeLeftToggle');
const edgeRightToggle = document.getElementById('edgeRightToggle');
const homeLink = document.getElementById('homeLink');
const homeTitleLink = document.getElementById('homeTitleLink');
const privacyLink = document.getElementById('privacyLink');
const categoryList = document.getElementById('categoryList');
const cweList = document.getElementById('cweList');
const sidebarTitle = document.getElementById('sidebarTitle');

// Navegación principal
navBtns.forEach(btn => {
  btn.addEventListener('click', () => {
    navBtns.forEach(b => b.classList.remove('active'));
    btn.classList.add('active');
    const target = btn.dataset.target;
    if (target === 'top10' || target === 'mobile' || target === 'llm') {
      renderSection(target);
    } else {
      renderSection('home');
    }
  });
});

// Logo/Home
homeLink.addEventListener('click', (e) => {
  e.preventDefault();
  renderSection('home');
});
homeTitleLink.addEventListener('click', (e) => {
  e.preventDefault();
  renderSection('home');
});

privacyLink.addEventListener('click', (e) => {
  e.preventDefault();
  renderSection('privacy');
});

// Renderizado de secciones
function renderSection(section) {
  currentSection = section;
  selectedCategory = null;
  // Home
  if (section === 'home') {
    leftSidebar.style.display = 'none';
    rightSidebar.style.display = 'none';
    mainContent.innerHTML = `
      <div class="placeholder" style="flex-direction:column;gap:1.5rem;">
        <img src="resources/owasp-logo-maincontent.png" alt="OWASP logo" class="placeholder-image">
        <h2>¿Qué es OWASP?</h2>
        <p style="max-width:600px;text-align:center;">OWASP (Open Web Application Security Project) es una comunidad global dedicada a mejorar la seguridad del software. El OWASP Top 10 es un ranking de los riesgos de seguridad más críticos en aplicaciones, orientado a concienciar y educar a desarrolladores y empresas.</p>
      </div>
    `;
    navBtns.forEach(b => b.classList.remove('active'));
    navBtns[0].classList.add('active');
    cweList.innerHTML = '';
    return;
  }

  if (section === 'privacy') {
    leftSidebar.style.display = 'none';
    rightSidebar.style.display = 'none';
    mainContent.innerHTML = `
      <div style="max-width:720px;margin:0 auto;padding:1rem;">
        <h2>Política de privacidad</h2>
        <p>Este proyecto es educativo y no guarda cookies ni datos personales de quienes lo usan. La información se procesa únicamente en el navegador local, sin enviar ni almacenar nada en servidores externos.</p>
        <h3 style="margin-top:1.2rem;">Qué no se guarda</h3>
        <ul>
          <li>No se utilizan cookies.</li>
          <li>No se recopilan nombres, correos, ni direcciones IP.</li>
          <li>No se almacena información de uso ni historial de navegación.</li>
        </ul>
        <h3 style="margin-top:1.2rem;">Cómo funciona</h3>
        <p>El contenido que ves se genera con datos ya incluidos en la aplicación. Todo ocurre en tu propio equipo, por lo que no existe registro de tu actividad.</p>
        <p>Si en el futuro se integra alguna funcionalidad extra, se avisará claramente y se respetará siempre tu privacidad.</p>
      </div>
    `;
    navBtns.forEach(b => b.classList.remove('active'));
    cweList.innerHTML = '';
    return;
  }

  // Mostrar sidebars solo en secciones
  leftSidebar.style.display = '';
  rightSidebar.style.display = '';


  if (section === 'llm') {
    sidebarTitle.textContent = 'Categorías';
    renderCategoryList();
    mainContent.innerHTML = `
      <div class="placeholder placeholder--llm">
        <img src="resources/otop10llm-bg.png" alt="OWASP logo" class="placeholder-image">
      </div>
    `;
    cweList.innerHTML = '';
  } else if (section === 'top10') {
    sidebarTitle.textContent = 'Categorías';
    renderCategoryListTop10();
    mainContent.innerHTML = `
      <div class="placeholder placeholder--top10">
        <img src="resources/otop10w-bg.png" alt="OWASP logo" class="placeholder-image">
      </div>
    `;
    cweList.innerHTML = '';
  } else if (section === 'mobile') {
    sidebarTitle.textContent = 'Categorías';
    renderCategoryListMobile();
    mainContent.innerHTML = `
      <div class="placeholder placeholder--mobile">
        <img src="resources/otop10m-bg.png" alt="OWASP logo" class="placeholder-image">
      </div>
    `;
    cweList.innerHTML = '';
  } else {
    sidebarTitle.textContent = 'Categorías';
    categoryList.innerHTML = '<li style="color:#aaa;">(Próximamente)</li>';
    mainContent.innerHTML = `<div style="text-align:center;color:#888;">Sección en construcción.</div>`;
    cweList.innerHTML = '';
  }
}

function renderCategoryList() {
  categoryList.innerHTML = '';
  owaspLLM.categories.forEach(cat => {
    const li = document.createElement('li');
    li.textContent = `${cat.id} - ${cat.name}`;
    li.addEventListener('click', () => {
      selectCategory(cat.id);
    });
    if (selectedCategory && selectedCategory.id === cat.id) {
      li.classList.add('active');
    }
    categoryList.appendChild(li);
  });
}

function renderCategoryListTop10() {
  categoryList.innerHTML = '';
  owaspTop10.categories.forEach(cat => {
    const li = document.createElement('li');
    li.textContent = `${cat.id} - ${cat.name}`;
    li.style.cursor = 'pointer';
    li.addEventListener('click', () => {
      selectCategoryTop10(cat.id);
    });
    if (selectedCategory && selectedCategory.id === cat.id) {
      li.classList.add('active');
    }
    categoryList.appendChild(li);
  });
}

function renderCategoryListMobile() {
  categoryList.innerHTML = '';
  owaspMobile.categories.forEach(cat => {
    const li = document.createElement('li');
    li.textContent = `${cat.id} - ${cat.name}`;
    li.addEventListener('click', () => {
      selectCategoryMobile(cat.id);
    });
    if (selectedCategory && selectedCategory.id === cat.id) {
      li.classList.add('active');
    }
    categoryList.appendChild(li);
  });
}

function selectCategory(catId) {
  selectedCategory = owaspLLM.categories.find(c => c.id === catId);
  renderCategoryList();
  renderCategoryDetail();
  renderCWEList();
}

function selectCategoryTop10(catId) {
  selectedCategory = owaspTop10.categories.find(c => c.id === catId);
  renderCategoryListTop10();
  renderCategoryDetailTop10();
  renderCWEListTop10();
}

function selectCategoryMobile(catId) {
  selectedCategory = owaspMobile.categories.find(c => c.id === catId);
  renderCategoryListMobile();
  renderCategoryDetailMobile();
  renderCWEMobile();
}

function renderExposureAndSolution() {
  if (!selectedCategory || !selectedCategory.exposure || !selectedCategory.exposure.length) return '';
  const solutionItems = selectedCategory.solution || [
    'Revisa y corrige los controles de seguridad según la categoría.',
    'Aplica buenas prácticas de validación, cifrado y autorización.',
    'Asegura configuraciones y permisos mínimos necesarios.',
    'Audita y prueba regularmente para detectar y corregir fallas.'
  ];
  return `
    <div class="detail-blocks">
      <div class="detail-block">
        <h3>¿A qué nos expone?</h3>
        <ul>
          ${selectedCategory.exposure.map(item => `<li>${item}</li>`).join('')}
        </ul>
      </div>
      <div class="detail-block detail-block--green">
        <h3>¿Cómo solucionarlo?</h3>
        <ul>
          ${solutionItems.map(item => `<li>${item}</li>`).join('')}
        </ul>
      </div>
    </div>
  `;
}

function formatDescription(text) {
  return text ? text.replace(/\n/g, '<br>') : '';
}

function renderExamples() {
  if (!selectedCategory || !selectedCategory.examples || !selectedCategory.examples.length) return '';
  return `
    <div class="detail-block detail-block--examples">
      <h3>Ejemplos</h3>
      <ul>
        ${selectedCategory.examples.map(item => `<li>${item}</li>`).join('')}
      </ul>
    </div>
  `;
}

function renderCategoryDetail() {
  if (!selectedCategory) return;
  mainContent.innerHTML = `
    <h2>${selectedCategory.id} - ${selectedCategory.name}</h2>
    <p>${formatDescription(selectedCategory.description)}</p>
    <div style="margin:1rem 0;max-width:520px;">
      <div style="display:grid;grid-template-columns:1fr 2fr 1fr;gap:0.5rem;text-align:center;background:#eef4fb;border:2px#c8d9e9;border-radius:2px;overflow:hidden;">
        <div style="padding:0.7rem 0.6rem;font-weight:700;background:#dbe9f9;color:#0f3f73;">Riesgo</div>
        <div style="padding:0.7rem 0.6rem;font-weight:700;background:#dbe9f9;color:#0f3f73;">Impacto</div>
        <div style="padding:0.7rem 0.6rem;font-weight:700;background:#dbe9f9;color:#0f3f73;">Probabilidad</div>
        <div style="padding:0.7rem 0.6rem;background:#ffffff;">${selectedCategory.risk}</div>
        <div style="padding:0.7rem 0.6rem;background:#ffffff;">${selectedCategory.impact}</div>
        <div style="padding:0.7rem 0.6rem;background:#ffffff;">${selectedCategory.likelihood}</div>
      </div>
    </div>
    ${renderExamples()}
    ${renderExposureAndSolution()}
  `;
}

function renderCategoryDetailTop10() {
  if (!selectedCategory) return;
  mainContent.innerHTML = `
    <h2>${selectedCategory.id} - ${selectedCategory.name}</h2>
    <p>${formatDescription(selectedCategory.description)}</p>
    
    <div style="margin:1rem 0;max-width:520px;">
      <div style="display:grid;grid-template-columns:1fr 2fr 1fr;gap:0.5rem;text-align:center;background:#eef4fb;border:2px#c8d9e9;border-radius:2px;overflow:hidden;">
        <div style="padding:0.7rem 0.6rem;font-weight:700;background:#dbe9f9;color:#0f3f73;">Riesgo</div>
        <div style="padding:0.7rem 0.6rem;font-weight:700;background:#dbe9f9;color:#0f3f73;">Impacto</div>
        <div style="padding:0.7rem 0.6rem;font-weight:700;background:#dbe9f9;color:#0f3f73;">Probabilidad</div>
        <div style="padding:0.7rem 0.6rem;background:#ffffff;">${selectedCategory.risk}</div>
        <div style="padding:0.7rem 0.6rem;background:#ffffff;">${selectedCategory.impact}</div>
        <div style="padding:0.7rem 0.6rem;background:#ffffff;">${selectedCategory.likelihood}</div>
      </div>
    </div>
    ${renderExamples()}
    ${renderExposureAndSolution()}
  `;
}

function renderCategoryDetailMobile() {
  if (!selectedCategory) return;
  mainContent.innerHTML = `
    <h2>${selectedCategory.id} - ${selectedCategory.name}</h2>
    <p>${formatDescription(selectedCategory.description)}</p>
    <div style="margin:1rem 0;max-width:520px;">
      <div style="display:grid;grid-template-columns:1fr 2fr 1fr;gap:0.5rem;text-align:center;background:#eef4fb;border:2px#c8d9e9;border-radius:2px;overflow:hidden;">
        <div style="padding:0.7rem 0.6rem;font-weight:700;background:#dbe9f9;color:#0f3f73;">Riesgo</div>
        <div style="padding:0.7rem 0.6rem;font-weight:700;background:#dbe9f9;color:#0f3f73;">Impacto</div>
        <div style="padding:0.7rem 0.6rem;font-weight:700;background:#dbe9f9;color:#0f3f73;">Probabilidad</div>
        <div style="padding:0.7rem 0.6rem;background:#ffffff;">${selectedCategory.risk}</div>
        <div style="padding:0.7rem 0.6rem;background:#ffffff;">${selectedCategory.impact}</div>
        <div style="padding:0.7rem 0.6rem;background:#ffffff;">${selectedCategory.likelihood}</div>
      </div>
    </div>
    ${renderExamples()}
    ${renderExposureAndSolution()}
  `;
}

function renderCWEList() {
  cweList.innerHTML = '';
  if (!selectedCategory) return;
  selectedCategory.cwes.forEach(cwe => {
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = `https://cwe.mitre.org/data/definitions/${cwe.replace(/CWE-/,'')}.html`;
    a.textContent = `${cwe} - ${owaspLLM.cwes[cwe] || ''}`;
    a.target = '_blank';
    a.rel = 'noopener';
    li.appendChild(a);
    cweList.appendChild(li);
  });
}

function renderCWEListTop10() {
  cweList.innerHTML = '';
  if (!selectedCategory) return;
  selectedCategory.cwes.forEach(cwe => {
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = `https://cwe.mitre.org/data/definitions/${cwe.replace(/CWE-/,'')}.html`;
    a.textContent = `${cwe} - ${owaspTop10.cwes[cwe] || ''}`;
    a.target = '_blank';
    a.rel = 'noopener';
    li.appendChild(a);
    cweList.appendChild(li);
  });
  // Añadir CWEs específicos de tipos de inyección para A03 sin encabezados
  if (selectedCategory.id === 'A03' && selectedCategory.injectionTypeCwes) {
    selectedCategory.injectionTypeCwes.forEach(entry => {
      const li = document.createElement('li');
      const a = document.createElement('a');
      a.href = `https://cwe.mitre.org/data/definitions/${entry.cwe.replace(/CWE-/,'')}.html`;
      a.textContent = `${entry.cwe} - ${entry.type}`;
      a.target = '_blank';
      a.rel = 'noopener';
      li.appendChild(a);
      cweList.appendChild(li);
    });
  }
}

function renderCWEMobile() {
  cweList.innerHTML = '';
  if (!selectedCategory) return;
  selectedCategory.cwes.forEach(cwe => {
    const li = document.createElement('li');
    const a = document.createElement('a');
    a.href = `https://cwe.mitre.org/data/definitions/${cwe.replace(/CWE-/,'')}.html`;
    a.textContent = `${cwe} - ${owaspMobile.cwes[cwe] || ''}`;
    a.target = '_blank';
    a.rel = 'noopener';
    li.appendChild(a);
    cweList.appendChild(li);
  });
}

// Inicialización
renderSection('home');
