# Publicar la extensión de CipherVault

## 1. Subirla a la Chrome Web Store (sirve para Chrome, Brave y Opera)

1. Crea tu cuenta de desarrollador en <https://chrome.google.com/webstore/devconsole>. Google cobra un pago único de 5 USD.
2. Ejecuta `.\build.ps1`: genera `dist\CipherVault-extension.zip`.
3. En la consola, pulsa **Nuevo elemento** y sube ese .zip.
4. Llena la ficha con los textos de abajo y sube estas imágenes:
   - Ícono: `extension/icons/icon128.png`.
   - Al menos una captura de 1280×800.
5. En **Prácticas de privacidad** usa las justificaciones de los permisos (abajo) y pon como política de privacidad la URL de `extension/PRIVACIDAD.md` en GitHub.
6. Envíala a revisión. Suele tardar entre 1 y 7 días.
7. Cuando la publiquen, copia el **ID del elemento** (32 letras). Ponlo en tu `.env`:
   ```
   CIPHERVAULT_EXTENSION_IDS=ID_DE_LA_CHROME_WEB_STORE
   ```
   Si también la publicas en Edge, agrega ese ID separado por coma.
8. Vuelve a compilar con `.\build.ps1`. La app registra el puente con ese ID la próxima vez que se abra.

## 2. Microsoft Edge (opcional)

Para Edge, súbela también en <https://partner.microsoft.com/dashboard/microsoftedge>. Es gratis. Edge le da otro ID: agrégalo a `CIPHERVAULT_EXTENSION_IDS`.

## 3. Probarla antes de publicarla

1. Abre `chrome://extensions` y activa el **Modo de desarrollador**.
2. Pulsa **Cargar extensión sin empaquetar** y elige la carpeta `extension`.
3. Copia el ID que muestra Chrome y ponlo en `CIPHERVAULT_EXTENSION_IDS` del `.env`.
4. Abre la app con `.\run.ps1`, inicia sesión, ve a una página de inicio de sesión y pulsa el ícono de CipherVault.

## Textos de la ficha

**Nombre:** CipherVault

**Resumen (132 caracteres máx.):**
Rellena tus contraseñas guardadas en CipherVault, el gestor de contraseñas cifrado para Windows. Sin nube: tus datos quedan en tu PC.

**Descripción:**
CipherVault es un gestor de contraseñas para Windows hecho en Colombia. Esta extensión lo conecta con tu navegador:

• Rellena usuario y contraseña en la página de inicio de sesión con un clic, o con Alt + Shift + V.
• Solo propone las cuentas guardadas para ese sitio. Si la dirección no coincide, te avisa, lo que protege contra páginas falsas.
• Muestra el código de verificación en dos pasos (2FA) cuando lo tienes guardado.
• Tus contraseñas no se guardan en la extensión ni salen de tu computador. La extensión se las pide a la app de escritorio en el momento de rellenar.

Requiere la app CipherVault para Windows, abierta y con la sesión iniciada.

**Categoría:** Productividad (o Herramientas para desarrolladores > Seguridad, si está disponible)
**Idioma:** Español

## Justificación de permisos (formulario de la tienda)

| Permiso | Justificación |
|---|---|
| `nativeMessaging` | Comunicarse con la app de escritorio CipherVault, que es la que guarda las contraseñas cifradas. |
| `activeTab` | Leer la dirección de la pestaña abierta solo cuando el usuario pulsa la extensión, para proponer las cuentas de ese sitio. |
| `scripting` | Escribir el usuario y la contraseña en los campos del formulario de inicio de sesión de la pestaña activa, cuando el usuario lo pide. |
| `storage` | Guardar el identificador con el que la extensión se emparejó con la app (no guarda contraseñas). |

**¿Usa código remoto?** No.
**Datos que maneja:** Credenciales de autenticación. Solo se transfieren entre la app local y la página que el usuario está viendo. No se envían a ningún servidor, no se venden y no se usan para otros fines.
