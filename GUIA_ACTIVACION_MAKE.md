# Guía: activación por código de un solo uso (Wompi → Make → app)

Reemplaza la guía anterior (`Make wompi setup.py`) y el diseño con Google Sheets. Ya **no se usa ninguna hoja**: los códigos viven en un *Data Store* privado de Make y la app los canjea llamando a un segundo escenario de Make.

## Reglas que garantiza

- **Un código = hasta 3 equipos.** Cada canje en un PC nuevo agrega su identificador al campo `machine` (separados por coma). Un cuarto PC se rechaza con `used`. El mismo PC puede repetir el canje (reinstalar la app) sin extender la vigencia. Los códigos de FileSync Pro (planes `fs-…`), que comparten este escenario, siguen limitados a 1 equipo.
- **Cada equipo necesita su propio código**, generado al azar. Un pago incluye los códigos que decidas (por defecto 1).
- **Atado al email.** El código solo sirve en una cuenta con el mismo email del pago.
- **Nada sensible circula:** la app envía solo el hash del código + el hash del equipo; Make nunca ve el código ni el email de la cuenta, y no hay hoja pública.
- **La licencia local queda atada al PC:** copiar `passwords.db` a otro equipo invalida el plan.

## Cómo funciona

1. El cliente se registra en CipherVault, pulsa «Comprar» y paga en Wompi con ese mismo email.
2. **Escenario A (pago):** Wompi → Make genera un código aleatorio por equipo, guarda su hash en el Data Store y se lo envía por correo.
3. El cliente pega el código en la app (Activar licencia).
4. **Escenario B (canje):** la app llama al webhook de Make con `{code_hash, machine, nonce}`; Make marca el código como usado por ese equipo y responde el plan **firmado** con un secreto compartido. La app verifica la firma antes de activar nada.

## 1. Data Store

En Make → Data stores → crear `CipherVault_codigos` con estructura:

| Campo | Tipo |
|---|---|
| `plan` | text (`premium`; `basic` solo en códigos antiguos) |
| `reference` | text |
| `meses` | number |
| `created_at` | text (ISO: `2026-10-02T15:30:00`) |
| `machine` | text (vacío al inicio) |
| `used_at` | text (vacío al inicio) |

La **clave del registro** es el `code_hash`. Crea un segundo Data Store `CipherVault_pagos` (clave = `reference`) para no procesar dos veces el mismo pago.

## 2. Escenario A — pago aprobado

`Webhook de Wompi` → filtro `status = APPROVED` (y la verificación de firma del punto 5) → `Data store: Get a record` en `CipherVault_pagos` con clave = referencia, **filtro: no existe** → **router por monto** (`amount_in_cents`) → en cada rama:

| Link de Wompi (clave en `CIPHERVAULT_WOMPI_LINK_MAP`) | Monto | `plan` | `meses` |
|---|---|---|---|
| `premium_mensual` | 9.900 COP (`990000` centavos) | `premium` | 1 |
| `premium_anual` | 89.900 COP (`8990000` centavos) | `premium` | 12 |
| `premium_vida` | 149.900 COP (`14990000` centavos) | `premium` | 1200 |
| `equipo_3` (`5fZGtj`) | 39.900 COP (`3990000`) | `equipo` | 1, **3 códigos** |
| `equipo_5` (`1TY6Z1`) | 59.900 COP (`5990000`) | `equipo` | 1, **5 códigos** |
| `equipo_10` (`KUzO5b`) | 99.900 COP (`9990000`) | `equipo` | 1, **10 códigos** |
| `equipo_ilimitado` (`bwpwwK`) | 199.900 COP (`19990000`) | `equipo` | 1, **1 código de empresa** (hasta 100 equipos) |

Todos están creados y conectados en Make. Cada rama comprueba el ID del link en la referencia del pago **y** el monto exacto.

**Ramas de Equipo.** Un *Repeater* (3, 5 o 10 repeticiones) genera un código por vuelta y guarda su registro. Un *Text aggregator* junta los códigos en una lista y se envía **un solo correo**. Los códigos de Equipo no van atados al correo: su `code_hash` es `sha256(CODIGO + "|")`, con el email vacío, para que la empresa los reparta. En el escenario de canje, el límite de equipos es 3 por código, o 100 si la referencia del pago contiene `bwpwwK` (paquete ilimitado).

Las URLs de los links están en `CIPHERVAULT_WOMPI_LINK_MAP` (y como valor por defecto en `build.ps1`). Si llega un pago con un monto que no coincide con su link, no se genera ningún código.

1. **Repeater** (cantidad = equipos incluidos; 1 por defecto).
2. **Set variable `codigo`** (16 caracteres al azar, imposibles de adivinar sin el secreto):
   ```
   {{upper(substring(sha256(1.data.transaction.id + "-" + i + "-" + formatDate(now; "x") + "-" + TU_SECRETO; "hex"); 0; 16))}}
   ```
3. **Set variable `code_hash`** (SHA-256 hex minúsculas de `CODIGO_SIN_GUIONES_MAYÚSCULAS|email_minúsculas`):
   ```
   {{sha256(codigo + "|" + lower(trim(1.data.transaction.customer_email)); "hex")}}
   ```
4. **Data store: Add/replace a record** en `CipherVault_codigos`: clave = `code_hash`; `plan` = `premium`; `reference` = `{{1.data.transaction.reference}}`; `meses` = el de la rama (1, 12 o 1200); `created_at` = `{{formatDate(now; "YYYY-MM-DDTHH:mm:ss")}}`; `machine` y `used_at` vacíos.
5. **Text aggregator** (agrupa los códigos del Repeater) → **Gmail: Send an Email** al `customer_email` con cada código (formato `XXXX-XXXX-XXXX-XXXX`: `{{substring(codigo; 0; 4)}}-{{substring(codigo; 4; 4)}}-…`) y las instrucciones: «Instala CipherVault en el equipo, inicia sesión con la cuenta de este email → Activar licencia → pega el código. Sirve hasta en 3 equipos tuyos».
6. Al final: **Add a record** en `CipherVault_pagos` con la referencia.

Pon el correo **después** de guardar el registro en el Data Store, para que nunca se envíe un código que no exista.

## 3. Escenario B — canje (el que llama la app)

Crea un escenario nuevo y **actívalo con ejecución inmediata**. En sus ajustes activa **«Sequential processing»** (evita que dos canjes simultáneos del mismo código se ligen a dos equipos).

`Custom webhook` (recibe JSON `{v, code_hash, machine, nonce}`) → `Data store: Get a record` (clave = `{{1.code_hash}}`) → **Router**:

| Condición | Acción | Respuesta (Webhook response, `Content-Type: application/json`) |
|---|---|---|
| El registro no existe | — | `{"ok":false,"error":"invalid"}` |
| `machine` vacío, o equipo nuevo con cupo (`machine` no contiene `{{1.machine}}`, plan no empieza por `fs-` y `length(split(machine; ","))` < 3) | **Update record**: `machine = {{if(5.machine; 5.machine + "," + 1.machine; 1.machine)}}` (y `used_at` solo la primera vez) | respuesta OK (abajo) |
| `machine` contiene `{{1.machine}}` (equipo ya registrado) | — | respuesta OK (abajo) |
| Equipo nuevo sin cupo (3 equipos, o 1 si es un plan `fs-` de FileSync) | — | `{"ok":false,"error":"used"}` |

**Respuesta OK** (reemplaza `TU_SECRETO` por el mismo valor de `CIPHERVAULT_ACTIVATION_SECRET`; `2.` es el registro del Data Store):

```
{
  "ok": true,
  "plan": "{{2.plan}}",
  "reference": "{{2.reference}}",
  "meses": "{{2.meses}}",
  "created_at": "{{2.created_at}}",
  "sig": "{{sha256(1.code_hash + "|" + 1.machine + "|" + 1.nonce + "|" + 2.plan + "|" + 2.reference + "|" + 2.meses + "|" + 2.created_at + "|" + "TU_SECRETO"; "hex")}}"
}
```

La firma debe calcularse exactamente con esos campos y en ese orden, unidos por `|` y con el secreto al final; la app calcula lo mismo y descarta cualquier respuesta que no coincida (también si alguien repite una respuesta vieja, porque incluye el `nonce` y el equipo). Copia la URL del webhook en `CIPHERVAULT_ACTIVATION_URL` del `.env`.

> Los nombres de funciones de Make (`sha256`, `substring`, `lower`, `trim`, `upper`, `formatDate`) conviene comprobarlos en el editor de fórmulas de tu cuenta; el resultado debe ser siempre el mismo hash/firma descritos aquí.

## 4. Prueba de extremo a extremo

1. Crea una cuenta de prueba con tu email y haz un pago mínimo (sandbox o real).
2. Comprueba que llegó el correo con el código y que el Data Store tiene el registro con `machine` vacío.
3. En la app: Activar licencia → pega el código → debe mostrar el plan y el vencimiento; el registro ahora tiene `machine` y `used_at`.
4. Actívalo en un segundo y un tercer PC con el mismo email: debe funcionar. En un **cuarto** PC debe responder «ya está activado en 3 equipos».
5. Un código mal escrito debe rechazarse.

## 5. Proteger el webhook de pagos (muy recomendable)

La URL del Escenario A es su única barrera: cualquiera que la conozca puede mandar un evento `APPROVED` falso y recibir un código. Wompi firma sus eventos (`signature.checksum` y `signature.properties`): calcula el SHA-256 de los valores de esas propiedades, en orden, + `timestamp` + tu **secreto de eventos** de Wompi y deja pasar solo los que coincidan con `checksum`. Compara también `amount_in_cents` y `currency` con los de tu plan.

## 6. Cambio de PC y soporte

Si un cliente ya usó sus 3 equipos y cambia uno de ellos (o reinstala Windows y cambia su identificador), abre su registro en el Data Store y **borra del campo `machine` el identificador del PC viejo** (o vacía el campo entero). Podrá canjearlo de nuevo en el PC nuevo. El plan activo en el PC viejo seguirá funcionando hasta su vencimiento, así que conviene hacerlo solo cuando el cliente lo pida.

## 7. Después de migrar

- La hoja antigua de Google Sheets estaba publicada con emails de clientes: **déjala de publicar** (Archivo → Compartir → Publicar en la web → Dejar de publicar) y bórrala cuando ya no la necesites.
- Los clientes que pagaron con el sistema anterior no tienen código: créales uno (registro manual en `CipherVault_codigos` con su `created_at` original) y envíaselo.
- Las licencias activadas con el sistema anterior (sin código) pasan al plan gratuito con la versión nueva hasta que canjeen un código.
- Recompila con `.\build.ps1` (el script avisa si falta la URL o el secreto).

## Límites conocidos

- El Escenario B debe estar **encendido**: si Make está caído, los clientes nuevos no pueden activar (los ya activados siguen funcionando sin conexión).
- El secreto de firma viaja dentro del `.exe`; quien lo extraiga podría fabricar respuestas "válidas" para sí mismo. Es un freno razonable para un producto de este precio, pero no una protección absoluta: la alternativa sería un servicio propio que firme con Ed25519 (la app solo tendría la clave pública).
- El identificador del equipo sale de Windows (`MachineGuid`): clonar un disco completo a otro PC también clona el identificador.
- Sin firma de código del `.exe`, Windows y los antivirus seguirán mostrando avisos.
