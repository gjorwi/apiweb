import { randomBytes } from "node:crypto";

console.log("Elige un ADMIN_ACCESS_CODE memorable (mínimo 8 caracteres) y guárdalo en api/.env.");
console.log("Copia la clave JWT en api/.env y la ruta privada en front/.env.local:\n");
console.log(`ADMIN_JWT_SECRET=${randomBytes(48).toString("hex")}`);
console.log(`ADMIN_ROUTE_SLUG=${randomBytes(16).toString("base64url")}`);
