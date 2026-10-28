// The CLI ships the repo's migration unchanged: copy it at build time so there
// is one source (migrations/001_postgresql.sql).
import { copyFileSync, mkdirSync } from "node:fs";
mkdirSync(new URL("../sql/", import.meta.url), { recursive: true });
copyFileSync(new URL("../../../migrations/001_postgresql.sql", import.meta.url),
             new URL("../sql/001_postgresql.sql", import.meta.url));
