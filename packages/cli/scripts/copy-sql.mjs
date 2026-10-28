// The CLI ships the repo's migration and shared checks unchanged: copy them at
// build time so there is one source (migrations/001_postgresql.sql,
// checks/postgresql.sql).
import { copyFileSync, mkdirSync } from "node:fs";
mkdirSync(new URL("../sql/", import.meta.url), { recursive: true });
copyFileSync(new URL("../../../migrations/001_postgresql.sql", import.meta.url),
             new URL("../sql/001_postgresql.sql", import.meta.url));
copyFileSync(new URL("../../../checks/postgresql.sql", import.meta.url),
             new URL("../sql/checks_postgresql.sql", import.meta.url));
