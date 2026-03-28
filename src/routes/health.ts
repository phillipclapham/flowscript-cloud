/**
 * Health endpoint — no auth required.
 */

import { Hono } from "hono";

export const healthRoutes = new Hono();

healthRoutes.get("/health", (c) => {
  return c.json({ status: "ok", version: "0.1.0" });
});
