import { serve } from "@hono/node-server";
import { Hono } from "hono";

const app = new Hono();
const items = [];
let nextID = 1;

app.get("/health", (c) =>
  c.json({
    status: "ok",
    itemCount: items.length,
  }),
);

app.get("/items", (c) =>
  c.json({
    items,
  }),
);

app.post("/items", async (c) => {
  const body = await c.req.json().catch(() => null);
  const title = typeof body?.title === "string" ? body.title.trim() : "";

  if (title === "") {
    return c.json(
      {
        error: "title is required",
      },
      400,
    );
  }

  const item = {
    id: String(nextID++),
    title,
    createdAt: new Date().toISOString(),
  };
  items.unshift(item);

  return c.json(item, 201);
});

app.delete("/items/:id", (c) => {
  const { id } = c.req.param();
  const index = items.findIndex((item) => item.id === id);

  if (index === -1) {
    return c.json(
      {
        error: "item not found",
      },
      404,
    );
  }

  const [deleted] = items.splice(index, 1);
  return c.json({
    deletedId: deleted.id,
  });
});

const port = Number.parseInt(process.env.PORT ?? "3000", 10);

serve(
  {
    fetch: app.fetch,
    port,
  },
  (info) => {
    console.log(`demo api listening on http://localhost:${info.port}`);
  },
);
