import { createServer } from "node:http";
import { describe, expect, it } from "vitest";
import { getPath, send } from "../src/target.ts";

describe("target client", () => {
  it("reads nested reply paths", () => {
    expect(getPath({ choices: [{ message: { content: "hi" } }] }, "choices.0.message.content")).toBe("hi");
    expect(getPath({ a: 1 }, "b.c")).toBeUndefined();
  });

  it("fills prompt, session and spreads history into an OpenAI-style body", async () => {
    let seen: any;
    const server = createServer((req, res) => {
      let b = "";
      req.on("data", (c) => (b += c));
      req.on("end", () => {
        seen = JSON.parse(b);
        res.end(JSON.stringify({ choices: [{ message: { content: "ok" } }] }));
      });
    });
    await new Promise<void>((r) => server.listen(0, r));
    const port = (server.address() as { port: number }).port;
    const reply = await send(
      {
        name: "t", url: `http://localhost:${port}`, method: "POST", headers: { "content-type": "application/json" },
        body: { sid: "{{session}}", messages: ["{{history}}", { role: "user", content: "{{prompt}}" }] },
        response: "choices.0.message.content", timeoutMs: 5000, gate: true,
      },
      "second",
      "s-1",
      [{ role: "user", content: "first" }, { role: "assistant", content: "hello" }],
    );
    server.close();
    expect(reply.text).toBe("ok");
    expect(seen.sid).toBe("s-1");
    expect(seen.messages).toEqual([
      { role: "user", content: "first" },
      { role: "assistant", content: "hello" },
      { role: "user", content: "second" },
    ]);
  });
});
