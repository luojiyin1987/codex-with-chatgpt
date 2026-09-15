import { describe, it, expect, afterEach, vi } from "vitest";
import { EventEmitter } from "node:events";
import fs from "node:fs";
import type { ChildProcess } from "node:child_process";
import { PassThrough } from "node:stream";
import { findBinary } from "../src/tunnel/detect.js";
import {
  CloudflaredQuickTunnel,
  parseQuickTunnelUrl,
  type CloudflaredQuickTunnelOptions,
} from "../src/tunnel/cloudflared.js";
import { normalizeNamedTunnelHostname } from "../src/tunnel/cloudflared-named.js";
import { hostnameSlug, parseZoneInput, suggestedNamedHostname } from "../src/tunnel/hostname.js";
import {
  chooseQuickTunnel,
  isBenignRouteError,
  parseCreatedTunnel,
  parseTunnelList,
  provisionNamedTunnel,
  type CloudflaredAccount,
} from "../src/tunnel/named-provision.js";
import { resolveTunnelProtocol, tunnelProtocolArgs } from "../src/tunnel/protocol.js";
import { isNamedTunnelReady, needsTunnelChoice, readTunnelState } from "../src/tunnel/state.js";
import { cleanup, isolateStateDir, makeTmpDir, write } from "./helpers.js";

const stateDirs: string[] = [];
const previousStateDir = process.env.C2C_STATE_DIR;
const previousCloudflaredPath = process.env.C2C_CLOUDFLARED_PATH;
const QUICK_URL = "https://random-words-here-1234.trycloudflare.com";
type FetchImpl = NonNullable<CloudflaredQuickTunnelOptions["fetchImpl"]>;

class FakeCloudflaredProcess extends EventEmitter {
  readonly stdout = new PassThrough();
  readonly stderr = new PassThrough();
  exitCode: number | null = null;
  signalCode: NodeJS.Signals | null = null;
  killed = false;
  readonly kill = vi.fn(() => {
    this.killed = true;
    return true;
  });
}

function setupTunnel(fetchImpl: FetchImpl, startTimeoutMs = 1_000) {
  const child = new FakeCloudflaredProcess();
  const spawnImpl = vi.fn(() => child as unknown as ChildProcess);
  const tunnel = new CloudflaredQuickTunnel(undefined, "cloudflared", {
    spawnImpl,
    fetchImpl,
    lookupImpl: async () => undefined,
    startTimeoutMs,
  });
  return { child, spawnImpl, tunnel };
}

function announceUrl(child: FakeCloudflaredProcess): void {
  child.stderr.write(`INF ${QUICK_URL}\n`);
  child.stderr.write("INF Registered tunnel connection\n");
}

function healthResponse(): Response {
  return new Response(JSON.stringify({ service: "c2c-bridge", status: "ok" }), { status: 200 });
}

afterEach(() => {
  while (stateDirs.length) cleanup(stateDirs.pop()!);
  if (previousStateDir === undefined) delete process.env.C2C_STATE_DIR;
  else process.env.C2C_STATE_DIR = previousStateDir;
  if (previousCloudflaredPath === undefined) delete process.env.C2C_CLOUDFLARED_PATH;
  else process.env.C2C_CLOUDFLARED_PATH = previousCloudflaredPath;
});

describe("findBinary", () => {
  it("uses C2C_CLOUDFLARED_PATH for an accessible cloudflared executable", () => {
    const dir = makeTmpDir("cloudflared-path");
    stateDirs.push(dir);
    const filename = process.platform === "win32" ? "cloudflared.exe" : "cloudflared";
    const configured = write(dir, filename, "placeholder");
    if (process.platform !== "win32") fs.chmodSync(configured, 0o755);
    process.env.C2C_CLOUDFLARED_PATH = configured;
    expect(findBinary("cloudflared")).toBe(configured);
  });
});

describe("parseQuickTunnelUrl", () => {
  it("extracts the URL from cloudflared banner output", () => {
    const line =
      "2026-08-28T10:00:00Z INF |  https://random-words-here-1234.trycloudflare.com                              |";
    expect(parseQuickTunnelUrl(line)).toBe(QUICK_URL);
  });

  it("ignores unrelated lines and non-Quick-Tunnel hosts", () => {
    expect(parseQuickTunnelUrl("INF Starting tunnel connection")).toBeNull();
    expect(parseQuickTunnelUrl("visit https://www.cloudflare.com for docs")).toBeNull();
    expect(parseQuickTunnelUrl("https://evil.example.com/trycloudflare.com")).toBeNull();
  });

  it("rejects Cloudflare's API host", () => {
    expect(parseQuickTunnelUrl("INF https://api.trycloudflare.com")).toBeNull();
  });
});

describe("CloudflaredQuickTunnel", () => {
  it("reports each readiness stage before the public endpoint becomes ready", async () => {
    let resolveLookup!: () => void;
    let resolveFetch!: () => void;
    let resolveJson!: () => void;
    const lookupImpl = vi.fn(
      () => new Promise<void>((resolve) => {
        resolveLookup = resolve;
      })
    );
    const response = new Response(null, { status: 200 });
    vi.spyOn(response, "json").mockImplementation(
      () => new Promise((resolve) => {
        resolveJson = () => resolve({ service: "c2c-bridge", status: "ok" });
      })
    );
    const child = new FakeCloudflaredProcess();
    const tunnel = new CloudflaredQuickTunnel(undefined, "cloudflared", {
      spawnImpl: () => child as unknown as ChildProcess,
      lookupImpl,
      fetchImpl: () => new Promise((resolve) => {
        resolveFetch = () => resolve(response);
      }),
      startTimeoutMs: 1_000,
    });

    const starting = tunnel.start(3333);
    child.stderr.write(`INF ${QUICK_URL}\n`);
    await new Promise((resolve) => setImmediate(resolve));
    expect(tunnel.status()).toMatchObject({ running: false, readiness: "SPAWNED" });
    child.stderr.write("INF Registered tunnel connection\n");
    await new Promise((resolve) => setImmediate(resolve));

    expect(tunnel.status()).toMatchObject({ running: false, readiness: "DNS_PENDING" });
    resolveLookup();
    await new Promise((resolve) => setImmediate(resolve));
    expect(tunnel.status()).toMatchObject({ running: false, readiness: "CONNECT_PENDING" });
    resolveFetch();
    await new Promise((resolve) => setImmediate(resolve));
    expect(tunnel.status()).toMatchObject({ running: false, readiness: "HEALTH_PENDING" });
    resolveJson();
    await expect(starting).resolves.toBe(QUICK_URL);
    expect(tunnel.status()).toMatchObject({ running: true, readiness: "READY" });
    await tunnel.stop();
  });

  it("includes the DNS stage and resolver code in the timeout error", async () => {
    const error = Object.assign(new Error("getaddrinfo ENOTFOUND"), { code: "ENOTFOUND" });
    const { child, tunnel } = setupTunnel(
      async () => {
        throw new TypeError("fetch failed", { cause: error });
      },
      50
    );
    const starting = tunnel.start(3333);
    announceUrl(child);
    await new Promise((resolve) => setImmediate(resolve));
    child.stderr.write("ERR transient edge connection warning\n");
    await new Promise((resolve) => setImmediate(resolve));

    expect(tunnel.status().detail).toBe(
      "last readiness failure = DNS_PENDING (ENOTFOUND): DNS lookup failed"
    );
    await expect(starting).rejects.toThrow(
      /last readiness failure = DNS_PENDING \(ENOTFOUND\): DNS lookup failed/
    );
    expect(tunnel.status()).toMatchObject({ running: false, readiness: "FAILED" });
  });

  it("keeps an HTTP failure bound to its observed readiness stage", async () => {
    vi.useFakeTimers();
    try {
      const lookupImpl = vi.fn()
        .mockResolvedValueOnce({ address: "203.0.113.1", family: 4 })
        .mockImplementation(() => new Promise(() => {}));
      const child = new FakeCloudflaredProcess();
      const tunnel = new CloudflaredQuickTunnel(undefined, "cloudflared", {
        spawnImpl: () => child as unknown as ChildProcess,
        lookupImpl,
        fetchImpl: async () => new Response(null, { status: 503 }),
        startTimeoutMs: 400,
      });

      const starting = tunnel.start(3333);
      const settled = starting.catch((error: unknown) => error);
      announceUrl(child);
      await vi.advanceTimersByTimeAsync(250);

      expect(tunnel.status()).toMatchObject({
        readiness: "DNS_PENDING",
        detail: "last readiness failure = HEALTH_PENDING: Health check returned HTTP 503",
      });
      await vi.advanceTimersByTimeAsync(150);
      expect(await settled).toEqual(
        expect.objectContaining({
          message: expect.stringMatching(
            /last readiness failure = HEALTH_PENDING: Health check returned HTTP 503/
          ),
        })
      );
    } finally {
      vi.useRealTimers();
    }
  });

  it("classifies non-DNS fetch failures as public connection failures", async () => {
    const error = Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" });
    const { child, tunnel } = setupTunnel(
      async () => {
        throw new TypeError("fetch failed", { cause: error });
      },
      20
    );
    const starting = tunnel.start(3333);
    announceUrl(child);

    await expect(starting).rejects.toThrow(
      /CONNECT_PENDING \(ECONNREFUSED\): Public request failed/
    );
  });

  it("uses bounded backoff while DNS propagation catches up", async () => {
    vi.useFakeTimers();
    try {
      const error = Object.assign(new Error("getaddrinfo ENOTFOUND"), { code: "ENOTFOUND" });
      const lookupImpl = vi.fn()
        .mockRejectedValueOnce(error)
        .mockRejectedValueOnce(error)
        .mockResolvedValue({ address: "203.0.113.1", family: 4 });
      const child = new FakeCloudflaredProcess();
      const tunnel = new CloudflaredQuickTunnel(undefined, "cloudflared", {
        spawnImpl: () => child as unknown as ChildProcess,
        lookupImpl,
        fetchImpl: async () => healthResponse(),
        startTimeoutMs: 2_000,
      });

      const starting = tunnel.start(3333);
      announceUrl(child);
      await vi.advanceTimersByTimeAsync(0);
      expect(lookupImpl).toHaveBeenCalledTimes(1);
      expect(tunnel.status()).toMatchObject({
        readiness: "DNS_PENDING",
        detail: "last readiness failure = DNS_PENDING (ENOTFOUND): DNS lookup failed",
      });

      await vi.advanceTimersByTimeAsync(249);
      expect(lookupImpl).toHaveBeenCalledTimes(1);
      await vi.advanceTimersByTimeAsync(1);
      expect(lookupImpl).toHaveBeenCalledTimes(2);
      await vi.advanceTimersByTimeAsync(499);
      expect(lookupImpl).toHaveBeenCalledTimes(2);
      await vi.advanceTimersByTimeAsync(1);

      await expect(starting).resolves.toBe(QUICK_URL);
      expect(lookupImpl).toHaveBeenCalledTimes(3);
      await tunnel.stop();
    } finally {
      vi.useRealTimers();
    }
  });

  it("resolves only after the public health endpoint identifies the bridge", async () => {
    const fetchImpl = vi.fn(async () => healthResponse());
    const { child, spawnImpl, tunnel } = setupTunnel(fetchImpl);
    const starting = tunnel.start(3333);
    announceUrl(child);

    await expect(starting).resolves.toBe(QUICK_URL);
    expect(spawnImpl).toHaveBeenCalledWith(
      "cloudflared",
      ["tunnel", "--url", "http://127.0.0.1:3333", "--no-autoupdate"],
      { stdio: ["ignore", "pipe", "pipe"], windowsHide: true }
    );
    expect(fetchImpl).toHaveBeenCalledWith(`${QUICK_URL}/health`, {
      redirect: "error",
      signal: expect.any(AbortSignal),
    });
    expect(tunnel.status()).toMatchObject({ running: true, url: QUICK_URL });
    await tunnel.stop();
  });

  it("passes --protocol when C2C_TUNNEL_PROTOCOL is set", async () => {
    vi.stubEnv("C2C_TUNNEL_PROTOCOL", "http2");
    const { child, spawnImpl, tunnel } = setupTunnel(async () => healthResponse());
    const starting = tunnel.start(3333);
    announceUrl(child);
    await expect(starting).resolves.toBe(QUICK_URL);
    expect(spawnImpl).toHaveBeenCalledWith(
      "cloudflared",
      ["tunnel", "--url", "http://127.0.0.1:3333", "--no-autoupdate", "--protocol", "http2"],
      { stdio: ["ignore", "pipe", "pipe"], windowsHide: true }
    );
    await tunnel.stop();
    vi.unstubAllEnvs();
  });

  it("keeps consuming cloudflared errors after the tunnel is ready", async () => {
    const { child, tunnel } = setupTunnel(async () => healthResponse());
    const starting = tunnel.start(3333);
    announceUrl(child);
    await expect(starting).resolves.toBe(QUICK_URL);

    child.stderr.write("ERR runtime connection error\n");
    await new Promise((resolve) => setImmediate(resolve));
    expect(tunnel.status().detail).toBe("ERR runtime connection error");
    await tunnel.stop();
  });

  it("does not accept an HTTP 200 response from another service", async () => {
    const { child, tunnel } = setupTunnel(
      async () =>
        new Response(JSON.stringify({ service: "cloudflare", status: "ok" }), { status: 200 }),
      20
    );
    const starting = tunnel.start(3333);
    announceUrl(child);

    await expect(starting).rejects.toThrow(/timed out/i);
    expect(child.kill).toHaveBeenCalledWith("SIGTERM");
    expect(tunnel.status()).toMatchObject({ running: false, url: null });
  });

  it("does not spawn twice or resolve a stopped pending start", async () => {
    const { child, spawnImpl, tunnel } = setupTunnel(() => new Promise<Response>(() => {}));
    const starting = tunnel.start(3333);
    announceUrl(child);
    await new Promise((resolve) => setImmediate(resolve));

    const concurrent = tunnel.start(3333);
    await tunnel.stop();
    await expect(starting).rejects.toThrow(/stopped/i);
    await expect(concurrent).rejects.toThrow(/stopped/i);
    expect(spawnImpl).toHaveBeenCalledTimes(1);
    expect(child.kill).toHaveBeenCalledWith("SIGTERM");
  });

  it("does not resolve if cloudflared exits while the health probe is in flight", async () => {
    let resolveFetch!: (response: Response) => void;
    const { child, tunnel } = setupTunnel(
      () => new Promise<Response>((resolve) => (resolveFetch = resolve))
    );
    const starting = tunnel.start(3333);
    announceUrl(child);
    await new Promise((resolve) => setImmediate(resolve));

    child.exitCode = 1;
    child.emit("exit", 1, null);
    resolveFetch(healthResponse());
    await expect(starting).rejects.toThrow(/exited/i);
    expect(tunnel.status()).toMatchObject({ running: false, url: null });
  });

  it("rejects when spawning reports an asynchronous error", async () => {
    const { child, tunnel } = setupTunnel(async () => new Response(null));
    const starting = tunnel.start(3333);
    await new Promise((resolve) => setImmediate(resolve));
    child.emit("error", new Error("spawn cloudflared ENOENT"));

    await expect(starting).rejects.toThrow(/ENOENT/i);
    expect(tunnel.status()).toMatchObject({ running: false, url: null });
  });

  it("retries a non-ready health response before resolving", async () => {
    let calls = 0;
    const cancelBody = vi.fn(async () => undefined);
    const { child, tunnel } = setupTunnel(async () => {
      calls += 1;
      return calls === 1
        ? ({ ok: false, status: 503, body: { cancel: cancelBody } } as unknown as Response)
        : healthResponse();
    });
    const starting = tunnel.start(3333);
    announceUrl(child);

    await expect(starting).resolves.toBe(QUICK_URL);
    expect(calls).toBe(2);
    expect(cancelBody).toHaveBeenCalledTimes(1);
    await tunnel.stop();
  });
});

describe("tunnel transport protocol", () => {
  it("keeps cloudflared's default when C2C_TUNNEL_PROTOCOL is unset or empty", () => {
    expect(resolveTunnelProtocol({})).toBeNull();
    expect(resolveTunnelProtocol({ C2C_TUNNEL_PROTOCOL: "  " })).toBeNull();
    expect(tunnelProtocolArgs(null)).toEqual([]);
  });

  it("accepts the cloudflared protocol names case-insensitively", () => {
    expect(resolveTunnelProtocol({ C2C_TUNNEL_PROTOCOL: "HTTP2" })).toBe("http2");
    expect(resolveTunnelProtocol({ C2C_TUNNEL_PROTOCOL: " quic " })).toBe("quic");
    expect(resolveTunnelProtocol({ C2C_TUNNEL_PROTOCOL: "auto" })).toBe("auto");
    expect(tunnelProtocolArgs("http2")).toEqual(["--protocol", "http2"]);
  });

  it("rejects unknown protocols instead of silently falling back", () => {
    expect(() => resolveTunnelProtocol({ C2C_TUNNEL_PROTOCOL: "tcp" })).toThrow(
      /C2C_TUNNEL_PROTOCOL must be one of auto, quic, http2/
    );
  });
});

describe("normalizeNamedTunnelHostname", () => {
  it("normalizes a valid hostname", () => {
    expect(normalizeNamedTunnelHostname("Dev.GetRemi.xyz.")).toBe("dev.getremi.xyz");
  });

  it("rejects URLs and invalid hostnames", () => {
    expect(() => normalizeNamedTunnelHostname("https://dev.getremi.xyz")).toThrow(/invalid/i);
    expect(() => normalizeNamedTunnelHostname("localhost")).toThrow(/invalid/i);
  });
});

describe("named hostname helpers", () => {
  it("builds a stable c2c-<project>.<zone> hostname", () => {
    expect(suggestedNamedHostname("Example.COM", "My App", "abcdef123456")).toBe("c2c-my-app.example.com");
  });

  it("falls back to the workspace id when the name is not ASCII", () => {
    expect(hostnameSlug("回声", "abcdef123456")).toBe("c2c-ws-abcdef12");
  });

  it("parses a typed domain", () => {
    expect(parseZoneInput("https://Example.com/")).toBe("example.com");
    expect(parseZoneInput("not a domain")).toBeNull();
  });
});

describe("cloudflared output parsers", () => {
  it("reads a tunnel list table", () => {
    const output = `
ID                                   NAME          CREATED
11111111-1111-1111-1111-111111111111 c2c-abc123    2026-08-30
`;
    expect(parseTunnelList(output)).toEqual([
      { id: "11111111-1111-1111-1111-111111111111", name: "c2c-abc123" },
    ]);
  });

  it("reads created-tunnel output", () => {
    expect(
      parseCreatedTunnel(
        "Created tunnel c2c-abc with id 22222222-2222-2222-2222-222222222222",
        "c2c-abc"
      )
    ).toEqual({ id: "22222222-2222-2222-2222-222222222222", name: "c2c-abc" });
  });

  it("treats an existing DNS route as success", () => {
    expect(isBenignRouteError("Failed to add route: record already exists")).toBe(true);
  });
});

describe("tunnel preference state", () => {
  it("asks once, then remembers a quick choice", () => {
    stateDirs.push(isolateStateDir());
    const unset = readTunnelState("ws1");
    expect(needsTunnelChoice(unset)).toBe(true);
    const saved = chooseQuickTunnel("ws1");
    expect(saved.preference).toBe("quick");
    expect(needsTunnelChoice(readTunnelState("ws1"))).toBe(false);
    expect(isNamedTunnelReady(saved)).toBe(false);
  });

  it("provisions a named hostname through the account adapter and stores it outside the project", () => {
    stateDirs.push(isolateStateDir());
    const account: CloudflaredAccount = {
      hasCert: () => true,
      login: async () => undefined,
      listTunnels: async () => [],
      createTunnel: async (name) => ({ id: "33333333-3333-3333-3333-333333333333", name }),
      routeDns: async () => undefined,
    };
    return provisionNamedTunnel({
      workspaceId: "abcdef123456",
      workspaceName: "Demo",
      zone: "example.com",
      account,
    }).then((result) => {
      expect(result.fallback).toBe(false);
      expect(result.state.preference).toBe("named");
      expect(result.state.hostname).toBe("c2c-demo.example.com");
      expect(result.state.tunnelName).toBe("c2c-abcdef123456");
      expect(isNamedTunnelReady(readTunnelState("abcdef123456"))).toBe(true);
    });
  });

  it("falls back to a temporary address when named provisioning fails", () => {
    stateDirs.push(isolateStateDir());
    const account: CloudflaredAccount = {
      hasCert: () => true,
      login: async () => undefined,
      listTunnels: async () => [],
      createTunnel: async () => {
        throw new Error("no zone");
      },
      routeDns: async () => undefined,
    };
    return provisionNamedTunnel({
      workspaceId: "ws2",
      workspaceName: "Demo",
      zone: "example.com",
      account,
    }).then((result) => {
      expect(result.fallback).toBe(true);
      expect(result.state.preference).toBe("quick");
      expect(result.userMessage).toMatch(/临时地址/);
    });
  });
});
