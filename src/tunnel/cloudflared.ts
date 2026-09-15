import { spawn, type ChildProcess } from "node:child_process";
import { lookup as dnsLookup } from "node:dns/promises";
import readline from "node:readline";
import type { Logger } from "../logger/index.js";
import { nullLogger } from "../logger/index.js";
import { SERVICE_NAME } from "../version.js";
import { findBinary } from "./detect.js";
import type {
  TunnelDoctorReport,
  TunnelProvider,
  TunnelReadinessStage,
  TunnelStatus,
} from "./provider.js";
import { tunnelProtocolArgs } from "./protocol.js";

const QUICK_TUNNEL_URL_RE = /https:\/\/[^\s|]+/gi;
const QUICK_TUNNEL_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)\.trycloudflare\.com$/i;
const REGISTERED_RE = /registered tunnel connection/i;
const HEALTH_CHECK_INTERVAL_MS = 250;
const HEALTH_CHECK_MAX_INTERVAL_MS = 2_000;
const HEALTH_CHECK_TIMEOUT_MS = 5_000;
const DNS_ERROR_CODES = new Set(["ENOTFOUND", "EAI_AGAIN", "EAI_FAIL", "EAI_NODATA"]);

function errorCode(error: unknown): string | null {
  let current = error;
  for (let depth = 0; depth < 5 && current && typeof current === "object"; depth += 1) {
    const record = current as { code?: unknown; cause?: unknown };
    if (typeof record.code === "string" && /^[A-Z0-9_]+$/i.test(record.code)) {
      return record.code.toUpperCase();
    }
    current = record.cause;
  }
  return null;
}

interface ReadinessFailure {
  stage: TunnelReadinessStage;
  code?: string;
  detail: string;
}

function formatReadinessFailure(failure: ReadinessFailure): string {
  return `${failure.stage}${failure.code ? ` (${failure.code})` : ""}: ${failure.detail}`;
}

function isBridgeHealth(payload: unknown): boolean {
  if (!payload || typeof payload !== "object") return false;
  const health = payload as Record<string, unknown>;
  return health.service === SERVICE_NAME && health.status === "ok";
}

async function fetchBridgeHealth(
  fetchImpl: NonNullable<CloudflaredQuickTunnelOptions["fetchImpl"]>,
  publicUrl: string
): Promise<Response> {
  return fetchImpl(new URL("/health", publicUrl).toString(), {
    redirect: "error",
    signal: AbortSignal.timeout(HEALTH_CHECK_TIMEOUT_MS),
  });
}

async function inspectBridgeHealth(response: Response): Promise<{ ready: boolean; detail: string }> {
  if (!response) return { ready: false, detail: "Health check did not run" };
  if (!response.ok) {
    await response.body?.cancel().catch(() => undefined);
    return { ready: false, detail: `Health check returned HTTP ${response.status}` };
  }
  return {
    ready: isBridgeHealth(await response.json().catch(() => null)),
    detail: `Health check did not identify ${SERVICE_NAME}`,
  };
}

/** Extract a Quick Tunnel public URL from a cloudflared log line. */
export function parseQuickTunnelUrl(line: string): string | null {
  for (const match of line.matchAll(QUICK_TUNNEL_URL_RE)) {
    try {
      const url = new URL(match[0]);
      if (url.protocol !== "https:" || !QUICK_TUNNEL_HOST_RE.test(url.hostname)) continue;
      if (url.hostname.toLowerCase() === "api.trycloudflare.com") continue;
      return url.origin;
    } catch {
      // Ignore malformed URLs embedded in log output.
    }
  }
  return null;
}

export interface CloudflaredQuickTunnelOptions {
  startTimeoutMs?: number;
  lookupImpl?: (hostname: string) => Promise<unknown>;
  spawnImpl?: (
    command: string,
    args: string[],
    options: { stdio: ["ignore", "pipe", "pipe"]; windowsHide: true }
  ) => ChildProcess;
  fetchImpl?: (input: string | URL, init?: RequestInit) => Promise<Response>;
}

/**
 * Cloudflare Quick Tunnel provider.
 * Quick Tunnels need no account/login; the URL changes on every start,
 * which the bridge and the Skill handle by reconfiguring automatically.
 */
export class CloudflaredQuickTunnel implements TunnelProvider {
  readonly name = "cloudflare-quick";
  private child: ChildProcess | null = null;
  private url: string | null = null;
  private readonly startTimeoutMs: number;
  private readonly spawnImpl: NonNullable<CloudflaredQuickTunnelOptions["spawnImpl"]>;
  private readonly fetchImpl: NonNullable<CloudflaredQuickTunnelOptions["fetchImpl"]>;
  private readonly lookupImpl: NonNullable<CloudflaredQuickTunnelOptions["lookupImpl"]>;
  private starting: Promise<string> | null = null;
  private cancelStart: (() => void) | null = null;
  private readiness: TunnelReadinessStage = "IDLE";
  private readinessFailure: ReadinessFailure | null = null;
  private processError: string | null = null;

  constructor(
    private readonly logger: Logger = nullLogger,
    private readonly binaryOverride?: string,
    options: CloudflaredQuickTunnelOptions = {}
  ) {
    this.startTimeoutMs = options.startTimeoutMs ?? 45_000;
    this.spawnImpl = options.spawnImpl ?? ((command, args, spawnOptions) => spawn(command, args, spawnOptions));
    this.fetchImpl = options.fetchImpl ?? ((input, init) => fetch(input, init));
    this.lookupImpl = options.lookupImpl ?? dnsLookup;
  }

  private binary(): string | null {
    return this.binaryOverride ?? findBinary("cloudflared");
  }

  private readinessDetail(): string | undefined {
    if (this.readinessFailure) {
      return `last readiness failure = ${formatReadinessFailure(this.readinessFailure)}`;
    }
    return this.processError ?? undefined;
  }

  async start(localPort: number): Promise<string> {
    if (this.child && this.url) return this.url;
    if (this.starting) return this.starting;
    const starting = this.startProcess(localPort);
    this.starting = starting;
    try {
      return await starting;
    } finally {
      if (this.starting === starting) this.starting = null;
    }
  }

  private startProcess(localPort: number): Promise<string> {
    const bin = this.binary();
    if (!bin) {
      this.readiness = "FAILED";
      this.processError = "cloudflared is not installed";
      return Promise.reject(
        new Error(
          "cloudflared is not installed. Install it (e.g. `brew install cloudflared`) and retry."
        )
      );
    }

    return new Promise<string>((resolve, reject) => {
      let child: ChildProcess;
      try {
        child = this.spawnImpl(
          bin,
          ["tunnel", "--url", `http://127.0.0.1:${localPort}`, "--no-autoupdate", ...tunnelProtocolArgs()],
          { stdio: ["ignore", "pipe", "pipe"], windowsHide: true }
        );
      } catch (error) {
        this.readiness = "FAILED";
        this.processError = error instanceof Error ? error.message : String(error);
        reject(error);
        return;
      }
      this.child = child;
      this.url = null;
      this.readinessFailure = null;
      this.processError = null;
      this.readiness = "SPAWNED";
      let settled = false;
      let candidateUrl: string | null = null;
      let registered = false;
      let healthStarted = false;
      let cancel: (() => void) | null = null;
      let timeout: ReturnType<typeof setTimeout> | undefined;

      const closeReaders = (): void => {
        child.stdout?.destroy();
        child.stderr?.destroy();
      };

      const isAlive = (): boolean => this.child === child;

      const stopChild = (): void => {
        try {
          child.kill("SIGTERM");
        } catch {
          // The process may have exited between the state check and kill().
        }
      };

      const finish = (callback: () => void, closeOutput = true): void => {
        if (settled) return;
        settled = true;
        if (timeout) clearTimeout(timeout);
        if (closeOutput) closeReaders();
        if (cancel && this.cancelStart === cancel) this.cancelStart = null;
        callback();
      };

      const fail = (error: unknown): void => {
        const failure = error instanceof Error ? error : new Error(String(error));
        finish(() => {
          this.readiness = "FAILED";
          this.processError = failure.message;
          stopChild();
          if (this.child === child) {
            this.child = null;
            this.url = null;
          }
          reject(failure);
        });
      };

      cancel = () => fail(new Error("Tunnel start stopped"));
      this.cancelStart = cancel;

      const ready = (url: string): void => {
        if (!isAlive()) {
          fail(new Error("cloudflared exited before the public health endpoint became ready"));
          return;
        }
        finish(
          () => {
            this.url = url;
            this.readinessFailure = null;
            this.processError = null;
            this.readiness = "READY";
            this.logger.info(`Quick tunnel established: ${url}`);
            resolve(url);
          },
          false
        );
      };

      const waitForHealth = async (): Promise<void> => {
        const publicUrl = candidateUrl;
        if (!publicUrl) return;
        const hostname = new URL(publicUrl).hostname;
        let retryDelayMs = HEALTH_CHECK_INTERVAL_MS;
        while (!settled) {
          if (!isAlive()) {
            fail(new Error("cloudflared exited before the public health endpoint became ready"));
            return;
          }

          this.readiness = "DNS_PENDING";
          try {
            await this.lookupImpl(hostname);
          } catch (error) {
            if (settled) return;
            const code = errorCode(error);
            this.readinessFailure = {
              stage: "DNS_PENDING",
              code: code ?? undefined,
              detail: "DNS lookup failed",
            };
            await new Promise((resolveWait) => setTimeout(resolveWait, retryDelayMs));
            retryDelayMs = Math.min(retryDelayMs * 2, HEALTH_CHECK_MAX_INTERVAL_MS);
            continue;
          }
          if (settled) return;

          this.readiness = "CONNECT_PENDING";
          let response: Response;
          try {
            response = await fetchBridgeHealth(this.fetchImpl, publicUrl);
          } catch (error) {
            if (settled) return;
            const code = errorCode(error);
            if (code && DNS_ERROR_CODES.has(code)) {
              this.readiness = "DNS_PENDING";
              this.readinessFailure = {
                stage: "DNS_PENDING",
                code,
                detail: "DNS lookup failed",
              };
            } else {
              this.readinessFailure = {
                stage: "CONNECT_PENDING",
                code: code ?? undefined,
                detail: "Public request failed",
              };
            }
            await new Promise((resolveWait) => setTimeout(resolveWait, retryDelayMs));
            retryDelayMs = Math.min(retryDelayMs * 2, HEALTH_CHECK_MAX_INTERVAL_MS);
            continue;
          }
          if (settled) {
            await response.body?.cancel().catch(() => undefined);
            return;
          }

          this.readiness = "HEALTH_PENDING";
          try {
            const result = await inspectBridgeHealth(response);
            if (settled) return;
            if (result.ready) {
              ready(publicUrl);
              return;
            }
            this.readinessFailure = {
              stage: "HEALTH_PENDING",
              detail: result.detail,
            };
          } catch (error) {
            if (settled) return;
            const code = errorCode(error);
            this.readinessFailure = {
              stage: "HEALTH_PENDING",
              code: code ?? undefined,
              detail: "Health check failed",
            };
          }
          if (settled) return;
          await new Promise((resolveWait) => setTimeout(resolveWait, retryDelayMs));
          retryDelayMs = Math.min(retryDelayMs * 2, HEALTH_CHECK_MAX_INTERVAL_MS);
        }
      };

      const startHealthCheck = (): void => {
        if (healthStarted || !registered || !candidateUrl) return;
        healthStarted = true;
        void waitForHealth().catch((error) => {
          this.logger.error(`Quick tunnel health check failed: ${String(error)}`);
        });
      };

      timeout = setTimeout(() => {
        if (!settled) {
          const detail = this.readinessFailure
            ? `: last readiness failure = ${formatReadinessFailure(this.readinessFailure)}`
            : this.processError
              ? `: process error = ${this.processError}`
              : "";
          const message = this.readinessFailure
            ? `Tunnel start timed out${detail}`
            : `Tunnel start timed out at ${this.readiness}${detail}`;
          this.logger.error(message);
          fail(new Error(message));
        }
      }, this.startTimeoutMs);

      const scan = (stream: NodeJS.ReadableStream): void => {
        const rl = readline.createInterface({ input: stream });
        rl.on("line", (line) => {
          const url = parseQuickTunnelUrl(line);
          if (url && !candidateUrl) {
            candidateUrl = url;
            startHealthCheck();
          }
          if (REGISTERED_RE.test(line) && !registered) {
            registered = true;
            this.readiness = "REGISTERED";
            startHealthCheck();
          }
          if (/\b(?:ERR|error|failed|fatal)\b/i.test(line)) {
            this.processError = line.slice(0, 400);
            this.logger.debug(`cloudflared: ${line.slice(0, 400)}`);
          }
        });
      };
      if (child.stdout) scan(child.stdout);
      if (child.stderr) scan(child.stderr);

      child.on("error", (error) => {
        closeReaders();
        if (this.child === child) {
          this.child = null;
          this.url = null;
          this.readiness = "FAILED";
          this.processError = error.message;
        }
        if (!settled) fail(error);
      });
      child.on("exit", (code) => {
        closeReaders();
        if (this.child === child) {
          this.child = null;
          this.url = null;
          this.readiness = "FAILED";
          this.processError = `cloudflared exited (code ${code})`;
        }
        this.logger.warn(`cloudflared exited with code ${code}`);
        if (!settled) {
          fail(
            new Error(
              `cloudflared exited (code ${code}) before establishing a tunnel${this.processError ? `: ${this.processError}` : ""}`
            )
          );
        }
      });
    });
  }

  async stop(): Promise<void> {
    this.cancelStart?.();
    if (this.child) {
      try {
        this.child.kill("SIGTERM");
      } catch {
        // The process may have exited between the state check and kill().
      }
      this.child = null;
    }
    this.url = null;
    this.readinessFailure = null;
    this.processError = null;
    this.readiness = "IDLE";
  }

  async restart(localPort: number): Promise<string> {
    await this.stop();
    return this.start(localPort);
  }

  status(): TunnelStatus {
    return {
      running: this.child !== null && this.url !== null,
      url: this.url,
      provider: this.name,
      detail: this.readinessDetail(),
      readiness: this.readiness,
    };
  }

  getPublicUrl(): string | null {
    return this.url;
  }

  async doctor(): Promise<TunnelDoctorReport> {
    const bin = this.binary();
    const problems: string[] = [];
    if (!bin) problems.push("cloudflared binary not found");
    if (bin && !this.child) problems.push("tunnel process not running");
    if (this.child && !this.url) {
      problems.push(
        `tunnel readiness is ${this.readiness}${this.readinessDetail() ? `: ${this.readinessDetail()}` : ""}`
      );
    }
    return {
      provider: this.name,
      binaryFound: bin !== null,
      binaryPath: bin,
      running: this.child !== null,
      url: this.url,
      problems,
      readiness: this.readiness,
    };
  }
}
