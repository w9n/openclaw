import { readFileSync, writeFileSync } from "node:fs";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildScopedCapability,
  runNightClawerTelegramProof,
  sanitizedChildEnvironment,
} from "../../scripts/mantis/run-night-clawer-telegram-proof.mjs";
import { useAutoCleanupTempDirTracker } from "../helpers/temp-dir.js";

const tempDirs = useAutoCleanupTempDirTracker(afterEach);

describe("Mantis Night Clawer Telegram proof owner", () => {
  it("rejects untrusted sources before acquiring a credential", async () => {
    const acquireCredential = vi.fn();
    await expect(
      runNightClawerTelegramProof(
        {
          controllerRoot: "/missing",
          controllerSha: "a".repeat(40),
          openclawSha: "b".repeat(40),
          output: "/tmp/result.json",
        },
        {
          acquireCredential,
          runController: vi.fn(),
          startProxy: vi.fn(),
          verifySources: () => {
            throw new Error("controller SHA differs");
          },
        },
      ),
    ).rejects.toThrow(/controller SHA differs/u);
    expect(acquireCredential).not.toHaveBeenCalled();
  });

  it("passes only a scoped temporary capability and releases the lease", async () => {
    const root = tempDirs.make("mantis-night-clawer-owner-");
    const stateRoot = `${root}/state`;
    const userDriverDir = `${stateRoot}/user-driver`;
    const output = `${root}/result.json`;
    const release = vi.fn(async () => {});
    const close = vi.fn(async () => {});
    const credential = {
      groupId: "-1009001",
      stateRoot,
      sutBotId: "900002",
      sutToken: "900002:" + "A".repeat(32),
      sutUsername: "h3_test_bot",
      testerUserId: "900001",
      userDriverDir,
      assertLeaseHealthy: vi.fn(),
      whenLeaseUnhealthy: new Promise(() => {}),
      release,
    };
    let observedCapability: Record<string, unknown> | undefined;
    const runController = vi.fn(async ({ capabilityPath, params, sources }) => {
      observedCapability = JSON.parse(readFileSync(capabilityPath, "utf8")) as Record<
        string,
        unknown
      >;
      writeFileSync(params.output, "{}\n");
      expect(sources.controller).toBe("/trusted/controller.mjs");
      expect(sources.controllerRoot).toBe("/trusted/controller-root");
      return { code: 0, signal: null };
    });
    await runNightClawerTelegramProof(
      {
        controllerRoot: root,
        controllerSha: "a".repeat(40),
        openclawSha: "b".repeat(40),
        output,
      },
      {
        acquireCredential: async () => credential,
        runController,
        startProxy: async () => ({
          apiRoot: "http://127.0.0.1:39093",
          close,
          drainUpdates: vi.fn(async () => {}),
        }),
        verifySources: () => ({
          controller: "/trusted/controller.mjs",
          controllerRoot: "/trusted/controller-root",
          openclawBin: "/trusted/openclaw.mjs",
          userDriver: "/trusted/user-driver.py",
        }),
      },
    );
    expect(observedCapability).toEqual(buildScopedCapability(credential, "http://127.0.0.1:39093"));
    expect(observedCapability).not.toHaveProperty("OPENCLAW_QA_CONVEX_SECRET_CI");
    expect(release).toHaveBeenCalledOnce();
    expect(close).toHaveBeenCalledOnce();
  });

  it("does not forward broker or GitHub credentials to the controller", () => {
    expect(
      sanitizedChildEnvironment({
        HOME: "/tmp/home",
        PATH: "/usr/bin",
        GITHUB_TOKEN: "secret",
        OPENCLAW_QA_CONVEX_SECRET_CI: "secret",
      }),
    ).toEqual({ HOME: "/tmp/home", PATH: "/usr/bin" });
  });

  it("reports cleanup failure alongside a controller failure", async () => {
    const root = tempDirs.make("mantis-night-clawer-cleanup-");
    const releaseFailure = new Error("lease release failed");
    const controllerFailure = new Error("controller failed");
    const release = vi.fn(async () => {
      throw releaseFailure;
    });
    const close = vi.fn(async () => {});
    let thrown: unknown;
    try {
      await runNightClawerTelegramProof(
        {
          controllerRoot: root,
          controllerSha: "a".repeat(40),
          openclawSha: "b".repeat(40),
          output: `${root}/result.json`,
        },
        {
          acquireCredential: async () => ({
            groupId: "-1009001",
            stateRoot: `${root}/state`,
            sutBotId: "900002",
            sutToken: "900002:" + "A".repeat(32),
            sutUsername: "h3_test_bot",
            testerUserId: "900001",
            userDriverDir: `${root}/state/user-driver`,
            assertLeaseHealthy: vi.fn(),
            whenLeaseUnhealthy: new Promise(() => {}),
            release,
          }),
          runController: async () => {
            throw controllerFailure;
          },
          startProxy: async () => ({
            apiRoot: "http://127.0.0.1:39093",
            close,
            drainUpdates: vi.fn(async () => {}),
          }),
          verifySources: () => ({
            controller: "/trusted/controller.mjs",
            controllerRoot: "/trusted/controller-root",
            openclawBin: "/trusted/openclaw.mjs",
            userDriver: "/trusted/user-driver.py",
          }),
        },
      );
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(AggregateError);
    expect((thrown as AggregateError).errors).toEqual([controllerFailure, releaseFailure]);
    expect(close).toHaveBeenCalledOnce();
    expect(release).toHaveBeenCalledOnce();
  });
});
