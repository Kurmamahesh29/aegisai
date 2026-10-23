import { execFile, ChildProcess } from "node:child_process";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import * as path from "node:path";
import { describeExitCode, parseScanResult, ScanResult, ScanResultError } from "./model";

const MAX_STDERR_BYTES = 1024 * 1024;

export interface ScanInvocation {
  /** Python interpreter; when set the scanner runs as `<python> -m aegisai.cli`. */
  pythonPath?: string;
  executablePath: string;
  args: string[];
  cwd: string;
  onLog?: (line: string) => void;
}

export interface ScanRun {
  result: ScanResult;
  exitCode: number;
  jsonPath: string;
  sarifPath: string;
  stderr: string;
}

export interface CancellationLike {
  isCancellationRequested: boolean;
  onCancellationRequested(listener: () => void): { dispose(): void };
}

export class ScannerError extends Error {
  constructor(
    message: string,
    public readonly stderr: string = "",
  ) {
    super(message);
  }
}

/**
 * Validate the configured executable. Bare names are resolved through PATH by execFile;
 * anything with a path separator must be an absolute path to an existing regular file so the
 * extension never runs an unintended binary relative to the workspace.
 */
export async function resolveExecutable(configured: string): Promise<string> {
  const value = configured.trim();
  if (!value) {
    throw new ScannerError("aegisai.executablePath is empty");
  }
  const hasSeparator = value.includes("/") || value.includes("\\");
  if (!hasSeparator) {
    return value;
  }
  if (!path.isAbsolute(value)) {
    throw new ScannerError(`aegisai.executablePath must be absolute when it contains a path: ${value}`);
  }
  try {
    const stat = await fs.stat(value);
    if (!stat.isFile()) {
      throw new ScannerError(`aegisai.executablePath is not a file: ${value}`);
    }
  } catch (error) {
    if (error instanceof ScannerError) {
      throw error;
    }
    throw new ScannerError(`aegisai.executablePath does not exist: ${value}`);
  }
  return value;
}

export async function createReportDir(): Promise<string> {
  return fs.mkdtemp(path.join(os.tmpdir(), "aegisai-"));
}

/** Spawn the scanner with an argument array (no shell), bounded stderr and cancellation. */
export async function runScanner(invocation: ScanInvocation, token: CancellationLike, jsonPath: string, sarifPath: string): Promise<ScanRun> {
  let command: string;
  let args: string[];
  if (invocation.pythonPath && invocation.pythonPath.trim()) {
    command = await resolveExecutable(invocation.pythonPath);
    args = ["-m", "aegisai.cli", ...invocation.args];
  } else {
    command = await resolveExecutable(invocation.executablePath);
    args = invocation.args;
  }
  invocation.onLog?.(`$ ${command} ${args.join(" ")}`);

  const { exitCode, stderr } = await new Promise<{ exitCode: number | null; stderr: string }>((resolve, reject) => {
    let child: ChildProcess;
    let stderrBuffer = "";
    let truncated = false;
    try {
      child = execFile(command, args, {
        cwd: invocation.cwd,
        windowsHide: true,
        maxBuffer: 64 * 1024 * 1024,
        env: { ...process.env, PYTHONIOENCODING: "utf-8", NO_COLOR: "1" },
      });
    } catch (error) {
      reject(new ScannerError(`cannot start scanner: ${(error as Error).message}`));
      return;
    }
    child.stdout?.on("data", (chunk: Buffer | string) => {
      invocation.onLog?.(chunk.toString());
    });
    child.stderr?.on("data", (chunk: Buffer | string) => {
      const text = chunk.toString();
      invocation.onLog?.(text);
      if (stderrBuffer.length < MAX_STDERR_BYTES) {
        stderrBuffer += text.slice(0, MAX_STDERR_BYTES - stderrBuffer.length);
      } else {
        truncated = true;
      }
    });
    const subscription = token.onCancellationRequested(() => {
      invocation.onLog?.("cancellation requested; terminating scanner");
      child.kill();
    });
    child.on("error", (error) => {
      subscription.dispose();
      const err = error as NodeJS.ErrnoException;
      if (err.code === "ENOENT") {
        reject(new ScannerError(`scanner executable not found: ${command}. Install with "pip install aegisai" or set aegisai.executablePath.`, stderrBuffer));
      } else {
        reject(new ScannerError(`cannot start scanner: ${err.message}`, stderrBuffer));
      }
    });
    child.on("close", (code, signal) => {
      subscription.dispose();
      if (token.isCancellationRequested) {
        reject(new ScannerError("scan cancelled", stderrBuffer));
        return;
      }
      if (code === null) {
        reject(new ScannerError(`scanner terminated by signal ${String(signal)}`, stderrBuffer));
        return;
      }
      resolve({ exitCode: code, stderr: stderrBuffer + (truncated ? "\n[stderr truncated]" : "") });
    });
  });

  const problem = describeExitCode(exitCode);
  if (problem !== null) {
    throw new ScannerError(`${problem}\n${stderr.trim()}`.trim(), stderr);
  }
  let text: string;
  try {
    text = await fs.readFile(jsonPath, "utf-8");
  } catch {
    throw new ScannerError(`scanner exited with ${String(exitCode)} but produced no JSON report\n${stderr.trim()}`, stderr);
  }
  try {
    const result = parseScanResult(text);
    return { result, exitCode: exitCode as number, jsonPath, sarifPath, stderr };
  } catch (error) {
    if (error instanceof ScanResultError) {
      throw new ScannerError(`invalid scanner report: ${error.message}`, stderr);
    }
    throw error;
  }
}
