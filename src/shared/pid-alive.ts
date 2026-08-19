// PID liveness helpers check whether process ids still refer to active processes.
import childProcess from "node:child_process";
import fsSync from "node:fs";

const DARWIN_PS_TIMEOUT_MS = 1000;
const WINDOWS_WMIC_TIMEOUT_MS = 1500;

function isValidPid(pid: number): boolean {
  return Number.isInteger(pid) && pid > 0;
}

/**
 * Check if a process is a zombie on Linux by reading /proc/<pid>/status.
 * Returns false on non-Linux platforms or if the proc file can't be read.
 */
function isZombieProcess(pid: number): boolean {
  if (process.platform !== "linux") {
    return false;
  }
  try {
    const status = fsSync.readFileSync(`/proc/${pid}/status`, "utf8");
    const stateMatch = status.match(/^State:\s+(\S)/m);
    return stateMatch?.[1] === "Z";
  } catch {
    return false;
  }
}

/** Returns true only when a positive PID exists and is not a Linux zombie process. */
export function isPidAlive(pid: number): boolean {
  if (!isValidPid(pid)) {
    return false;
  }
  try {
    process.kill(pid, 0);
  } catch (err) {
    // EPERM means the PID exists but we cannot signal it. Treat that as a
    // successful existence probe, then still apply the Linux zombie check.
    // Keep parity with isPidDefinitelyDead (EPERM is not "definitely dead").
    if ((err as NodeJS.ErrnoException).code !== "EPERM") {
      return false;
    }
  }
  if (isZombieProcess(pid)) {
    return false;
  }
  return true;
}

/** Returns true only when the PID is invalid, missing, or known to be a Linux zombie. */
export function isPidDefinitelyDead(pid: number): boolean {
  if (!isValidPid(pid)) {
    return true;
  }
  try {
    process.kill(pid, 0);
  } catch (err) {
    return (err as NodeJS.ErrnoException).code === "ESRCH";
  }
  return isZombieProcess(pid);
}

function getDarwinProcessStartTime(pid: number): number | null {
  try {
    const startedAt = childProcess
      .execFileSync("/bin/ps", ["-o", "lstart=", "-p", String(pid)], {
        encoding: "utf8",
        env: { ...process.env, LC_ALL: "C", TZ: "UTC" },
        stdio: ["ignore", "pipe", "ignore"],
        timeout: DARWIN_PS_TIMEOUT_MS,
      })
      .trim();
    // Darwin's lstart output has no timezone. Force UTC for both ps and parsing so
    // a system timezone change cannot make a live lock owner look like PID reuse.
    const startedAtMs = Date.parse(`${startedAt} UTC`);
    return Number.isFinite(startedAtMs) ? Math.floor(startedAtMs / 1000) : null;
  } catch {
    return null;
  }
}

/** Read the Linux procfs start identity used by Linux-owned runtime state. */
export function getProcessStartTime(pid: number): number | null {
  if (!isValidPid(pid)) {
    return null;
  }
  if (process.platform !== "linux") {
    return null;
  }
  try {
    const stat = fsSync.readFileSync(`/proc/${pid}/stat`, "utf8");
    const commEndIndex = stat.lastIndexOf(")");
    if (commEndIndex < 0) {
      return null;
    }
    // The comm field (field 2) is wrapped in parens and can contain spaces,
    // so split after the last ")" to get fields 3..N reliably.
    const afterComm = stat.slice(commEndIndex + 1).trimStart();
    const fields = afterComm.split(/\s+/);
    // field 22 (starttime) = index 19 after the comm-split (field 3 is index 0).
    const starttime = Number(fields[19]);
    return Number.isInteger(starttime) && starttime >= 0 ? starttime : null;
  } catch {
    return null;
  }
}

/**
 * Read the Windows process creation time (WMIC CreationDate, e.g.
 * "20260819115506.123456-420") used to catch PID recycling on win32, where
 * neither the Linux procfs nor the Darwin `ps lstart` path applies.
 */
function getWindowsProcessStartTime(pid: number): number | null {
  try {
    const output = childProcess
      .execFileSync(
        "wmic",
        ["process", "where", `ProcessId=${pid}`, "get", "CreationDate", "/value"],
        {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
          timeout: WINDOWS_WMIC_TIMEOUT_MS,
          windowsHide: true,
        },
      )
      .trim();
    const match = output.match(/CreationDate=(\d{14})/);
    if (!match) {
      return null;
    }
    const raw = match[1];
    const isoLike = `${raw.slice(0, 4)}-${raw.slice(4, 6)}-${raw.slice(6, 8)}T${raw.slice(8, 10)}:${raw.slice(10, 12)}:${raw.slice(12, 14)}Z`;
    const startedAtMs = Date.parse(isoLike);
    return Number.isFinite(startedAtMs) ? Math.floor(startedAtMs / 1000) : null;
  } catch {
    return null;
  }
}

/** Read a cross-platform process identity for filesystem lock ownership. */
export function getFileLockProcessStartTime(pid: number): number | null {
  if (!isValidPid(pid)) {
    return null;
  }
  if (process.platform === "darwin") {
    return getDarwinProcessStartTime(pid);
  }
  if (process.platform === "win32") {
    return getWindowsProcessStartTime(pid);
  }
  return getProcessStartTime(pid);
}
