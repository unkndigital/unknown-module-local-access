"use strict";

const fs = require("fs");
const os = require("os");
const path = require("path");
const crypto = require("crypto");
const childProcess = require("child_process");

const BASE = "/var/lib/unknown-home";
const ACCESS_DIR = path.join(BASE, "access");
const BIN_DIR = path.join(BASE, "bin");
const KEY_FILE = path.join(ACCESS_DIR, "webos_rsa");
const PUBLIC_KEY_FILE = KEY_FILE + ".pub";
const PASSPHRASE_FILE = path.join(ACCESS_DIR, "passphrase");
const SSH_ENABLED_FILE = path.join(ACCESS_DIR, "ssh-enabled");
const KEY_SERVER_ENABLED_FILE = path.join(ACCESS_DIR, "keyserver-enabled");
const SSH_PID_FILE = "/tmp/unknown-home-dropbear.pid";
const KEY_SERVER_PID_FILE = "/tmp/unknown-home-keyserver.pid";
const SSH_PORT = 9922;
const KEY_SERVER_PORT = 9991;
const AUTHORIZED_KEYS = "/home/root/.ssh/authorized_keys";
const KEY_SERVER_SCRIPT = path.join(__dirname, "unknown-home-keyserver.js");
const DROPBEAR_CACHE = path.join(BIN_DIR, "dropbear");
const SFTP_CACHE = path.join(BIN_DIR, "sftp-server");
const DROPBEAR_SOURCES = [
  DROPBEAR_CACHE,
  "/var/lib/owner-recovery/bin/dropbear",
  "/media/developer/apps/usr/palm/services/org.webosbrew.hbchannel.service/bin/dropbear"
];
const SFTP_SOURCES = [
  SFTP_CACHE,
  "/media/developer/apps/usr/palm/services/org.webosbrew.hbchannel.service/bin/sftp-server"
];

function fail(message) {
  process.stderr.write(String(message) + "\n");
  process.exitCode = 1;
}

function ensureRoot() {
  if (typeof process.getuid !== "function" || process.getuid() !== 0) {
    throw new Error("root privileges are required");
  }
}

function mkdir(directory, mode) {
  fs.mkdirSync(directory, { recursive: true, mode: mode });
  fs.chmodSync(directory, mode);
}

function firstExecutable(candidates) {
  for (const candidate of candidates) {
    try {
      fs.accessSync(candidate, fs.constants.X_OK);
      return candidate;
    } catch (error) {
      // Try the next fixed path.
    }
  }
  return "";
}

function firstFile(candidates) {
  for (const candidate of candidates) {
    try {
      if (fs.statSync(candidate).isFile()) {
        return candidate;
      }
    } catch (error) {
      // Try the next fixed path.
    }
  }
  return "";
}

function adoptBinary(sources, destination) {
  if (fs.existsSync(destination)) {
    fs.chmodSync(destination, 0o755);
    return destination;
  }
  const source = firstFile(sources);
  if (!source) {
    return "";
  }
  mkdir(path.dirname(destination), 0o755);
  fs.copyFileSync(source, destination);
  fs.chownSync(destination, 0, 0);
  fs.chmodSync(destination, 0o755);
  return destination;
}

function base64UrlBuffer(value) {
  let encoded = String(value).replace(/-/g, "+").replace(/_/g, "/");
  while (encoded.length % 4) {
    encoded += "=";
  }
  return Buffer.from(encoded, "base64");
}

function sshField(buffer) {
  const length = Buffer.alloc(4);
  length.writeUInt32BE(buffer.length, 0);
  return Buffer.concat([length, buffer]);
}

function sshMpint(buffer) {
  let value = buffer;
  while (value.length > 1 && value[0] === 0) {
    value = value.slice(1);
  }
  if (value[0] & 0x80) {
    value = Buffer.concat([Buffer.from([0]), value]);
  }
  return sshField(value);
}

function openSshPublicKey(publicKey) {
  const jwk = publicKey.export({ format: "jwk" });
  const type = Buffer.from("ssh-rsa", "ascii");
  const exponent = base64UrlBuffer(jwk.e);
  const modulus = base64UrlBuffer(jwk.n);
  const blob = Buffer.concat([
    sshField(type),
    sshMpint(exponent),
    sshMpint(modulus)
  ]);
  return "ssh-rsa " + blob.toString("base64") + " unknown-home";
}

function randomPassphrase() {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";
  const bytes = crypto.randomBytes(10);
  let result = "";
  for (let index = 0; index < bytes.length; index += 1) {
    result += alphabet[bytes[index] % alphabet.length];
  }
  return result;
}

function ensureKey() {
  ensureRoot();
  mkdir(BASE, 0o755);
  mkdir(ACCESS_DIR, 0o700);
  mkdir("/home/root/.ssh", 0o700);

  let passphrase = "";
  try {
    passphrase = fs.readFileSync(PASSPHRASE_FILE, "utf8").trim();
  } catch (error) {
    passphrase = "";
  }

  if (!fs.existsSync(KEY_FILE) || !fs.existsSync(PUBLIC_KEY_FILE) || !passphrase) {
    passphrase = randomPassphrase();
    const pair = crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const privatePem = pair.privateKey.export({
      type: "pkcs1",
      format: "pem",
      cipher: "aes-256-cbc",
      passphrase: passphrase
    });
    const publicLine = openSshPublicKey(pair.publicKey);
    fs.writeFileSync(KEY_FILE, privatePem, { mode: 0o600 });
    fs.writeFileSync(PUBLIC_KEY_FILE, publicLine + "\n", { mode: 0o644 });
    fs.writeFileSync(PASSPHRASE_FILE, passphrase + "\n", { mode: 0o600 });
  }

  const publicLine = fs.readFileSync(PUBLIC_KEY_FILE, "utf8").trim();
  let authorized = "";
  try {
    authorized = fs.readFileSync(AUTHORIZED_KEYS, "utf8");
  } catch (error) {
    authorized = "";
  }
  const lines = authorized.split(/\r?\n/).filter((line) => line && !/\sunknown-home\s*$/.test(line));
  lines.push(publicLine);
  fs.writeFileSync(AUTHORIZED_KEYS, lines.join("\n") + "\n", { mode: 0o600 });

  [KEY_FILE, PASSPHRASE_FILE, AUTHORIZED_KEYS].forEach((file) => {
    fs.chownSync(file, 0, 0);
    fs.chmodSync(file, 0o600);
  });
  fs.chownSync(PUBLIC_KEY_FILE, 0, 0);
  fs.chmodSync(PUBLIC_KEY_FILE, 0o644);
  return passphrase;
}

function readPid(pidFile) {
  try {
    const value = Number(fs.readFileSync(pidFile, "utf8").trim());
    return Number.isInteger(value) && value > 1 ? value : 0;
  } catch (error) {
    return 0;
  }
}

function pidAlive(pidFile) {
  const pid = readPid(pidFile);
  if (!pid) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch (error) {
    return false;
  }
}

function processCommand(pid) {
  try {
    return fs.readFileSync("/proc/" + pid + "/cmdline").toString("utf8").replace(/\0/g, " ");
  } catch (error) {
    return "";
  }
}

function netstat() {
  try {
    return childProcess.execFileSync("/bin/sh", ["-c", "netstat -ltn 2>/dev/null || true"], {
      encoding: "utf8",
      timeout: 5000
    });
  } catch (error) {
    return "";
  }
}

function portListening(port) {
  const expression = new RegExp("[:.]" + port + "\\s");
  return netstat().split(/\r?\n/).some((line) => expression.test(line));
}

function sleep(seconds) {
  childProcess.execFileSync("/bin/sleep", [String(seconds)], { timeout: (seconds + 2) * 1000 });
}

function startSsh() {
  ensureRoot();
  ensureKey();
  adoptBinary(SFTP_SOURCES, SFTP_CACHE);
  const dropbear = adoptBinary(DROPBEAR_SOURCES, DROPBEAR_CACHE) || firstExecutable(DROPBEAR_SOURCES);
  if (!dropbear) {
    throw new Error("Dropbear was not found. Install Homebrew Channel before enabling root SSH.");
  }
  if (pidAlive(SSH_PID_FILE) && portListening(SSH_PORT)) {
    fs.writeFileSync(SSH_ENABLED_FILE, "1\n", { mode: 0o600 });
    return;
  }
  if (portListening(SSH_PORT)) {
    throw new Error("Port " + SSH_PORT + " is already in use; no process was stopped.");
  }
  try {
    fs.unlinkSync(SSH_PID_FILE);
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }
  const result = childProcess.spawnSync(dropbear, [
    "-R",
    "-s",
    "-m",
    "-p",
    "0.0.0.0:" + SSH_PORT,
    "-P",
    SSH_PID_FILE
  ], {
    encoding: "utf8",
    timeout: 10000
  });
  if (result.error || result.status !== 0) {
    throw new Error((result.stderr || result.stdout || (result.error && result.error.message) || "Dropbear failed").trim());
  }
  sleep(1);
  if (!pidAlive(SSH_PID_FILE) || !portListening(SSH_PORT)) {
    throw new Error("Dropbear did not open port " + SSH_PORT);
  }
  fs.writeFileSync(SSH_ENABLED_FILE, "1\n", { mode: 0o600 });
}

function stopKnownPid(pidFile, requiredText) {
  const pid = readPid(pidFile);
  if (!pid) {
    try {
      fs.unlinkSync(pidFile);
    } catch (error) {
      // A missing stale pid file is already stopped.
    }
    return;
  }
  let alive = true;
  try {
    process.kill(pid, 0);
  } catch (error) {
    alive = false;
  }
  if (!alive) {
    try {
      fs.unlinkSync(pidFile);
    } catch (error) {
      // A missing stale pid file is already stopped.
    }
    return;
  }
  const command = processCommand(pid);
  if (command.indexOf(requiredText) < 0) {
    throw new Error("Refusing to stop unexpected process " + pid);
  }
  process.kill(pid, "SIGTERM");
  sleep(1);
  try {
    process.kill(pid, 0);
    throw new Error("Process " + pid + " did not stop");
  } catch (error) {
    if (error.message && error.message.indexOf("did not stop") >= 0) {
      throw error;
    }
  }
  try {
    fs.unlinkSync(pidFile);
  } catch (error) {
    // The child may have removed its own pid file.
  }
}

function stopSsh() {
  ensureRoot();
  stopKnownPid(SSH_PID_FILE, "dropbear");
  try {
    fs.unlinkSync(SSH_ENABLED_FILE);
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }
}

function startKeyServer() {
  ensureRoot();
  ensureKey();
  if (!fs.existsSync(KEY_SERVER_SCRIPT)) {
    throw new Error("Key server runtime is missing");
  }
  if (pidAlive(KEY_SERVER_PID_FILE) && portListening(KEY_SERVER_PORT)) {
    fs.writeFileSync(KEY_SERVER_ENABLED_FILE, "1\n", { mode: 0o600 });
    return;
  }
  if (portListening(KEY_SERVER_PORT)) {
    throw new Error("Port " + KEY_SERVER_PORT + " is already in use; no process was stopped.");
  }
  try {
    fs.unlinkSync(KEY_SERVER_PID_FILE);
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }
  const child = childProcess.spawn(process.execPath, [KEY_SERVER_SCRIPT], {
    detached: true,
    stdio: "ignore"
  });
  child.unref();
  sleep(1);
  if (!pidAlive(KEY_SERVER_PID_FILE) || !portListening(KEY_SERVER_PORT)) {
    throw new Error("Key server did not open port " + KEY_SERVER_PORT);
  }
  fs.writeFileSync(KEY_SERVER_ENABLED_FILE, "1\n", { mode: 0o600 });
}

function stopKeyServer() {
  ensureRoot();
  stopKnownPid(KEY_SERVER_PID_FILE, "unknown-home-keyserver.js");
  try {
    fs.unlinkSync(KEY_SERVER_ENABLED_FILE);
  } catch (error) {
    if (error.code !== "ENOENT") {
      throw error;
    }
  }
}

function networkAddress() {
  const interfaces = os.networkInterfaces();
  for (const name of Object.keys(interfaces)) {
    for (const entry of interfaces[name] || []) {
      if (entry.family === "IPv4" && !entry.internal) {
        return entry.address;
      }
    }
  }
  return "";
}

function status() {
  let passphrase = "";
  try {
    passphrase = fs.readFileSync(PASSPHRASE_FILE, "utf8").trim();
  } catch (error) {
    passphrase = "";
  }
  const ipAddress = networkAddress();
  const sshRunning = pidAlive(SSH_PID_FILE) && portListening(SSH_PORT);
  const keyServerRunning = pidAlive(KEY_SERVER_PID_FILE) && portListening(KEY_SERVER_PORT);
  return {
    available: !!firstExecutable(DROPBEAR_SOURCES),
    sshRunning: sshRunning,
    keyServerRunning: keyServerRunning,
    sshEnabled: fs.existsSync(SSH_ENABLED_FILE),
    keyServerEnabled: fs.existsSync(KEY_SERVER_ENABLED_FILE),
    sshPort: SSH_PORT,
    keyServerPort: KEY_SERVER_PORT,
    keyExists: fs.existsSync(KEY_FILE),
    passphrase: passphrase,
    ipAddress: ipAddress,
    keyUrl: keyServerRunning && ipAddress
      ? "http://" + ipAddress + ":" + KEY_SERVER_PORT + "/webos_rsa"
      : ""
  };
}

function startEnabled() {
  ensureRoot();
  const errors = [];
  if (fs.existsSync(SSH_ENABLED_FILE)) {
    try {
      startSsh();
    } catch (error) {
      errors.push(error.message);
    }
  }
  if (fs.existsSync(KEY_SERVER_ENABLED_FILE)) {
    try {
      startKeyServer();
    } catch (error) {
      errors.push(error.message);
    }
  }
  if (errors.length) {
    throw new Error(errors.join("; "));
  }
}

function main() {
  const command = process.argv[2] || "status";
  const value = process.argv[3] || "";
  if (command === "status") {
    process.stdout.write(JSON.stringify(status()) + "\n");
    return;
  }
  if (command === "ensure") {
    ensureKey();
    process.stdout.write(JSON.stringify(status()) + "\n");
    return;
  }
  if (command === "ssh") {
    if (value === "on") {
      startSsh();
    } else if (value === "off") {
      stopSsh();
    } else {
      throw new Error("ssh expects on or off");
    }
    process.stdout.write(JSON.stringify(status()) + "\n");
    return;
  }
  if (command === "keyserver") {
    if (value === "on") {
      startKeyServer();
    } else if (value === "off") {
      stopKeyServer();
    } else {
      throw new Error("keyserver expects on or off");
    }
    process.stdout.write(JSON.stringify(status()) + "\n");
    return;
  }
  if (command === "start-enabled") {
    startEnabled();
    process.stdout.write(JSON.stringify(status()) + "\n");
    return;
  }
  if (command === "stop-all") {
    stopKeyServer();
    stopSsh();
    process.stdout.write(JSON.stringify(status()) + "\n");
    return;
  }
  throw new Error("unknown command");
}

try {
  main();
} catch (error) {
  fail(error && error.stack ? error.stack : error);
}
