"use strict";

const fs = require("fs");
const http = require("http");

const KEY_FILE = "/var/lib/unknown-home/access/webos_rsa";
const PID_FILE = "/tmp/unknown-home-keyserver.pid";
const PORT = 9991;

function cleanup() {
  try {
    if (fs.readFileSync(PID_FILE, "utf8").trim() === String(process.pid)) {
      fs.unlinkSync(PID_FILE);
    }
  } catch (error) {
    // The pid file may already be gone.
  }
}

function send(response, status, contentType, body) {
  response.writeHead(status, {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  });
  response.end(body);
}

process.on("SIGINT", () => {
  cleanup();
  process.exit(0);
});
process.on("SIGTERM", () => {
  cleanup();
  process.exit(0);
});

fs.writeFileSync(PID_FILE, String(process.pid) + "\n", { mode: 0o644 });

const server = http.createServer((request, response) => {
  const requestPath = String(request.url || "/").split("?")[0];
  if (request.method !== "GET") {
    send(response, 405, "text/plain", "method not allowed\n");
    return;
  }
  if (requestPath === "/" || requestPath === "/status") {
    send(response, 200, "text/plain", "Unknown Home key server\n");
    return;
  }
  if (requestPath !== "/webos_rsa") {
    send(response, 404, "text/plain", "not found\n");
    return;
  }
  fs.readFile(KEY_FILE, (error, data) => {
    if (error) {
      send(response, 404, "text/plain", "webos_rsa not available\n");
      return;
    }
    response.writeHead(200, {
      "Content-Type": "application/octet-stream",
      "Content-Disposition": 'attachment; filename="webos_rsa"',
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff"
    });
    response.end(data);
  });
});

server.listen(PORT, "0.0.0.0");
server.on("error", (error) => {
  process.stderr.write(String(error && error.stack ? error.stack : error) + "\n");
  cleanup();
  process.exit(1);
});
