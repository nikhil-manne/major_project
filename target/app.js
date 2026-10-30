const http = require("http");

const server = http.createServer((req, res) => {
  // Harmless test endpoints; no exploit or sensitive data is included.
  if (req.url === "/") {
    res.writeHead(200, { "content-type": "text/plain" });
    return res.end("Cyber Range test target is running.\n");
  }
  if (req.url === "/health") {
    res.writeHead(200, { "content-type": "application/json" });
    return res.end(JSON.stringify({ status: "ok", target: "cyber-range-test" }));
  }
  res.writeHead(404, { "content-type": "text/plain" });
  res.end("Not found\n");
});

server.listen(3000, "0.0.0.0", () => {
  console.log("Cyber Range test target listening on port 3000");
});
