import type { Server } from "http";
import type { WebSocketServer } from "ws";

export function attachRelayUpgradeHandlers(
  server: Server,
  hostWsServer: WebSocketServer,
  mobileWsServer: WebSocketServer,
): void {
  server.on("upgrade", (req, socket, head) => {
    const requestUrl = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
    if (requestUrl.pathname === "/relay/ws" || /^\/relay\/[^/]+$/.test(requestUrl.pathname)) {
      hostWsServer.handleUpgrade(req, socket, head, (ws) => hostWsServer.emit("connection", ws, req));
      return;
    }
    if (requestUrl.pathname === "/mobile/ws") {
      mobileWsServer.handleUpgrade(req, socket, head, (ws) => mobileWsServer.emit("connection", ws, req));
      return;
    }
    socket.destroy();
  });
}
