import socket
import socketserver
import threading
import time
import collections

BIND_HOST           = "10.0.0.2"
PROXY_PORT          = 5502   # external-facing port (attackers connect here)
INTERNAL_PORT       = 5020   # internal Modbus server port

MAX_CONN_PER_SECOND = 2      # max new connections allowed per IP per second
STATS_INTERVAL_SEC  = 10

_lock    = threading.Lock()
_windows = collections.defaultdict(collections.deque)
_allowed = 0
_dropped = 0


def _rate_check(ip: str) -> bool:
    now    = time.time()
    window = _windows[ip]

    while window and now - window[0] > 1.0:
        window.popleft()

    if len(window) >= MAX_CONN_PER_SECOND:
        return False

    window.append(now)
    return True


BUFFER = 4096


def _pipe(src: socket.socket, dst: socket.socket):
    try:
        while True:
            data = src.recv(BUFFER)
            if not data:
                break
            dst.sendall(data)
    except Exception:
        pass
    finally:
        for s in (src, dst):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except Exception:
                pass


class _ProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        global _allowed, _dropped
        ip = self.client_address[0]

        with _lock:
            if not _rate_check(ip):
                _dropped += 1
                print(
                    f"[{time.strftime('%H:%M:%S')}] RATE-LIMITED  {ip}  "
                    f"(>{MAX_CONN_PER_SECOND} conn/s) -- connection dropped"
                )
                return
            _allowed += 1

        upstream = None
        try:
            upstream = socket.create_connection((BIND_HOST, INTERNAL_PORT), timeout=20)
            client_sock = self.request
            t1 = threading.Thread(target=_pipe, args=(client_sock, upstream), daemon=True)
            t2 = threading.Thread(target=_pipe, args=(upstream, client_sock), daemon=True)
            t1.start()
            t2.start()
            t1.join()
            t2.join()
        except Exception as e:
            print(f"[{time.strftime('%H:%M:%S')}] UPSTREAM ERROR for {ip}: {e}")
        finally:
            if upstream:
                try:
                    upstream.close()
                except Exception:
                    pass


class _ThreadedServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads      = True


def _stats_loop():
    while True:
        time.sleep(STATS_INTERVAL_SEC)
        with _lock:
            allowed  = _allowed
            dropped  = _dropped
            total    = allowed + dropped
            top_ips  = sorted(
                ((ip, len(dq)) for ip, dq in _windows.items() if dq),
                key=lambda x: x[1],
                reverse=True,
            )[:5]

        rate = (dropped / total * 100) if total else 0.0
        print(
            f"\n{'─'*45}\n"
            f"  STATS @ {time.strftime('%H:%M:%S')}\n"
            f"  Allowed : {allowed}\n"
            f"  Dropped : {dropped}  ({rate:.1f}% drop rate)\n"
            f"  Total   : {total}\n"
            f"  Top IPs (conn/s window):"
        )
        for ip, count in top_ips:
            print(f"    {ip:16s}  {count} in last 1s")
        print(f"{'─'*45}\n")


def _start_modbus():
    from pymodbus.server import StartTcpServer
    from pymodbus.datastore import (
        ModbusSlaveContext,
        ModbusServerContext,
        ModbusSequentialDataBlock,
    )
    store   = ModbusSlaveContext(hr=ModbusSequentialDataBlock(30000, [300, 185] + [0] * 13))
    context = ModbusServerContext(slaves=store, single=True)
    print(f"[INFO] Internal Modbus server on {BIND_HOST}:{INTERNAL_PORT}")
    StartTcpServer(context=context, address=(BIND_HOST, INTERNAL_PORT))


if __name__ == "__main__":
    modbus_thread = threading.Thread(target=_start_modbus, daemon=True)
    modbus_thread.start()
    time.sleep(1.5)

    stats_thread = threading.Thread(target=_stats_loop, daemon=True)
    stats_thread.start()

    print(
        f"[INFO] Rate-limiting proxy on {BIND_HOST}:{PROXY_PORT}  "
        f"(limit: {MAX_CONN_PER_SECOND} conn/s per IP)"
    )
    with _ThreadedServer((BIND_HOST, PROXY_PORT), _ProxyHandler) as server:
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            print("\n[INFO] Server stopped.")
