package com.example.settvproxy.vpn;

import android.util.Log;

import com.example.settvproxy.ProxyVpnService;

import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetSocketAddress;
import java.net.SocketTimeoutException;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * SOCKS5 UDP ASSOCIATE 转发器（仅 SOCKS5 模式可用）。
 *
 * 每个「本地 UDP 端点」建立一条独立的关联：一条 UDP ASSOCIATE 控制连接 + 一个受 protect 的
 * DatagramSocket。SOCKS5 的 UDP 中继不携带多路复用标识，独立关联能保证回包准确对应到
 * 原始本地端口。控制连接关闭即代表中继失效。
 */
public final class UdpRelay {

    private static final String TAG = "UdpRelay";
    private static final long IDLE_TIMEOUT_MS = 60_000L;
    private static final int QUEUE_CAPACITY = 256;

    public interface Sink {
        void writePacket(byte[] packet);
    }

    private final ProxyVpnService service;
    private final Sink sink;
    private final ConcurrentHashMap<String, UdpSession> sessions = new ConcurrentHashMap<>();
    private volatile boolean running = true;

    public UdpRelay(ProxyVpnService service, Sink sink) {
        this.service = service;
        this.sink = sink;
    }

    /** TUN 读线程调用：把应用的 UDP 包交给中继；不阻塞读循环 */
    public void send(int srcIp, int srcPort, int dstIp, int dstPort,
                     byte[] payload, String domain) {
        if (!running || !service.isUdpAssociateSupported() || payload.length == 0) {
            return;
        }
        String key = srcIp + ":" + srcPort;
        UdpSession session = sessions.get(key);
        if (session == null) {
            UdpSession created = new UdpSession(this, key, srcIp, srcPort);
            UdpSession old = sessions.putIfAbsent(key, created);
            if (old == null) {
                created.start();
                session = created;
            } else {
                session = old;
            }
        }
        session.enqueue(dstIp, dstPort, domain, payload);
    }

    private void onRelayReply(int localIp, int localPort,
                              int remoteIp, int remotePort, byte[] data) {
        sink.writePacket(Packets.buildUdp(remoteIp, localIp, remotePort, localPort, data));
    }

    private void remove(String key, UdpSession session) {
        sessions.remove(key, session);
    }

    public void sweep() {
        long now = System.currentTimeMillis();
        for (UdpSession s : sessions.values()) {
            if (now - s.lastActivity() > IDLE_TIMEOUT_MS) {
                s.close();
            }
        }
    }

    public void shutdown() {
        running = false;
        for (UdpSession s : sessions.values()) {
            s.close();
        }
        sessions.clear();
    }

    private static final class UdpSession {

        private final UdpRelay owner;
        private final String key;
        private final int localIp;
        private final int localPort;
        private final AtomicBoolean closed = new AtomicBoolean(false);
        private final LinkedBlockingQueue<byte[]> outbound = new LinkedBlockingQueue<>(QUEUE_CAPACITY);

        private volatile DatagramSocket udpSocket;
        private volatile ProxyVpnService.UdpControl control;
        private volatile InetSocketAddress relay;
        private volatile int lastDstIp;
        private volatile int lastDstPort;
        private volatile long lastActivity = System.currentTimeMillis();

        UdpSession(UdpRelay owner, String key, int localIp, int localPort) {
            this.owner = owner;
            this.key = key;
            this.localIp = localIp;
            this.localPort = localPort;
        }

        long lastActivity() {
            return lastActivity;
        }

        void start() {
            Thread t = new Thread(this::run, "udp-relay-" + key);
            t.setDaemon(true);
            t.start();
        }

        /** 封装 SOCKS5 UDP 请求头并入队，握手完成前的数据不会丢失 */
        void enqueue(int dstIp, int dstPort, String domain, byte[] payload) {
            if (closed.get()) {
                return;
            }
            lastDstIp = dstIp;
            lastDstPort = dstPort;
            byte[] packet = (domain != null)
                    ? Packets.buildSocksUdpRequest(domain, dstPort, payload)
                    : Packets.buildSocksUdpRequest(dstIp, dstPort, payload);
            if (!outbound.offer(packet)) {
                close();
            }
        }

        private void run() {
            try {
                DatagramSocket ds = new DatagramSocket();
                if (!owner.service.protect(ds)) {
                    Log.w(TAG, "protect udp socket failed");
                }
                ds.setSoTimeout(100);
                udpSocket = ds;

                ProxyVpnService.UdpControl c =
                        owner.service.openSocks5UdpAssociate(ds.getLocalPort());
                control = c;
                relay = c.relayAddress;

                // 控制连接必须保持；服务端关闭它即代表中继失效
                Thread keepAlive = new Thread(() -> {
                    try {
                        InputStream in = c.controlSocket.getInputStream();
                        while (in.read() != -1) {
                            // 控制连接上不应有数据，只负责检测关闭
                        }
                    } catch (IOException ignore) {
                        // 连接关闭
                    } finally {
                        close();
                    }
                }, "udp-keep-" + key);
                keepAlive.setDaemon(true);
                keepAlive.start();

                byte[] rbuf = new byte[65535];
                while (!closed.get()) {
                    byte[] out;
                    InetSocketAddress r = relay;
                    while (r != null && (out = outbound.poll()) != null) {
                        ds.send(new DatagramPacket(out, out.length,
                                r.getAddress(), r.getPort()));
                        lastActivity = System.currentTimeMillis();
                    }
                    DatagramPacket received = new DatagramPacket(rbuf, rbuf.length);
                    try {
                        ds.receive(received);
                        handleReply(received.getData(), received.getLength());
                        lastActivity = System.currentTimeMillis();
                    } catch (SocketTimeoutException ignore) {
                        // 让出时间给待发送队列
                    }
                }
            } catch (Exception e) {
                Log.w(TAG, "udp association ended: " + e);
            } finally {
                close();
            }
        }

        /** 解封 SOCKS5 UDP 响应头：RSV(2) FRAG(1) ATYP(1) ADDR PORT(2) DATA */
        private void handleReply(byte[] data, int length) {
            Packets.SocksUdpReply reply = Packets.parseSocksUdpReply(data, length);
            if (reply == null || reply.payload.length == 0) {
                return;
            }
            // 代理回域名形式时无法还原成 IP，用本会话最近一次的目标地址构造回包
            int srcIp = (reply.remoteIp != 0) ? reply.remoteIp : lastDstIp;
            int srcPort = (reply.remotePort != 0) ? reply.remotePort : lastDstPort;
            owner.onRelayReply(localIp, localPort, srcIp, srcPort, reply.payload);
        }

        void close() {
            if (!closed.compareAndSet(false, true)) {
                return;
            }
            outbound.clear();
            ProxyVpnService.UdpControl c = control;
            if (c != null) {
                try {
                    c.controlSocket.close();
                } catch (IOException ignore) {
                    // 已关闭
                }
            }
            DatagramSocket ds = udpSocket;
            if (ds != null) {
                ds.close();
            }
            owner.remove(key, this);
        }
    }
}
