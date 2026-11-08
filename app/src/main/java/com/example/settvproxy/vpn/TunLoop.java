package com.example.settvproxy.vpn;

import android.os.ParcelFileDescriptor;
import android.util.Log;

import com.example.settvproxy.ProxyVpnService;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.util.Arrays;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

/**
 * TUN 读写主循环。
 *
 * - TCP：按四元组维护 {@link TcpConnection}，经代理隧道转发；fake-IP 模式下会把
 *   虚拟 IP 还原成域名，交给代理端远程解析；
 * - UDP 53：域名透传开启时由 {@link FakeDns} 本地伪造应答（A 记录指向虚拟 IP，
 *   AAAA 返回 NODATA），否则回退到直连上游 DNS；
 * - 其它 UDP：丢弃（强制 QUIC 回退 TCP）或经 {@link UdpRelay} 中继；
 * - 非 IPv4 包（IPv6）：丢弃，避免绕过 VPN 直连泄漏。
 */
public final class TunLoop implements TcpConnection.Sink, UdpRelay.Sink {

    private static final String TAG = "TunLoop";
    private static final int BUFFER_SIZE = 32767;
    private static final long IDLE_TIMEOUT_MS = 120_000L;

    private final ParcelFileDescriptor pfd;
    private final FileInputStream in;
    private final FileOutputStream out;
    private final ProxyVpnService service;
    private final int upstreamDnsIp;
    private final boolean domainPassthrough;
    private final FakeDns fakeDns = new FakeDns();
    private final UdpRelay udpRelay;
    private final ConcurrentHashMap<String, TcpConnection> sessions = new ConcurrentHashMap<>();
    private final ExecutorService dnsPool = Executors.newFixedThreadPool(4);
    private final ScheduledExecutorService sweeper = Executors.newSingleThreadScheduledExecutor();
    private volatile boolean running = true;

    public TunLoop(ParcelFileDescriptor pfd, ProxyVpnService service, int upstreamDnsIp,
                   boolean udpRelayEnabled, boolean domainPassthrough) {
        this.pfd = pfd;
        this.in = new FileInputStream(pfd.getFileDescriptor());
        this.out = new FileOutputStream(pfd.getFileDescriptor());
        this.service = service;
        this.upstreamDnsIp = upstreamDnsIp;
        this.domainPassthrough = domainPassthrough;
        this.udpRelay = udpRelayEnabled ? new UdpRelay(service, this) : null;
    }

    public void start() {
        Thread reader = new Thread(this::readLoop, "tun-reader");
        reader.setDaemon(true);
        reader.start();
        sweeper.scheduleAtFixedRate(this::sweep, 10, 10, TimeUnit.SECONDS);
    }

    private void readLoop() {
        byte[] buf = new byte[BUFFER_SIZE];
        try {
            while (running) {
                int n = in.read(buf);
                if (n <= 0) {
                    continue;
                }
                try {
                    handle(buf, n);
                } catch (Exception e) {
                    Log.w(TAG, "drop malformed packet", e);
                }
            }
        } catch (IOException e) {
            if (running) {
                Log.e(TAG, "tun read failed", e);
            }
        }
    }

    private void handle(byte[] buf, int length) {
        Packets.Ip ip = Packets.parseIpPacket(buf, length);
        if (ip == null) {
            return;
        }
        if (ip.protocol == Packets.PROTO_TCP) {
            Packets.TcpHeader tcp = Packets.tcp(buf, ip);
            if (tcp != null) {
                handleTcp(ip, tcp);
            }
        } else if (ip.protocol == Packets.PROTO_UDP) {
            Packets.UdpHeader udp = Packets.udp(buf, ip);
            if (udp == null) {
                return;
            }
            if (udp.dstPort == 53) {
                if (domainPassthrough) {
                    byte[] response = fakeDns.buildResponse(udp.payload, udp.payload.length);
                    if (response != null) {
                        Log.d(TAG, "fake dns answer " + response.length + "B");
                        writePacket(Packets.buildUdp(ip.dst, ip.src, 53,
                                udp.srcPort, response));
                        return;
                    }
                }
                // 域名透传关闭，或报文无法解析：直连上游 DNS
                forwardDns(ip, udp);
            } else if (udpRelay != null) {
                if (udpRelay.isDisabled()) {
                    // 代理无 UDP 中继端口，等同丢弃，让客户端快速回退 TCP
                    return;
                }
                if (service.isProxyEndpoint(ip.dst, udp.dstPort)) {
                    // 发往代理端口的 UDP 不再封装转发，避免代理把包又发给自己
                    return;
                }
                String domain = domainPassthrough ? fakeDns.lookup(ip.dst) : null;
                if (domainPassthrough && fakeDns.isFakeIp(ip.dst) && domain == null) {
                    // fake-IP 映射已丢失：丢弃，让应用重新发起 DNS 查询
                    return;
                }
                udpRelay.send(ip.src, udp.srcPort, ip.dst, udp.dstPort,
                        udp.payload, domain);
            }
            // 无中继时其余 UDP 一律丢弃：QUIC 连不上后会回退到 TCP
        }
    }

    private static String key(Packets.Ip ip, Packets.TcpHeader tcp) {
        return ip.src + ":" + tcp.srcPort + ">" + ip.dst + ":" + tcp.dstPort;
    }

    private void handleTcp(Packets.Ip ip, Packets.TcpHeader tcp) {
        String k = key(ip, tcp);
        boolean syn = (tcp.flags & Packets.SYN) != 0 && (tcp.flags & Packets.ACK) == 0;
        if (syn) {
            String domain = domainPassthrough ? fakeDns.lookup(ip.dst) : null;
            if (domainPassthrough && fakeDns.isFakeIp(ip.dst) && domain == null) {
                // fake-IP 映射已丢失（服务重启或地址池回收）：回 RST 促使应用重新解析
                writePacket(Packets.buildTcp(ip.dst, ip.src, tcp.dstPort, tcp.srcPort,
                        tcp.ack, Packets.advance(tcp.seq, 1),
                        Packets.RST | Packets.ACK, null));
                return;
            }
            TcpConnection conn = new TcpConnection(k, this, ip.src, tcp.srcPort,
                    ip.dst, tcp.dstPort, tcp.seq, domain);
            TcpConnection old = sessions.putIfAbsent(k, conn);
            if (old != null) {
                old.close();
                sessions.put(k, conn);
            }
            conn.start();
            return;
        }

        TcpConnection conn = sessions.get(k);
        if (conn == null) {
            writePacket(Packets.buildTcp(ip.dst, ip.src, tcp.dstPort, tcp.srcPort,
                    tcp.ack, Packets.advance(tcp.seq, tcp.payload.length + 1),
                    Packets.RST | Packets.ACK, null));
            return;
        }
        conn.onPacket(tcp);
    }

    private void forwardDns(Packets.Ip ip, Packets.UdpHeader udp) {
        final byte[] query = udp.payload;
        final int srcIp = ip.src;
        final int dstIp = ip.dst;
        final int srcPort = udp.srcPort;
        dnsPool.execute(() -> {
            DatagramSocket sock = null;
            try {
                sock = new DatagramSocket();
                boolean bound = false;
                android.net.Network network = service.getPhysicalNetwork();
                if (network != null) {
                    try {
                        network.bindSocket(sock);
                        bound = true;
                    } catch (IOException e) {
                        Log.w(TAG, "bind dns socket to physical network failed", e);
                    }
                }
                if (!bound && !service.protect(sock)) {
                    Log.w(TAG, "protect dns socket failed");
                }
                sock.setSoTimeout(5000);
                InetAddress dns = InetAddress.getByAddress(Packets.ipToBytes(upstreamDnsIp));
                sock.send(new DatagramPacket(query, query.length, dns, 53));

                byte[] rb = new byte[2048];
                DatagramPacket response = new DatagramPacket(rb, rb.length);
                sock.receive(response);
                byte[] answer = Arrays.copyOf(rb, response.getLength());
                writePacket(Packets.buildUdp(dstIp, srcIp, 53, srcPort, answer));
            } catch (Exception e) {
                Log.w(TAG, "dns forward failed", e);
            } finally {
                if (sock != null) {
                    sock.close();
                }
            }
        });
    }

    @Override
    public void writePacket(byte[] packet) {
        if (!running) {
            return;
        }
        synchronized (out) {
            try {
                out.write(packet);
                out.flush();
            } catch (IOException e) {
                Log.w(TAG, "tun write failed", e);
            }
        }
    }

    @Override
    public void onClosed(TcpConnection connection) {
        sessions.remove(connection.key(), connection);
    }

    @Override
    public Socket openTunnel(int targetIp, int targetPort, String domain) throws IOException {
        return service.openTunnel(targetIp, targetPort, domain);
    }

    private void sweep() {
        long now = System.currentTimeMillis();
        for (TcpConnection c : sessions.values()) {
            if (now - c.lastActivity() > IDLE_TIMEOUT_MS) {
                c.close();
            }
        }
        if (udpRelay != null) {
            udpRelay.sweep();
        }
    }

    public void shutdown() {
        running = false;
        if (udpRelay != null) {
            udpRelay.shutdown();
        }
        for (TcpConnection c : sessions.values()) {
            c.close();
        }
        sessions.clear();
        sweeper.shutdownNow();
        dnsPool.shutdownNow();
        try {
            pfd.close();
        } catch (IOException e) {
            Log.w(TAG, "close tun failed", e);
        }
    }
}
