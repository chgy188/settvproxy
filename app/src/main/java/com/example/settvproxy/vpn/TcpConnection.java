package com.example.settvproxy.vpn;

import android.util.Log;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 单个 TCP 会话：把应用经 TUN 发出的 TCP 流，通过 SOCKS5 / HTTP CONNECT 隧道转发到代理服务器。
 *
 * 这里由本地代答三次握手与 ACK（相当于一个极简 TCP 端点），不实现重传与拥塞控制：
 * 丢包由远端 TCP 协议栈重传，收到重复包时只回 ACK 而不重复转发数据。
 * 每个会话有独立的读、写线程，避免慢代理阻塞整个 TUN 读循环。
 */
public final class TcpConnection {

    private static final String TAG = "TcpConnection";
    private static final int MAX_PENDING_BYTES = 256 * 1024;
    private static final int QUEUE_CAPACITY = 256;

    public interface Sink {
        void writePacket(byte[] packet);

        void onClosed(TcpConnection connection);

        /**
         * 返回一个已完成代理握手、可直接读写目标数据的 Socket。
         * domain 不为 null 时由代理端按域名远程解析（fake-IP 模式）。
         */
        Socket openTunnel(int targetIp, int targetPort, String domain) throws IOException;
    }

    private final String key;
    private final Sink sink;
    private final int localIp;
    private final int localPort;
    private final int remoteIp;
    private final int remotePort;
    private final String domain;
    private final long synSeq;

    private final AtomicBoolean closed = new AtomicBoolean(false);
    private final CountDownLatch tunnelLatch = new CountDownLatch(1);
    private final LinkedBlockingQueue<byte[]> outbound = new LinkedBlockingQueue<>(QUEUE_CAPACITY);
    private final List<byte[]> pending = new ArrayList<>();

    private long mySeq;
    private long theirSeq;
    private int pendingBytes;
    private volatile boolean established;
    private volatile boolean tunnelReady;
    private volatile boolean closing;
    private volatile boolean appFin;
    private volatile Socket socket;
    private volatile long lastActivity = System.currentTimeMillis();

    public TcpConnection(String key, Sink sink, int localIp, int localPort,
                         int remoteIp, int remotePort, long appSeq, String domain) {
        this.key = key;
        this.sink = sink;
        this.localIp = localIp;
        this.localPort = localPort;
        this.remoteIp = remoteIp;
        this.remotePort = remotePort;
        this.domain = domain;
        this.synSeq = Packets.newSeq();
        this.mySeq = synSeq;
        this.theirSeq = Packets.advance(appSeq, 1);
    }

    public String key() {
        return key;
    }

    public boolean isClosed() {
        return closed.get();
    }

    public long lastActivity() {
        return lastActivity;
    }

    /** 收到 SYN 后调用：本地代答 SYN|ACK，同时异步建立代理隧道 */
    public void start() {
        synchronized (this) {
            reply(Packets.SYN | Packets.ACK, null);
        }
        Thread writer = new Thread(this::runWriter, "vpn-wr-" + key);
        writer.setDaemon(true);
        writer.start();
        Thread reader = new Thread(this::runReader, "vpn-rd-" + key);
        reader.setDaemon(true);
        reader.start();
    }

    /** TUN 读线程调用：处理应用发出的 TCP 包 */
    public void onPacket(Packets.TcpHeader t) {
        if (isClosed()) {
            return;
        }
        lastActivity = System.currentTimeMillis();
        if ((t.flags & Packets.RST) != 0) {
            close();
            return;
        }

        synchronized (this) {
            if (isClosed()) {
                return;
            }
            // SYN 重传：重发 SYN|ACK，序号保持不变
            if ((t.flags & Packets.SYN) != 0 && (t.flags & Packets.ACK) == 0) {
                sink.writePacket(Packets.buildTcp(remoteIp, localIp, remotePort, localPort,
                        synSeq, theirSeq, Packets.SYN | Packets.ACK, null));
                return;
            }

            if (!established && (t.flags & Packets.ACK) != 0 && t.ack == mySeq) {
                established = true;
            }

            int n = t.payload.length;
            if (n > 0) {
                if (t.seq == theirSeq) {
                    byte[] chunk = t.payload;
                    boolean accepted;
                    if (tunnelReady) {
                        accepted = outbound.offer(chunk);
                    } else {
                        accepted = pendingBytes + n <= MAX_PENDING_BYTES;
                        if (accepted) {
                            pending.add(chunk);
                            pendingBytes += n;
                        }
                    }
                    if (!accepted) {
                        // 代理过慢，缓冲已满：回 RST 让应用重连，避免静默丢数据
                        reply(Packets.RST | Packets.ACK, null);
                        close();
                        return;
                    }
                    theirSeq = Packets.advance(theirSeq, n);
                } else if (!Packets.isOldSeq(t.seq, theirSeq)) {
                    // 序号出现缺口：不推进，保持 ACK 不变，等对方重传
                }
                reply(Packets.ACK, null);
            } else if ((t.flags & Packets.FIN) != 0) {
                theirSeq = Packets.advance(theirSeq, 1);
                appFin = true;
                reply(Packets.ACK, null);
                Socket s = socket;
                if (s != null && tunnelReady && !s.isClosed()) {
                    try {
                        s.shutdownOutput();
                    } catch (IOException ignore) {
                        // 代理侧可能不支持半关闭
                    }
                }
            } else if (closing && (t.flags & Packets.ACK) != 0 && t.ack == mySeq) {
                close();
            }
        }
    }

    /** 我方发包；SYN/FIN 各消耗一个序号 */
    private void reply(int flags, byte[] payload) {
        if (isClosed()) {
            return;
        }
        sink.writePacket(Packets.buildTcp(remoteIp, localIp, remotePort, localPort,
                mySeq, theirSeq, flags, payload));
        int consumed = (payload == null) ? 0 : payload.length;
        if ((flags & Packets.SYN) != 0) {
            consumed++;
        }
        if ((flags & Packets.FIN) != 0) {
            consumed++;
        }
        mySeq = Packets.advance(mySeq, consumed);
        lastActivity = System.currentTimeMillis();
    }

    /** 建立代理隧道，并把应用数据持续写入隧道 */
    private void runWriter() {
        try {
            Socket s = sink.openTunnel(remoteIp, remotePort, domain);
            synchronized (this) {
                if (isClosed()) {
                    s.close();
                    return;
                }
                socket = s;
                OutputStream out = s.getOutputStream();
                for (byte[] p : pending) {
                    out.write(p);
                }
                if (!pending.isEmpty()) {
                    out.flush();
                }
                pending.clear();
                pendingBytes = 0;
                tunnelReady = true;
                if (appFin) {
                    s.shutdownOutput();
                }
            }
            tunnelLatch.countDown();

            OutputStream out = s.getOutputStream();
            while (!isClosed()) {
                byte[] chunk = outbound.poll(1, TimeUnit.SECONDS);
                if (chunk == null) {
                    continue;
                }
                out.write(chunk);
                out.flush();
                lastActivity = System.currentTimeMillis();
            }
        } catch (Exception e) {
            Log.d(TAG, "writer ended: " + e);
            tunnelLatch.countDown();
            fail(e);
        }
    }

    /** 从隧道读数据，封装成 TCP 包回写 TUN */
    private void runReader() {
        try {
            if (!tunnelLatch.await(15, TimeUnit.SECONDS)) {
                fail(new IOException("proxy connect timeout"));
                return;
            }
            Socket s = socket;
            if (s == null || isClosed()) {
                return;
            }
            InputStream in = s.getInputStream();
            byte[] buf = new byte[4096];
            int n;
            while (!isClosed() && (n = in.read(buf)) != -1) {
                if (n == 0) {
                    continue;
                }
                byte[] chunk = Arrays.copyOf(buf, n);
                synchronized (this) {
                    if (isClosed()) {
                        break;
                    }
                    reply(Packets.ACK | Packets.PSH, chunk);
                }
            }
            synchronized (this) {
                if (!isClosed()) {
                    reply(Packets.ACK | Packets.FIN, null);
                    closing = true;
                }
            }
            // 会话保留一段时间以接收应用对 FIN 的 ACK，最终由超时扫描回收
        } catch (Exception e) {
            Log.d(TAG, "reader ended: " + e);
            fail(e);
        }
    }

    private void fail(Exception e) {
        synchronized (this) {
            if (!isClosed()) {
                reply(Packets.RST | Packets.ACK, null);
            }
        }
        close();
    }

    public void close() {
        if (!closed.compareAndSet(false, true)) {
            return;
        }
        tunnelLatch.countDown();
        outbound.clear();
        synchronized (this) {
            pending.clear();
            Socket s = socket;
            if (s != null) {
                try {
                    s.close();
                } catch (IOException ignore) {
                    // 已关闭
                }
            }
        }
        sink.onClosed(this);
    }
}
