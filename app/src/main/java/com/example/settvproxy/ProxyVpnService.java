package com.example.settvproxy;

import android.app.Notification;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.app.PendingIntent;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.VpnService;
import android.os.Build;
import android.os.ParcelFileDescriptor;
import android.util.Base64;
import android.util.Log;

import com.example.settvproxy.vpn.FakeDns;
import com.example.settvproxy.vpn.Packets;
import com.example.settvproxy.vpn.TunLoop;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * VpnService 全局代理模式。
 *
 * 建立 TUN 接口捕获设备 IPv4 流量，由 {@link TunLoop} 转发到 SOCKS5 / HTTP CONNECT 代理。
 * 到代理服务器的 socket 都绑定在 VPN 建立前找到的物理网络上，避免被自身捕获形成环路。
 *
 * 支持：
 * - SOCKS5 无认证 / 用户名密码认证（RFC 1929），HTTP CONNECT Basic 认证；
 * - SOCKS5 UDP ASSOCIATE 控制连接，供 {@link com.example.settvproxy.vpn.UdpRelay} 转发 UDP；
 * - 应用过滤：全部 / 排除选中 / 仅允许选中（默认不过滤，分流交给代理端）。
 */
public class ProxyVpnService extends VpnService {

    private static final String TAG = "ProxyVpnService";
    public static final String ACTION_CONNECT = "com.example.settvproxy.CONNECT";
    public static final String ACTION_DISCONNECT = "com.example.settvproxy.DISCONNECT";

    private static final int NOTIFICATION_ID = 1;
    private static final String CHANNEL_ID = "settvproxy_vpn";
    private static final String VPN_ADDRESS = "10.0.0.2";
    private static final int MTU = 1500;
    private static final int CONNECT_TIMEOUT_MS = 10000;

    private static volatile boolean running = false;

    public static boolean isRunning() {
        return running;
    }

    private volatile TunLoop loop;
    private volatile int proxyIp;
    private volatile int proxyPort;
    private volatile boolean socks5;
    private volatile int dnsIp;
    private volatile String proxyUser = "";
    private volatile String proxyPass = "";
    private volatile boolean hasAuth;
    /** VPN 建立前找到的物理网络，所有到代理的 socket 都从它出去 */
    private volatile Network physicalNetwork;

    @Override
    public int onStartCommand(Intent intent, int flags, int startId) {
        String action = (intent == null) ? null : intent.getAction();
        if (ACTION_DISCONNECT.equals(action)) {
            disconnect();
        } else {
            connect();
        }
        return START_NOT_STICKY;
    }

    @Override
    public void onRevoke() {
        disconnect();
        super.onRevoke();
    }

    @Override
    public void onDestroy() {
        closeTunnel();
        // 系统回收服务时纠正残留状态；启动失败的状态不能被覆盖
        Prefs prefs = new Prefs(this);
        if (prefs.getVpnState() == Prefs.VPN_RUNNING) {
            prefs.setVpnState(Prefs.VPN_STOPPED, null);
        }
        super.onDestroy();
    }

    private void connect() {
        Prefs prefs = new Prefs(this);
        // 把启动结果持久化，界面即使被切到后台或重建也能读到最终状态
        prefs.setVpnState(Prefs.VPN_STARTING, null);
        if (running) {
            // 只重建 TUN，不能 stopSelf，否则本次 start 请求结束后服务会被销毁
            closeTunnel();
        }

        String host = prefs.getHost().trim();
        int port = parsePort(prefs.getPort());
        if (host.isEmpty() || port <= 0) {
            Log.e(TAG, "invalid proxy address");
            failStart(prefs, getString(R.string.err_vpn_bad_addr));
            return;
        }

        // 必须在 establish() 之前把代理主机（和 DNS）解析成 IP：
        // VPN 建立后 DNS 查询会进入 TUN，此时再按域名解析会形成死循环。
        try {
            proxyIp = resolveIpv4(host);
        } catch (Exception e) {
            Log.e(TAG, "cannot resolve proxy host", e);
            failStart(prefs, getString(R.string.err_vpn_resolve));
            return;
        }
        try {
            dnsIp = resolveIpv4(prefs.getDns());
        } catch (Exception e) {
            // 域名透传时上游 DNS 仅作异常回退，解析失败不应影响启动
            dnsIp = Packets.parseIpv4Address(Prefs.DEFAULT_DNS);
        }
        proxyPort = port;
        socks5 = prefs.getProxyType() == Prefs.TYPE_SOCKS5;
        proxyUser = prefs.getUser() == null ? "" : prefs.getUser();
        proxyPass = prefs.getPass() == null ? "" : prefs.getPass();
        hasAuth = !proxyUser.isEmpty();
        boolean udpRelayEnabled = prefs.isUdpRelayEnabled();
        boolean domainPassthrough = prefs.isDomainPassthrough();
        // 必须在 establish() 之前取物理网络：VPN 建好后默认网络会变成 tun0
        physicalNetwork = findPhysicalNetwork();
        Log.d(TAG, "physical network=" + physicalNetwork
                + " udpRelay=" + udpRelayEnabled
                + " domainPassthrough=" + domainPassthrough);

        startForegroundCompat();

        Builder builder = new Builder();
        builder.setSession(getString(R.string.app_name));
        builder.addAddress(VPN_ADDRESS, 32);
        builder.addRoute("0.0.0.0", 0);
        try {
            // 把 IPv6 也收进 TUN 并丢弃，防止 IPv6 流量绕过代理直连
            builder.addRoute("::", 0);
        } catch (IllegalArgumentException ignore) {
            // 个别 ROM 不支持 IPv6 路由
        }
        // 域名透传开启时把 VPN 的 DNS 指向本地 fake DNS，由 TunLoop 直接伪造应答
        builder.addDnsServer(domainPassthrough
                ? FakeDns.DNS_ADDRESS : Packets.ipToString(dnsIp));
        builder.setMtu(MTU);
        applyAppFilter(builder, prefs);
        builder.setConfigureIntent(configureIntent());

        ParcelFileDescriptor pfd;
        try {
            pfd = builder.establish();
        } catch (Exception e) {
            Log.e(TAG, "establish failed", e);
            failStart(prefs, getString(R.string.err_vpn_establish));
            return;
        }
        if (pfd == null) {
            Log.e(TAG, "vpn not prepared");
            failStart(prefs, getString(R.string.err_vpn_not_prepared));
            return;
        }

        try {
            loop = new TunLoop(pfd, this, dnsIp, udpRelayEnabled, domainPassthrough);
            loop.start();
        } catch (Exception e) {
            Log.e(TAG, "start tun loop failed", e);
            try {
                pfd.close();
            } catch (IOException ignore) {
                // 已关闭
            }
            failStart(prefs, getString(R.string.err_vpn_tun));
            return;
        }
        running = true;
        prefs.setVpnState(Prefs.VPN_RUNNING, null);
    }

    private void failStart(Prefs prefs, String reason) {
        running = false;
        stopForeground(true);
        prefs.setVpnState(Prefs.VPN_FAILED, reason);
        stopSelf();
    }

    /**
     * addAllowedApplication 与 addDisallowedApplication 互斥，不能混用。
     * 白名单模式下自身不在名单里即自动直连，无需再调 disallowed。
     */
    private void applyAppFilter(Builder builder, Prefs prefs) {
        Set<String> apps = prefs.getAppSet();
        try {
            if (prefs.getFilterMode() == Prefs.FILTER_ONLY && !apps.isEmpty()) {
                for (String pkg : apps) {
                    builder.addAllowedApplication(pkg);
                }
                return;
            }
            if (prefs.getFilterMode() == Prefs.FILTER_EXCLUDE) {
                for (String pkg : apps) {
                    if (!pkg.equals(getPackageName())) {
                        builder.addDisallowedApplication(pkg);
                    }
                }
            }
            builder.addDisallowedApplication(getPackageName());
        } catch (PackageManager.NameNotFoundException e) {
            Log.w(TAG, "filtered package not found", e);
        }
    }

    private void closeTunnel() {
        running = false;
        TunLoop l = loop;
        loop = null;
        if (l != null) {
            l.shutdown();
        }
    }

    private void disconnect() {
        closeTunnel();
        new Prefs(this).setVpnState(Prefs.VPN_STOPPED, null);
        stopForeground(true);
        stopSelf();
    }

    public boolean isSocks5() {
        return socks5;
    }

    public boolean isUdpAssociateSupported() {
        return socks5;
    }

    /** 供 UdpRelay / TunLoop 把 socket 绑定到物理网络，彻底绕开自身 VPN */
    public Network getPhysicalNetwork() {
        return physicalNetwork;
    }

    /** 目标是否就是代理服务器自己（某些常驻 App 缓存了旧的 HTTP 代理设置时会连到这里） */
    public boolean isProxyEndpoint(int ip, int port) {
        return ip == proxyIp && port == proxyPort;
    }

    /** 找一个具备 INTERNET 能力且不是 VPN 的网络（通常是 WiFi） */
    private Network findPhysicalNetwork() {
        ConnectivityManager cm =
                (ConnectivityManager) getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) {
            return null;
        }
        for (Network network : cm.getAllNetworks()) {
            NetworkCapabilities caps = cm.getNetworkCapabilities(network);
            if (caps != null
                    && caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    && !caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) {
                return network;
            }
        }
        return null;
    }

    /**
     * 建立到目标的 TCP 代理隧道。返回的 Socket 已完成握手，读写即为目标服务器的原始字节流。
     * domain 非空（由 fake-IP 还原）时用 SOCKS5 ATYP=DOMAIN / HTTP CONNECT 域名形式，
     * 由代理端远程解析并按域名分流；否则按 ATYP=IPv4 / IP 形式连接。
     */
    public Socket openTunnel(int targetIp, int targetPort, String domain) throws IOException {
        if (domain == null && targetIp == proxyIp && targetPort == proxyPort) {
            // 目标就是代理服务器自己：直接把字节送到代理端口原样转发。
            // 若再做一次 SOCKS5/HTTP 握手就成了「通过代理连代理」，会不断派生无效连接。
            Log.d(TAG, "proxy endpoint direct passthrough");
            return newSocketToProxy();
        }
        Log.d(TAG, "tunnel " + (domain != null && !domain.isEmpty()
                ? "DOMAIN " + domain : "IP " + Packets.ipToString(targetIp))
                + ":" + targetPort);
        Socket socket = newSocketToProxy();
        try {
            if (socks5) {
                socks5Connect(socket, targetIp, targetPort, domain);
            } else {
                httpConnect(socket, targetIp, targetPort, domain);
            }
            return socket;
        } catch (IOException e) {
            socket.close();
            throw e;
        }
    }

    private Socket newSocketToProxy() throws IOException {
        Network network = physicalNetwork;
        // 从物理网络的 SocketFactory 创建，连接天然不经过 tun0，不依赖 protect() 是否成功
        Socket socket = (network != null)
                ? network.getSocketFactory().createSocket()
                : new Socket();
        if (network == null && !protect(socket)) {
            // 自身 UID 已被 addDisallowedApplication 排除，protect 返回 false 不代表环路
            Log.d(TAG, "protect() unavailable, relying on excluded self UID");
        }
        socket.connect(new InetSocketAddress(Packets.ipToString(proxyIp), proxyPort),
                CONNECT_TIMEOUT_MS);
        socket.setTcpNoDelay(true);
        socket.setSoTimeout(0);
        return socket;
    }

    // ---------- HTTP CONNECT ----------

    private void httpConnect(Socket socket, int targetIp, int targetPort,
                             String domain) throws IOException {
        String host = (domain != null && !domain.isEmpty())
                ? domain : Packets.ipToString(targetIp);
        String authority = host + ":" + targetPort;
        StringBuilder request = new StringBuilder();
        request.append("CONNECT ").append(authority).append(" HTTP/1.1\r\n")
                .append("Host: ").append(authority).append("\r\n");
        if (hasAuth) {
            String token = proxyUser + ":" + proxyPass;
            String encoded = Base64.encodeToString(
                    token.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
            request.append("Proxy-Authorization: Basic ").append(encoded).append("\r\n");
        }
        request.append("Proxy-Connection: Keep-Alive\r\n\r\n");

        OutputStream out = socket.getOutputStream();
        out.write(request.toString().getBytes(StandardCharsets.US_ASCII));
        out.flush();

        InputStream in = socket.getInputStream();
        // 逐字节读取响应头，避免缓冲预读吞掉隧道里的前几个数据字节
        byte[] end = {'\r', '\n', '\r', '\n'};
        int matched = 0;
        StringBuilder header = new StringBuilder();
        while (matched < end.length) {
            int c = in.read();
            if (c == -1) {
                throw new EOFException("proxy closed during CONNECT");
            }
            if (header.length() < 512) {
                header.append((char) c);
            }
            if (c == (end[matched] & 0xff)) {
                matched++;
            } else {
                matched = (c == '\r') ? 1 : 0;
            }
        }
        String statusLine = header.toString().split("\r\n")[0];
        if (!statusLine.contains(" 200")) {
            throw new IOException("proxy refused CONNECT: " + statusLine);
        }
    }

    // ---------- SOCKS5 ----------

    /** 方法协商 + 可选的用户名密码认证（RFC 1929） */
    private void socks5Negotiate(InputStream in, OutputStream out) throws IOException {
        byte[] user = proxyUser.getBytes(StandardCharsets.UTF_8);
        byte[] pass = proxyPass.getBytes(StandardCharsets.UTF_8);
        boolean offerAuth = hasAuth && user.length > 0 && user.length <= 255 && pass.length <= 255;

        if (offerAuth) {
            out.write(new byte[]{0x05, 0x02, 0x00, 0x02}); // NO-AUTH + USER/PASS
        } else {
            out.write(new byte[]{0x05, 0x01, 0x00});        // NO-AUTH only
        }
        out.flush();

        int version = in.read();
        int method = in.read();
        if (version != 0x05) {
            throw new IOException("not a socks5 proxy: " + version);
        }
        if (method == 0x02) {
            if (!offerAuth) {
                throw new IOException("proxy requires auth but no credentials configured");
            }
            byte[] auth = new byte[3 + user.length + pass.length];
            auth[0] = 0x01;
            auth[1] = (byte) user.length;
            System.arraycopy(user, 0, auth, 2, user.length);
            auth[2 + user.length] = (byte) pass.length;
            System.arraycopy(pass, 0, auth, 3 + user.length, pass.length);
            out.write(auth);
            out.flush();
            int authVersion = in.read();
            int status = in.read();
            if (authVersion != 0x01 || status != 0x00) {
                throw new IOException("socks5 username/password auth rejected");
            }
        } else if (method != 0x00) {
            throw new IOException("socks5 no acceptable method: 0x"
                    + Integer.toHexString(method));
        }
    }

    private void socks5Connect(Socket socket, int targetIp, int targetPort,
                               String domain) throws IOException {
        InputStream in = socket.getInputStream();
        OutputStream out = socket.getOutputStream();
        socks5Negotiate(in, out);

        byte[] req;
        if (domain != null && !domain.isEmpty()) {
            byte[] name = domain.getBytes(StandardCharsets.US_ASCII);
            if (name.length > 255) {
                throw new IOException("domain too long: " + domain);
            }
            req = new byte[5 + name.length + 2];
            req[0] = 0x05;
            req[1] = 0x01; // CONNECT
            req[2] = 0x00;
            req[3] = 0x03; // ATYP = DOMAIN
            req[4] = (byte) name.length;
            System.arraycopy(name, 0, req, 5, name.length);
            req[5 + name.length] = (byte) (targetPort >> 8);
            req[6 + name.length] = (byte) targetPort;
        } else {
            req = new byte[10];
            req[0] = 0x05;
            req[1] = 0x01; // CONNECT
            req[2] = 0x00;
            req[3] = 0x01; // ATYP = IPv4
            System.arraycopy(Packets.ipToBytes(targetIp), 0, req, 4, 4);
            req[8] = (byte) (targetPort >> 8);
            req[9] = (byte) targetPort;
        }
        out.write(req);
        out.flush();

        SocksReply reply = readSocks5Reply(in);
        if (reply.rep != 0x00) {
            throw new IOException("socks5 CONNECT failed, REP=" + reply.rep);
        }
    }

    /**
     * 建立一条 UDP ASSOCIATE 控制连接，返回中继地址。
     * 控制 Socket 必须一直保持打开，关闭后中继即失效。
     */
    public UdpControl openSocks5UdpAssociate(int clientUdpPort) throws IOException {
        if (!socks5) {
            throw new IOException("UDP ASSOCIATE requires SOCKS5 mode");
        }
        Socket socket = newSocketToProxy();
        try {
            InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();
            socks5Negotiate(in, out);

            byte[] req = new byte[10];
            req[0] = 0x05;
            req[1] = 0x03; // UDP ASSOCIATE
            req[2] = 0x00;
            req[3] = 0x01; // DST.ADDR = 0.0.0.0（由服务端按实际来源判定）
            req[8] = (byte) (clientUdpPort >> 8);
            req[9] = (byte) clientUdpPort;
            out.write(req);
            out.flush();

            SocksReply reply = readSocks5Reply(in);
            if (reply.rep != 0x00) {
                throw new IOException("socks5 UDP ASSOCIATE failed, REP=" + reply.rep);
            }
            if (reply.port <= 0) {
                throw new IOException("socks5 UDP relay returned invalid port");
            }

            InetAddress relayAddr;
            if (reply.atyp == 0x01) {
                relayAddr = InetAddress.getByAddress(reply.addr);
            } else if (reply.atyp == 0x03) {
                relayAddr = InetAddress.getByName(
                        new String(reply.addr, StandardCharsets.US_ASCII));
            } else {
                relayAddr = socket.getInetAddress();
            }
            if (relayAddr.isAnyLocalAddress()) {
                relayAddr = socket.getInetAddress();
            }
            return new UdpControl(socket, new InetSocketAddress(relayAddr, reply.port));
        } catch (IOException e) {
            socket.close();
            throw e;
        }
    }

    public static final class UdpControl {
        public final Socket controlSocket;
        public final InetSocketAddress relayAddress;

        private UdpControl(Socket controlSocket, InetSocketAddress relayAddress) {
            this.controlSocket = controlSocket;
            this.relayAddress = relayAddress;
        }
    }

    private static final class SocksReply {
        int rep;
        int atyp;
        byte[] addr;
        int port;
    }

    private SocksReply readSocks5Reply(InputStream in) throws IOException {
        byte[] head = readFully(in, 4);
        SocksReply r = new SocksReply();
        r.rep = head[1] & 0xff;
        r.atyp = head[3] & 0xff;
        int addrLen;
        if (r.atyp == 0x01) {
            addrLen = 4;
        } else if (r.atyp == 0x04) {
            addrLen = 16;
        } else if (r.atyp == 0x03) {
            addrLen = readFully(in, 1)[0] & 0xff;
        } else {
            throw new IOException("socks5 unknown ATYP=" + r.atyp);
        }
        r.addr = readFully(in, addrLen);
        byte[] portBytes = readFully(in, 2);
        r.port = ((portBytes[0] & 0xff) << 8) | (portBytes[1] & 0xff);
        return r;
    }

    private static byte[] readFully(InputStream in, int n) throws IOException {
        byte[] buf = new byte[n];
        int off = 0;
        while (off < n) {
            int r = in.read(buf, off, n - off);
            if (r < 0) {
                throw new EOFException("socks5 reply truncated");
            }
            off += r;
        }
        return buf;
    }

    // ---------- 辅助 ----------

    private static int resolveIpv4(String host) throws UnknownHostException {
        if (host.matches("\\d{1,3}(\\.\\d{1,3}){3}")) {
            return Packets.parseIpv4Address(host);
        }
        byte[] addr = InetAddress.getByName(host).getAddress();
        if (addr.length != 4) {
            throw new UnknownHostException("IPv6 proxy address is not supported: " + host);
        }
        return Packets.ipAt(addr, 0);
    }

    private static int parsePort(String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return -1;
        }
    }

    private PendingIntent configureIntent() {
        int flags = PendingIntent.FLAG_UPDATE_CURRENT;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            flags |= PendingIntent.FLAG_IMMUTABLE;
        }
        return PendingIntent.getActivity(this, 0,
                new Intent(this, MainActivity.class), flags);
    }

    private void startForegroundCompat() {
        NotificationManager nm =
                (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && nm != null) {
            NotificationChannel channel = new NotificationChannel(CHANNEL_ID,
                    getString(R.string.app_name), NotificationManager.IMPORTANCE_LOW);
            nm.createNotificationChannel(channel);
        }
        Notification.Builder nb = (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O)
                ? new Notification.Builder(this, CHANNEL_ID)
                : new Notification.Builder(this);
        Notification notification = nb
                .setSmallIcon(android.R.drawable.ic_dialog_info)
                .setContentTitle(getString(R.string.app_name))
                .setContentText(getString(R.string.vpn_notification))
                .setContentIntent(configureIntent())
                .setOngoing(true)
                .build();
        startForeground(NOTIFICATION_ID, notification);
    }
}
