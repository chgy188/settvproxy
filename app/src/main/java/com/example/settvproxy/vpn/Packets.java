package com.example.settvproxy.vpn;

import java.nio.ByteBuffer;
import java.util.Random;

/**
 * IPv4 / TCP / UDP 报文的解析、构造与 16 位反码校验和计算。
 *
 * TUN 接口交给应用的是原始 IP 包；我们在这里把包拆开，并在回写时按协议重新封装。
 * 仅处理 IPv4（VPN 模式会把 IPv6 路由也收进 TUN 后丢弃，避免 IPv6 直连泄漏）。
 */
public final class Packets {

    public static final int PROTO_TCP = 6;
    public static final int PROTO_UDP = 17;

    public static final int FIN = 1;
    public static final int SYN = 2;
    public static final int RST = 4;
    public static final int PSH = 8;
    public static final int ACK = 16;

    private static final Random RANDOM = new Random();

    private Packets() {
    }

    public static int u8(byte[] b, int o) {
        return b[o] & 0xff;
    }

    public static int u16(byte[] b, int o) {
        return ((b[o] & 0xff) << 8) | (b[o + 1] & 0xff);
    }

    public static long u32(byte[] b, int o) {
        return ((long) (b[o] & 0xff) << 24)
                | ((long) (b[o + 1] & 0xff) << 16)
                | ((long) (b[o + 2] & 0xff) << 8)
                | (b[o + 3] & 0xffL);
    }

    public static int ipAt(byte[] b, int o) {
        return ((b[o] & 0xff) << 24)
                | ((b[o + 1] & 0xff) << 16)
                | ((b[o + 2] & 0xff) << 8)
                | (b[o + 3] & 0xff);
    }

    public static String ipToString(int ip) {
        return ((ip >>> 24) & 0xff) + "." + ((ip >>> 16) & 0xff) + "."
                + ((ip >>> 8) & 0xff) + "." + (ip & 0xff);
    }

    public static byte[] ipToBytes(int ip) {
        return new byte[]{
                (byte) (ip >>> 24), (byte) (ip >>> 16), (byte) (ip >>> 8), (byte) ip
        };
    }

    /** 解析点分十进制 IPv4 地址，失败抛 IllegalArgumentException */
    public static int parseIpv4Address(String s) {
        String[] p = s.split("\\.");
        if (p.length != 4) {
            throw new IllegalArgumentException("not an IPv4 address: " + s);
        }
        int v = 0;
        for (String part : p) {
            int n = Integer.parseInt(part);
            if (n < 0 || n > 255) {
                throw new IllegalArgumentException("bad octet: " + part);
            }
            v = (v << 8) | n;
        }
        return v;
    }

    public static long newSeq() {
        return RANDOM.nextInt() & 0xffffffffL;
    }

    /** 序号按 2^32 回绕 */
    public static long advance(long seq, int n) {
        return (seq + n) & 0xffffffffL;
    }

    /** seq 是否位于 expected 之前（用于识别重复包），兼容回绕 */
    public static boolean isOldSeq(long seq, long expected) {
        long d = (seq - expected) & 0xffffffffL;
        return d > 0x7fffffffL;
    }

    private static long sum(byte[] b, int off, int len) {
        long s = 0;
        int i = off;
        int end = off + len;
        for (; i + 1 < end; i += 2) {
            s += u16(b, i);
        }
        if (i < end) {
            s += (b[i] & 0xff) << 8;
        }
        return s;
    }

    private static int fold(long s) {
        while ((s >>> 16) != 0) {
            s = (s & 0xffff) + (s >>> 16);
        }
        return (int) (~s & 0xffff);
    }

    public static int checksum(byte[] b, int off, int len, long initial) {
        return fold(sum(b, off, len) + initial);
    }

    private static long pseudoHeader(int src, int dst, int proto, int transportLen) {
        return ((src >>> 16) & 0xffffL) + (src & 0xffffL)
                + ((dst >>> 16) & 0xffffL) + (dst & 0xffffL)
                + proto + transportLen;
    }

    // ---------- 解析 ----------

    public static final class Ip {
        public int headerLength;
        public int totalLength;
        public int protocol;
        public int src;
        public int dst;
        /** 指向原始缓冲区的传输层起点，避免拷贝 */
        public int offset;
        public int dataLength;
    }

    public static Ip parseIpPacket(byte[] buf, int length) {
        if (length < 20 || ((buf[0] >> 4) & 0x0f) != 4) {
            return null;
        }
        int ihl = (buf[0] & 0x0f) * 4;
        if (ihl < 20 || ihl > length) {
            return null;
        }
        int total = u16(buf, 2);
        if (total < ihl || total > length) {
            return null;
        }
        Ip ip = new Ip();
        ip.headerLength = ihl;
        ip.totalLength = total;
        ip.protocol = u8(buf, 9);
        ip.src = ipAt(buf, 12);
        ip.dst = ipAt(buf, 16);
        ip.offset = ihl;
        ip.dataLength = total - ihl;
        return ip;
    }

    public static final class TcpHeader {
        public int srcPort;
        public int dstPort;
        public long seq;
        public long ack;
        public int flags;
        public int window;
        public byte[] payload;
    }

    private static TcpHeader parseTcp(byte[] buf, Ip ip) {
        if (ip.protocol != PROTO_TCP || ip.dataLength < 20) {
            return null;
        }
        int o = ip.offset;
        int dataOffset = ((buf[o + 12] >> 4) & 0x0f) * 4;
        if (dataOffset < 20 || dataOffset > ip.dataLength) {
            return null;
        }
        TcpHeader t = new TcpHeader();
        t.srcPort = u16(buf, o);
        t.dstPort = u16(buf, o + 2);
        t.seq = u32(buf, o + 4);
        t.ack = u32(buf, o + 8);
        t.flags = u8(buf, o + 13);
        t.window = u16(buf, o + 14);
        int n = ip.dataLength - dataOffset;
        t.payload = new byte[n];
        System.arraycopy(buf, o + dataOffset, t.payload, 0, n);
        return t;
    }

    public static final class UdpHeader {
        public int srcPort;
        public int dstPort;
        public byte[] payload;
    }

    private static UdpHeader parseUdp(byte[] buf, Ip ip) {
        if (ip.protocol != PROTO_UDP || ip.dataLength < 8) {
            return null;
        }
        int o = ip.offset;
        int len = u16(buf, o + 4);
        int n = Math.min(Math.max(len - 8, 0), ip.dataLength - 8);
        UdpHeader u = new UdpHeader();
        u.srcPort = u16(buf, o);
        u.dstPort = u16(buf, o + 2);
        u.payload = new byte[n];
        System.arraycopy(buf, o + 8, u.payload, 0, n);
        return u;
    }

    public static TcpHeader tcp(byte[] buf, Ip ip) {
        return parseTcp(buf, ip);
    }

    public static UdpHeader udp(byte[] buf, Ip ip) {
        return parseUdp(buf, ip);
    }

    // ---------- 构造 ----------

    /**
     * 构造一个从「远端」发往「本机 VPN 地址」的 TCP 包。
     * 调用方传入的 srcIp/srcPort 是远端，dstIp/dstPort 是 TUN 内的本机。
     */
    public static byte[] buildTcp(int srcIp, int dstIp, int srcPort, int dstPort,
                                  long seq, long ack, int flags, byte[] payload) {
        int plen = (payload == null) ? 0 : payload.length;
        int tcpLen = 20 + plen;
        int total = 20 + tcpLen;
        ByteBuffer bb = ByteBuffer.allocate(total);

        bb.put((byte) 0x45);
        bb.put((byte) 0);
        bb.putShort((short) total);
        bb.putShort((short) 0);
        bb.putShort((short) 0x4000);
        bb.put((byte) 64);
        bb.put((byte) PROTO_TCP);
        bb.putShort((short) 0);
        bb.put(ipToBytes(srcIp));
        bb.put(ipToBytes(dstIp));

        bb.putShort((short) srcPort);
        bb.putShort((short) dstPort);
        bb.putInt((int) seq);
        bb.putInt((int) ack);
        bb.put((byte) 0x50);
        bb.put((byte) flags);
        bb.putShort((short) 65535);
        bb.putShort((short) 0);
        bb.putShort((short) 0);
        if (plen > 0) {
            bb.put(payload);
        }

        byte[] pkt = bb.array();
        int ipCsum = checksum(pkt, 0, 20, 0);
        pkt[10] = (byte) (ipCsum >> 8);
        pkt[11] = (byte) ipCsum;
        int tcpCsum = checksum(pkt, 20, tcpLen,
                pseudoHeader(srcIp, dstIp, PROTO_TCP, tcpLen));
        pkt[20 + 16] = (byte) (tcpCsum >> 8);
        pkt[20 + 17] = (byte) tcpCsum;
        return pkt;
    }

    /** 构造一个 UDP 回包（DNS 响应） */
    public static byte[] buildUdp(int srcIp, int dstIp, int srcPort, int dstPort,
                                  byte[] payload) {
        int plen = (payload == null) ? 0 : payload.length;
        int udpLen = 8 + plen;
        int total = 20 + udpLen;
        ByteBuffer bb = ByteBuffer.allocate(total);

        bb.put((byte) 0x45);
        bb.put((byte) 0);
        bb.putShort((short) total);
        bb.putShort((short) 0);
        bb.putShort((short) 0x4000);
        bb.put((byte) 64);
        bb.put((byte) PROTO_UDP);
        bb.putShort((short) 0);
        bb.put(ipToBytes(srcIp));
        bb.put(ipToBytes(dstIp));

        bb.putShort((short) srcPort);
        bb.putShort((short) dstPort);
        bb.putShort((short) udpLen);
        bb.putShort((short) 0);
        if (plen > 0) {
            bb.put(payload);
        }

        byte[] pkt = bb.array();
        int ipCsum = checksum(pkt, 0, 20, 0);
        pkt[10] = (byte) (ipCsum >> 8);
        pkt[11] = (byte) ipCsum;
        int udpCsum = checksum(pkt, 20, udpLen,
                pseudoHeader(srcIp, dstIp, PROTO_UDP, udpLen));
        if (udpCsum == 0) {
            udpCsum = 0xffff;
        }
        pkt[20 + 6] = (byte) (udpCsum >> 8);
        pkt[20 + 7] = (byte) udpCsum;
        return pkt;
    }

    // ---------- SOCKS5 UDP 封装 ----------

    public static final class SocksUdpReply {
        /** ATYP=DOMAIN 时为 0，此时调用方应改用会话记录的目标地址 */
        public int remoteIp;
        public int remotePort;
        public String remoteDomain;
        public byte[] payload;
    }

    /** ATYP=IPv4 的 SOCKS5 UDP 请求：RSV(2) FRAG(1) ATYP(1) ADDR(4) PORT(2) DATA */
    public static byte[] buildSocksUdpRequest(int dstIp, int dstPort, byte[] payload) {
        byte[] packet = new byte[10 + payload.length];
        packet[3] = 0x01;
        System.arraycopy(ipToBytes(dstIp), 0, packet, 4, 4);
        packet[8] = (byte) (dstPort >> 8);
        packet[9] = (byte) dstPort;
        System.arraycopy(payload, 0, packet, 10, payload.length);
        return packet;
    }

    /** ATYP=DOMAIN 的 SOCKS5 UDP 请求，代理端按域名远程解析 */
    public static byte[] buildSocksUdpRequest(String domain, int dstPort, byte[] payload) {
        byte[] name = domain.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        int header = 4 + 1 + name.length + 2;
        byte[] packet = new byte[header + payload.length];
        packet[3] = 0x03;
        packet[4] = (byte) name.length;
        System.arraycopy(name, 0, packet, 5, name.length);
        packet[5 + name.length] = (byte) (dstPort >> 8);
        packet[6 + name.length] = (byte) dstPort;
        System.arraycopy(payload, 0, packet, header, payload.length);
        return packet;
    }

    /** 解析中继回包；分片与 IPv6 返回 null */
    public static SocksUdpReply parseSocksUdpReply(byte[] data, int length) {
        if (length < 10 || (data[2] & 0xff) != 0) {
            return null;
        }
        SocksUdpReply r = new SocksUdpReply();
        int atyp = data[3] & 0xff;
        int dataOffset;
        if (atyp == 0x01) {
            r.remoteIp = ipAt(data, 4);
            r.remotePort = ((data[8] & 0xff) << 8) | (data[9] & 0xff);
            dataOffset = 10;
        } else if (atyp == 0x03) {
            int nameLen = data[4] & 0xff;
            dataOffset = 5 + nameLen + 2;
            if (dataOffset > length) {
                return null;
            }
            r.remoteDomain = new String(data, 5, nameLen,
                    java.nio.charset.StandardCharsets.US_ASCII);
            r.remotePort = ((data[5 + nameLen] & 0xff) << 8)
                    | (data[6 + nameLen] & 0xff);
        } else {
            return null;
        }
        if (dataOffset > length) {
            return null;
        }
        r.payload = java.util.Arrays.copyOfRange(data, dataOffset, length);
        return r;
    }
}
