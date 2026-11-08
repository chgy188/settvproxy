package com.example.settvproxy.vpn;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * fake-IP DNS。
 *
 * 不再让电视在墙内侧解析域名，而是本地伪造 DNS 应答：给每个域名分配一个
 * 198.18.0.0/16 网段的虚拟 IP，并记录「虚拟 IP → 域名」映射。
 * 应用连接虚拟 IP 时，TunLoop 查表还原域名，改用 SOCKS5 ATYP=DOMAIN /
 * HTTP CONNECT 域名形式发给代理，由代理端远程解析与按域名分流。
 *
 * AAAA 查询返回 NODATA，客户端因此不会拿到 IPv6 地址，也就绕开了
 * VPN 里 IPv6 被丢弃造成的连接等待。
 */
public final class FakeDns {

    /** 保留给 DNS 服务器本身的地址，不分配给域名 */
    public static final String DNS_ADDRESS = "198.18.0.1";
    private static final int NETWORK_PREFIX = 0xC6120000; // 198.18.0.0/16
    private static final int FIRST_HOST = 2;
    private static final int LAST_HOST = 0xFFFE;
    private static final int TTL_SECONDS = 60;

    private static final int TYPE_A = 1;
    private static final int TYPE_AAAA = 28;

    private final ConcurrentHashMap<Integer, String> ipToDomain = new ConcurrentHashMap<>();
    private final ConcurrentHashMap<String, Integer> domainToIp = new ConcurrentHashMap<>();
    private final AtomicInteger nextHost = new AtomicInteger(FIRST_HOST);

    public boolean isFakeIp(int ip) {
        return (ip >>> 16) == (NETWORK_PREFIX >>> 16);
    }

    public String lookup(int ip) {
        return ipToDomain.get(ip);
    }

    /** 解析 DNS 查询并构造应答；返回 null 表示报文无法处理（调用方应回退到上游 DNS） */
    public byte[] buildResponse(byte[] query, int length) {
        if (length < 17) {
            return null;
        }
        int id = Packets.u16(query, 0);
        int qdCount = Packets.u16(query, 4);
        if (qdCount < 1) {
            return null;
        }

        int[] questionEnd = new int[1];
        String domain = readName(query, 12, length, questionEnd);
        if (domain == null || domain.isEmpty()) {
            return null;
        }
        domain = domain.toLowerCase(Locale.US);
        int p = questionEnd[0];
        if (p + 4 > length) {
            return null;
        }
        int qType = Packets.u16(query, p);
        int questionLength = p + 4 - 12;

        boolean isA = (qType == TYPE_A);
        int answerLength = isA ? 16 : 0;
        byte[] response = new byte[12 + questionLength + answerLength];

        put16(response, 0, id);
        put16(response, 2, 0x8180);  // QR=1, RD=1, RA=1
        put16(response, 4, 1);       // QDCOUNT（只回答第一题）
        put16(response, 6, isA ? 1 : 0);
        put16(response, 8, 0);
        put16(response, 10, 0);
        System.arraycopy(query, 12, response, 12, questionLength);

        if (isA) {
            int o = 12 + questionLength;
            response[o] = (byte) 0xC0;
            response[o + 1] = 0x0C;              // NAME 指针指向 Question
            put16(response, o + 2, TYPE_A);
            put16(response, o + 4, 1);            // CLASS IN
            put32(response, o + 6, TTL_SECONDS);
            put16(response, o + 10, 4);           // RDLENGTH
            System.arraycopy(Packets.ipToBytes(allocate(domain)), 0, response, o + 12, 4);
        }
        // AAAA / HTTPS / 其它类型：ANCOUNT=0 的 NODATA，让客户端只用 IPv4
        return response;
    }

    private int allocate(String domain) {
        Integer existing = domainToIp.get(domain);
        if (existing != null) {
            return existing;
        }
        int host = nextHost.getAndIncrement();
        if (host > LAST_HOST) {
            ipToDomain.clear();
            domainToIp.clear();
            host = FIRST_HOST;
            nextHost.set(FIRST_HOST + 1);
        }
        int ip = NETWORK_PREFIX | host;
        ipToDomain.put(ip, domain);
        domainToIp.put(domain, ip);
        return ip;
    }

    /** 读取 QNAME；查询报文的 Question 段不含压缩指针，遇到指针直接放弃 */
    private static String readName(byte[] data, int offset, int end, int[] next) {
        StringBuilder sb = new StringBuilder();
        int p = offset;
        while (p < end) {
            int len = data[p] & 0xff;
            if (len == 0) {
                next[0] = p + 1;
                return sb.toString();
            }
            if ((len & 0xC0) != 0 || len > 63 || p + 1 + len > end) {
                return null;
            }
            if (sb.length() > 0) {
                sb.append('.');
            }
            sb.append(new String(data, p + 1, len, StandardCharsets.US_ASCII));
            p += 1 + len;
        }
        return null;
    }

    private static void put16(byte[] b, int off, int value) {
        b[off] = (byte) (value >> 8);
        b[off + 1] = (byte) value;
    }

    private static void put32(byte[] b, int off, int value) {
        b[off] = (byte) (value >> 24);
        b[off + 1] = (byte) (value >> 16);
        b[off + 2] = (byte) (value >> 8);
        b[off + 3] = (byte) value;
    }
}
