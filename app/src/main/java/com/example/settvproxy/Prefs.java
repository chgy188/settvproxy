package com.example.settvproxy;

import android.content.Context;
import android.content.SharedPreferences;

import java.util.HashSet;
import java.util.Set;

/**
 * 偏好存储：代理地址、认证、工作模式、协议、DNS、UDP 策略、应用过滤，重启后仍保留。
 */
public class Prefs {

    /** 系统 HTTP 代理模式（Settings.Global） */
    public static final int MODE_SYSTEM = 0;
    /** VpnService 全局模式（捕获全部 IPv4 流量） */
    public static final int MODE_VPN = 1;

    /** HTTP CONNECT 代理 */
    public static final int TYPE_HTTP = 0;
    /** SOCKS5 代理 */
    public static final int TYPE_SOCKS5 = 1;

    /** 丢弃 UDP（含 QUIC），强制应用回退到 TCP */
    public static final int UDP_DROP = 0;
    /** 通过 SOCKS5 UDP ASSOCIATE 转发 UDP（仅 SOCKS5 模式有效） */
    public static final int UDP_RELAY = 1;

    /** 所有应用都走 VPN（自身除外） */
    public static final int FILTER_NONE = 0;
    /** 选中的应用直连，不走 VPN */
    public static final int FILTER_EXCLUDE = 1;
    /** 仅选中的应用走 VPN */
    public static final int FILTER_ONLY = 2;

    /** VPN 状态：由 ProxyVpnService 写入，MainActivity 读取以显示启动结果 */
    public static final int VPN_STOPPED = 0;
    public static final int VPN_STARTING = 1;
    public static final int VPN_RUNNING = 2;
    public static final int VPN_FAILED = 3;

    private static final String NAME = "settvproxy_prefs";
    private static final String KEY_HOST = "host";
    private static final String KEY_PORT = "port";
    private static final String KEY_USER = "proxy_user";
    private static final String KEY_PASS = "proxy_pass";
    private static final String KEY_MODE = "mode";
    private static final String KEY_TYPE = "proxy_type";
    private static final String KEY_DNS = "dns";
    private static final String KEY_UDP_MODE = "udp_mode";
    private static final String KEY_FILTER_MODE = "filter_mode";
    private static final String KEY_APP_SET = "app_set";
    private static final String KEY_VPN_STATE = "vpn_state";
    private static final String KEY_VPN_ERROR = "vpn_error";
    private static final String KEY_DOMAIN_PASSTHROUGH = "domain_passthrough";

    public static final String DEFAULT_DNS = "8.8.8.8";

    private final SharedPreferences sp;

    public Prefs(Context context) {
        sp = context.getSharedPreferences(NAME, Context.MODE_PRIVATE);
    }

    public void save(String host, String port) {
        sp.edit()
                .putString(KEY_HOST, host)
                .putString(KEY_PORT, port)
                .apply();
    }

    public String getHost() {
        return sp.getString(KEY_HOST, "");
    }

    public String getPort() {
        return sp.getString(KEY_PORT, "");
    }

    /** 代理用户名，HTTP Basic 与 SOCKS5 用户密码认证共用 */
    public String getUser() {
        return sp.getString(KEY_USER, "");
    }

    public String getPass() {
        return sp.getString(KEY_PASS, "");
    }

    public void setCredentials(String user, String pass) {
        sp.edit().putString(KEY_USER, user).putString(KEY_PASS, pass).apply();
    }

    public boolean hasCredentials() {
        return getUser() != null && !getUser().isEmpty();
    }

    public int getMode() {
        return sp.getInt(KEY_MODE, MODE_SYSTEM);
    }

    public void setMode(int mode) {
        sp.edit().putInt(KEY_MODE, mode).apply();
    }

    public int getProxyType() {
        return sp.getInt(KEY_TYPE, TYPE_HTTP);
    }

    public void setProxyType(int type) {
        sp.edit().putInt(KEY_TYPE, type).apply();
    }

    public String getDns() {
        String dns = sp.getString(KEY_DNS, DEFAULT_DNS);
        return (dns == null || dns.trim().isEmpty()) ? DEFAULT_DNS : dns.trim();
    }

    public void setDns(String dns) {
        sp.edit().putString(KEY_DNS, dns).apply();
    }

    /** UDP 策略：默认开启 SOCKS5 UDP 转发，QUIC 不再被硬丢；HTTP 模式下自动退回丢弃 */
    public int getUdpMode() {
        return sp.getInt(KEY_UDP_MODE, UDP_RELAY);
    }

    public void setUdpMode(int mode) {
        sp.edit().putInt(KEY_UDP_MODE, mode).apply();
    }

    /** 实际生效的 UDP 策略：只有 SOCKS5 模式才允许转发 */
    public boolean isUdpRelayEnabled() {
        return getUdpMode() == UDP_RELAY && getProxyType() == TYPE_SOCKS5;
    }

    public int getFilterMode() {
        return sp.getInt(KEY_FILTER_MODE, FILTER_NONE);
    }

    public void setFilterMode(int mode) {
        sp.edit().putInt(KEY_FILTER_MODE, mode).apply();
    }

    public Set<String> getAppSet() {
        return new HashSet<>(sp.getStringSet(KEY_APP_SET, new HashSet<>()));
    }

    public void setAppSet(Set<String> packages) {
        sp.edit().putStringSet(KEY_APP_SET, new HashSet<>(packages)).apply();
    }

    public int getVpnState() {
        return sp.getInt(KEY_VPN_STATE, VPN_STOPPED);
    }

    public String getVpnError() {
        String e = sp.getString(KEY_VPN_ERROR, "");
        return (e == null) ? "" : e;
    }

    public void setVpnState(int state, String error) {
        sp.edit()
                .putInt(KEY_VPN_STATE, state)
                .putString(KEY_VPN_ERROR, (error == null) ? "" : error)
                .apply();
    }

    /** fake-IP + 域名透传，默认开启：由代理端远程解析并按域名分流 */
    public boolean isDomainPassthrough() {
        return sp.getBoolean(KEY_DOMAIN_PASSTHROUGH, true);
    }

    public void setDomainPassthrough(boolean enabled) {
        sp.edit().putBoolean(KEY_DOMAIN_PASSTHROUGH, enabled).apply();
    }
}
