package com.example.settvproxy;

import android.content.ContentResolver;
import android.content.Context;
import android.net.ProxyInfo;
import android.net.wifi.WifiConfiguration;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.provider.Settings;
import android.text.TextUtils;
import android.util.Log;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Arrays;
import java.util.List;

/**
 * 代理管理器。
 *
 * 现代 Android（尤其是 Android 10+）出于安全限制，普通应用无法直接修改系统全局代理。
 * 本类采用「主方案 + 备用方案」两种思路，最大限度兼容不同设备：
 *
 * 主方案：通过 {@link Settings.Global} 写入全局代理。
 *   需要 {@code WRITE_SECURE_SETTINGS} 权限——该权限需在电脑上用 adb 一次性授予，
 *   授予后普通侧载应用即可一键控制系统全局代理，localhost 默认不走代理。
 *
 * 备用方案：通过反射修改当前 WiFi 网络的代理配置（隐藏 API）。
 *   对部分旧系统 / 已 root 设备有效，受 Android 10+ 限制可能失效。
 *
 * 所有方法均捕获异常，不会让界面崩溃；返回 null 表示成功，否则返回错误标识。
 */
public final class ProxyManager {

    private static final String TAG = "ProxyManager";

    /** 不走代理的例外列表：localhost 与回环地址 */
    private static final List<String> EXCLUSIONS = Arrays.asList("localhost", "127.0.0.1");

    private ProxyManager() {
    }

    /**
     * 开启手动代理。
     *
     * @return null 成功；"permission" 无权限；其它字符串为具体错误
     */
    public static String setProxy(Context context, String host, int port) {
        // 1) 主方案：系统全局代理
        String err = setGlobalProxy(context, host, port, true);
        if (err == null) {
            return null;
        }
        if (!"permission".equals(err)) {
            // 非权限类错误（如 Settings 写入异常），尝试备用方案
            Log.w(TAG, "global proxy failed, try wifi fallback: " + err);
            String wifiErr = setWifiProxy(context, host, port, true);
            if (wifiErr == null) {
                return null;
            }
        }
        return err;
    }

    /**
     * 关闭代理（无）。
     *
     * @return null 成功；"permission" 无权限；其它字符串为具体错误
     */
    public static String clearProxy(Context context) {
        String err = setGlobalProxy(context, "", 0, false);
        if (err == null) {
            return null;
        }
        if (!"permission".equals(err)) {
            String wifiErr = setWifiProxy(context, "", 0, false);
            if (wifiErr == null) {
                return null;
            }
        }
        return err;
    }

    /** 读取当前全局代理字符串，例如 "192.168.1.100:7890"；无则返回空串 */
    public static String getCurrentProxy(Context context) {
        try {
            String proxy = Settings.Global.getString(context.getContentResolver(), "http_proxy");
            return (proxy == null) ? "" : proxy;
        } catch (Throwable t) {
            Log.e(TAG, "getCurrentProxy failed", t);
            return "";
        }
    }

    // ---------- 主方案：Settings.Global ----------

    private static String setGlobalProxy(Context context, String host, int port, boolean enable) {
        try {
            ContentResolver cr = context.getContentResolver();
            if (enable) {
                String proxy = host + ":" + port;
                Settings.Global.putString(cr, "http_proxy", proxy);
                Settings.Global.putString(cr, "global_http_proxy_host", host);
                Settings.Global.putString(cr, "global_http_proxy_port", String.valueOf(port));
                Settings.Global.putString(cr, "global_http_proxy_exclusion_list",
                        TextUtils.join(";", EXCLUSIONS));
            } else {
                Settings.Global.putString(cr, "http_proxy", "");
                Settings.Global.putString(cr, "global_http_proxy_host", "");
                Settings.Global.putString(cr, "global_http_proxy_port", "0");
                Settings.Global.putString(cr, "global_http_proxy_exclusion_list", "");
            }
            return null;
        } catch (SecurityException e) {
            Log.e(TAG, "no WRITE_SECURE_SETTINGS permission", e);
            return "permission";
        } catch (Throwable t) {
            Log.e(TAG, "setGlobalProxy failed", t);
            return t.getMessage();
        }
    }

    // ---------- 备用方案：反射 WiFi 配置 ----------

    private static String setWifiProxy(Context context, String host, int port, boolean enable) {
        try {
            WifiManager wifiManager =
                    (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
            if (wifiManager == null) {
                return "no_wifi_manager";
            }

            WifiInfo wifiInfo = wifiManager.getConnectionInfo();
            if (wifiInfo == null) {
                return "no_connection";
            }

            List<WifiConfiguration> configs = wifiManager.getConfiguredNetworks();
            if (configs == null) {
                return "no_configs";
            }

            WifiConfiguration target = null;
            int networkId = wifiInfo.getNetworkId();
            for (WifiConfiguration cfg : configs) {
                if (cfg.networkId == networkId) {
                    target = cfg;
                    break;
                }
            }
            if (target == null) {
                return "no_target";
            }

            // WifiConfiguration.httpProxy 为隐藏字段，通过反射写入
            Field httpProxyField = WifiConfiguration.class.getField("httpProxy");
            if (enable) {
                ProxyInfo proxyInfo = ProxyInfo.buildDirectProxy(host, port, EXCLUSIONS);
                httpProxyField.set(target, proxyInfo);
            } else {
                httpProxyField.set(target, null);
            }

            int updateResult = wifiManager.updateNetwork(target);
            if (updateResult == -1) {
                // 部分 ROM 需要显式保存
                try {
                    Method saveMethod = wifiManager.getClass().getMethod("saveConfiguration");
                    saveMethod.invoke(wifiManager);
                } catch (Throwable ignore) {
                    return "update_failed";
                }
            } else {
                // 重新关联使代理配置生效
                wifiManager.disconnect();
                wifiManager.reconnect();
            }
            return null;
        } catch (SecurityException e) {
            Log.e(TAG, "wifi proxy no permission", e);
            return "permission";
        } catch (Throwable t) {
            Log.e(TAG, "setWifiProxy failed", t);
            return t.getMessage();
        }
    }
}
