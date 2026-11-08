package com.example.settvproxy;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.net.VpnService;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.widget.Button;
import android.widget.TextView;

/**
 * 首页只有一个一键开关和一个设置入口，所有配置都在 SettingsActivity。
 *
 * VPN 启动 / 关闭是异步的：结果由 ProxyVpnService 写入持久化状态，本页轮询确认。
 * 只有「本次点击一键开关」且确认成功后才自动 finish() 退出前台；失败会留在页面显示原因。
 */
public class MainActivity extends Activity {

    private static final int REQUEST_VPN = 1001;
    private static final long VPN_POLL_INTERVAL_MS = 400L;
    private static final long VPN_START_TIMEOUT_MS = 12000L;
    private static final long STOP_TIMEOUT_MS = 3000L;

    private TextView tvStatus;
    private TextView tvStatusDetail;
    private TextView tvMessage;
    private Button btnToggle;
    private Prefs prefs;

    private boolean pendingVpnStart;
    private boolean exitOnSuccess;
    private boolean vpnPollActive;
    private boolean stopPollActive;
    private long vpnStartAt;
    private long stopStartAt;

    private final Handler handler = new Handler(Looper.getMainLooper());

    private final Runnable vpnPoll = new Runnable() {
        @Override
        public void run() {
            if (!vpnPollActive) {
                return;
            }
            refreshStatus();
            int state = prefs.getVpnState();
            if (state == Prefs.VPN_RUNNING && ProxyVpnService.isRunning()) {
                vpnPollActive = false;
                showMessage(getString(R.string.msg_vpn_started));
                leaveOnSuccess();
                return;
            }
            if (state == Prefs.VPN_FAILED) {
                vpnPollActive = false;
                showMessage(getString(R.string.msg_vpn_failed, prefs.getVpnError()));
                return;
            }
            if (state == Prefs.VPN_STOPPED
                    || System.currentTimeMillis() - vpnStartAt > VPN_START_TIMEOUT_MS) {
                vpnPollActive = false;
                showMessage(getString(R.string.msg_vpn_timeout));
                return;
            }
            handler.postDelayed(this, VPN_POLL_INTERVAL_MS);
        }
    };

    private final Runnable stopPoll = new Runnable() {
        @Override
        public void run() {
            if (!stopPollActive) {
                return;
            }
            if (!ProxyVpnService.isRunning() && prefs.getVpnState() != Prefs.VPN_RUNNING) {
                stopPollActive = false;
                refreshStatus();
                showMessage(getString(R.string.msg_disabled));
                leaveOnSuccess();
                return;
            }
            if (System.currentTimeMillis() - stopStartAt > STOP_TIMEOUT_MS) {
                stopPollActive = false;
                showMessage(getString(R.string.msg_stop_timeout));
                return;
            }
            handler.postDelayed(this, 200L);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        prefs = new Prefs(this);
        tvStatus = findViewById(R.id.tvStatus);
        tvStatusDetail = findViewById(R.id.tvStatusDetail);
        tvMessage = findViewById(R.id.tvMessage);
        btnToggle = findViewById(R.id.btnToggle);

        btnToggle.setOnClickListener(v -> {
            if (isProxyOn()) {
                disableProxy();
            } else {
                enableProxy();
            }
        });
        findViewById(R.id.btnSettings).setOnClickListener(v ->
                startActivity(new Intent(this, SettingsActivity.class)));

        refreshStatus();
        btnToggle.requestFocus();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refreshStatus();
        int state = prefs.getVpnState();
        if (state == Prefs.VPN_STARTING) {
            showMessage(getString(R.string.msg_vpn_starting));
            startVpnPolling();
        } else if (state == Prefs.VPN_FAILED) {
            showMessage(getString(R.string.msg_vpn_failed, prefs.getVpnError()));
        }
    }

    @Override
    protected void onDestroy() {
        vpnPollActive = false;
        stopPollActive = false;
        handler.removeCallbacksAndMessages(null);
        super.onDestroy();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQUEST_VPN && pendingVpnStart) {
            pendingVpnStart = false;
            if (resultCode == RESULT_OK) {
                startVpn();
            } else {
                exitOnSuccess = false;
                prefs.setVpnState(Prefs.VPN_STOPPED, null);
                showMessage(getString(R.string.msg_vpn_cancel));
            }
        }
    }

    private boolean isProxyOn() {
        String proxy = ProxyManager.getCurrentProxy(this);
        return ProxyVpnService.isRunning() || (proxy != null && !proxy.isEmpty());
    }

    private void refreshStatus() {
        boolean vpn = ProxyVpnService.isRunning();
        String proxy = ProxyManager.getCurrentProxy(this);
        boolean on = vpn || (proxy != null && !proxy.isEmpty());

        tvStatus.setText(on ? R.string.status_running : R.string.status_stopped);
        tvStatus.setTextColor(on ? Color.parseColor("#66d18a") : Color.parseColor("#aaaaaa"));
        btnToggle.setText(on ? R.string.disable : R.string.enable);

        String type = getString(prefs.getProxyType() == Prefs.TYPE_SOCKS5
                ? R.string.type_socks5 : R.string.type_http);
        if (vpn) {
            tvStatusDetail.setText(getString(R.string.status_detail_vpn,
                    type, prefs.getHost(), prefs.getPort()));
        } else if (on) {
            tvStatusDetail.setText(getString(R.string.status_detail_system,
                    type, prefs.getHost(), prefs.getPort()));
        } else {
            tvStatusDetail.setText(R.string.status_detail_none);
        }
    }

    private void enableProxy() {
        String host = prefs.getHost().trim();
        int port = parsePort(prefs.getPort());
        if (host.isEmpty() || port <= 0 || port > 65535) {
            showMessage(getString(R.string.msg_config_missing));
            return;
        }

        exitOnSuccess = true;
        stopPollActive = false;
        handler.removeCallbacks(stopPoll);

        if (prefs.getMode() == Prefs.MODE_VPN) {
            // 避免两种模式叠加
            ProxyManager.clearProxy(this);
            Intent prepare = VpnService.prepare(this);
            if (prepare != null) {
                pendingVpnStart = true;
                showMessage(getString(R.string.msg_vpn_starting));
                startActivityForResult(prepare, REQUEST_VPN);
            } else {
                startVpn();
            }
            return;
        }

        if (ProxyVpnService.isRunning()) {
            stopVpn();
        }
        String err = ProxyManager.setProxy(this, host, port);
        if (err == null) {
            prefs.setVpnState(Prefs.VPN_STOPPED, null);
            refreshStatus();
            showMessage(getString(R.string.msg_enabled, host, prefs.getPort()));
            leaveOnSuccess();
        } else if ("permission".equals(err)) {
            showMessage(getString(R.string.msg_no_perm, getPackageName()));
        } else {
            showMessage("开启失败：" + err);
        }
    }

    private void disableProxy() {
        vpnPollActive = false;
        handler.removeCallbacks(vpnPoll);
        exitOnSuccess = true;

        boolean hadVpn = ProxyVpnService.isRunning();
        if (hadVpn) {
            stopVpn();
        }
        String err = ProxyManager.clearProxy(this);
        if (err != null && !"permission".equals(err)) {
            showMessage("关闭失败：" + err);
            return;
        }
        if (hadVpn) {
            stopPollActive = false;
            handler.removeCallbacks(stopPoll);
            stopStartAt = System.currentTimeMillis();
            stopPollActive = true;
            handler.postDelayed(stopPoll, 200L);
        } else {
            refreshStatus();
            showMessage(getString(R.string.msg_disabled));
            leaveOnSuccess();
        }
    }

    private void startVpn() {
        prefs.setVpnState(Prefs.VPN_STARTING, null);
        showMessage(getString(R.string.msg_vpn_starting));
        Intent intent = new Intent(this, ProxyVpnService.class)
                .setAction(ProxyVpnService.ACTION_CONNECT);
        // 由前台 Activity 启动，服务内部会立即转为前台服务
        startService(intent);
        vpnPollActive = false;
        handler.removeCallbacks(vpnPoll);
        startVpnPolling();
    }

    private void startVpnPolling() {
        if (vpnPollActive) {
            return;
        }
        vpnPollActive = true;
        vpnStartAt = System.currentTimeMillis();
        handler.postDelayed(vpnPoll, VPN_POLL_INTERVAL_MS);
    }

    private void stopVpn() {
        Intent intent = new Intent(this, ProxyVpnService.class)
                .setAction(ProxyVpnService.ACTION_DISCONNECT);
        startService(intent);
    }

    /** 仅在本次一键开关确认成功后退出前台 */
    private void leaveOnSuccess() {
        if (exitOnSuccess) {
            exitOnSuccess = false;
            finish();
        }
    }

    private static int parsePort(String s) {
        try {
            return Integer.parseInt(s.trim());
        } catch (Exception e) {
            return -1;
        }
    }

    private void showMessage(String msg) {
        tvMessage.setText(msg);
    }
}
