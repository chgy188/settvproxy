package com.example.settvproxy;

import android.app.Activity;
import android.content.Intent;
import android.os.Bundle;
import android.widget.Button;
import android.widget.EditText;
import android.widget.TextView;

/**
 * 统一设置页：首页所有配置都集中在这里，点击切换类按钮即时保存，输入框在离开页面时保存。
 */
public class SettingsActivity extends Activity {

    private EditText etHost;
    private EditText etPort;
    private EditText etDns;
    private EditText etUser;
    private EditText etPass;
    private Button btnMode;
    private Button btnType;
    private Button btnDomain;
    private Button btnUdpMode;
    private Button btnAppFilter;
    private TextView tvMessage;
    private Prefs prefs;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_settings);

        prefs = new Prefs(this);
        etHost = findViewById(R.id.etHost);
        etPort = findViewById(R.id.etPort);
        etDns = findViewById(R.id.etDns);
        etUser = findViewById(R.id.etUser);
        etPass = findViewById(R.id.etPass);
        btnMode = findViewById(R.id.btnMode);
        btnType = findViewById(R.id.btnType);
        btnDomain = findViewById(R.id.btnDomain);
        btnUdpMode = findViewById(R.id.btnUdpMode);
        btnAppFilter = findViewById(R.id.btnAppFilter);
        tvMessage = findViewById(R.id.tvMessage);

        etHost.setText(prefs.getHost());
        etPort.setText(prefs.getPort());
        etDns.setText(prefs.getDns());
        etUser.setText(prefs.getUser());
        etPass.setText(prefs.getPass());

        btnMode.setOnClickListener(v -> {
            int next = (prefs.getMode() == Prefs.MODE_VPN)
                    ? Prefs.MODE_SYSTEM : Prefs.MODE_VPN;
            prefs.setMode(next);
            refresh();
            showMessage(getString(R.string.mode_label) + labelForMode(next));
        });

        btnType.setOnClickListener(v -> {
            int next = (prefs.getProxyType() == Prefs.TYPE_SOCKS5)
                    ? Prefs.TYPE_HTTP : Prefs.TYPE_SOCKS5;
            // 切到 HTTP 时 UDP 转发不再可用，同步复位避免设置与实际生效状态不一致
            if (next == Prefs.TYPE_HTTP && prefs.getUdpMode() == Prefs.UDP_RELAY) {
                prefs.setUdpMode(Prefs.UDP_DROP);
            }
            prefs.setProxyType(next);
            refresh();
            showMessage(getString(R.string.type_label) + labelForType(next));
        });

        btnDomain.setOnClickListener(v -> {
            boolean next = !prefs.isDomainPassthrough();
            prefs.setDomainPassthrough(next);
            refresh();
            showMessage(getString(next ? R.string.domain_on : R.string.domain_off));
        });

        btnUdpMode.setOnClickListener(v -> {
            int next = (prefs.getUdpMode() == Prefs.UDP_RELAY)
                    ? Prefs.UDP_DROP : Prefs.UDP_RELAY;
            if (next == Prefs.UDP_RELAY && prefs.getProxyType() != Prefs.TYPE_SOCKS5) {
                showMessage(getString(R.string.msg_udp_http_only));
                return;
            }
            prefs.setUdpMode(next);
            refresh();
            showMessage(getString(next == Prefs.UDP_RELAY
                    ? R.string.udp_relay : R.string.udp_drop));
        });

        btnAppFilter.setOnClickListener(v ->
                startActivity(new Intent(this, AppPickerActivity.class)));

        Button btnBack = findViewById(R.id.btnBack);
        btnBack.setOnClickListener(v -> {
            save();
            finish();
        });

        refresh();
        etHost.requestFocus();
    }

    @Override
    protected void onResume() {
        super.onResume();
        refresh();
    }

    @Override
    protected void onPause() {
        save();
        super.onPause();
    }

    private void save() {
        prefs.save(etHost.getText().toString().trim(), etPort.getText().toString().trim());
        prefs.setDns(etDns.getText().toString().trim());
        prefs.setCredentials(etUser.getText().toString().trim(), etPass.getText().toString());
    }

    private void refresh() {
        btnMode.setText(labelForMode(prefs.getMode()));
        btnType.setText(labelForType(prefs.getProxyType()));
        btnDomain.setText(prefs.isDomainPassthrough()
                ? R.string.domain_on : R.string.domain_off);
        btnUdpMode.setText(prefs.getUdpMode() == Prefs.UDP_RELAY
                ? R.string.udp_relay : R.string.udp_drop);

        int count = prefs.getAppSet().size();
        if (count == 0) {
            btnAppFilter.setText(R.string.filter_none);
        } else if (prefs.getFilterMode() == Prefs.FILTER_EXCLUDE) {
            btnAppFilter.setText(getString(R.string.filter_exclude, count));
        } else if (prefs.getFilterMode() == Prefs.FILTER_ONLY) {
            btnAppFilter.setText(getString(R.string.filter_only, count));
        } else {
            btnAppFilter.setText(R.string.filter_none);
        }
    }

    private String labelForMode(int mode) {
        return getString(mode == Prefs.MODE_VPN ? R.string.mode_vpn : R.string.mode_system);
    }

    private String labelForType(int type) {
        return getString(type == Prefs.TYPE_SOCKS5 ? R.string.type_socks5 : R.string.type_http);
    }

    private void showMessage(String msg) {
        tvMessage.setText(msg);
    }
}
