package com.example.settvproxy;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Bundle;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * 应用过滤选择页。
 *
 * 用动态 Button 列表而非 ListView：Button 天然可聚焦，配合 focus_bg 高亮，
 * 遥控器上下移动 + 确定键勾选即可，无需处理触摸/选择态差异。
 */
public class AppPickerActivity extends Activity {

    private static final class AppInfo {
        final String pkg;
        final String label;

        AppInfo(String pkg, String label) {
            this.pkg = pkg;
            this.label = label;
        }
    }

    private Prefs prefs;
    private Set<String> selected;
    private Button btnFilterMode;
    private LinearLayout appList;
    private final List<AppInfo> apps = new ArrayList<>();

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_app_picker);

        prefs = new Prefs(this);
        selected = prefs.getAppSet();
        btnFilterMode = findViewById(R.id.btnFilterMode);
        appList = findViewById(R.id.appList);

        btnFilterMode.setOnClickListener(v -> {
            int current = prefs.getFilterMode();
            int next = (current == Prefs.FILTER_NONE) ? Prefs.FILTER_EXCLUDE
                    : (current == Prefs.FILTER_EXCLUDE) ? Prefs.FILTER_ONLY
                    : Prefs.FILTER_NONE;
            prefs.setFilterMode(next);
            refreshModeLabel();
        });
        findViewById(R.id.btnBack).setOnClickListener(v -> finish());

        loadApps();
        buildRows();
        refreshModeLabel();
    }

    private void loadApps() {
        PackageManager pm = getPackageManager();
        Map<String, String> byPackage = new HashMap<>();

        Intent launcher = new Intent(Intent.ACTION_MAIN)
                .addCategory(Intent.CATEGORY_LAUNCHER);
        for (ResolveInfo r : pm.queryIntentActivities(launcher, 0)) {
            collect(byPackage, pm, r);
        }
        Intent tvLauncher = new Intent(Intent.ACTION_MAIN)
                .addCategory(Intent.CATEGORY_LEANBACK_LAUNCHER);
        for (ResolveInfo r : pm.queryIntentActivities(tvLauncher, 0)) {
            collect(byPackage, pm, r);
        }
        byPackage.remove(getPackageName());

        List<Map.Entry<String, String>> entries = new ArrayList<>(byPackage.entrySet());
        Collections.sort(entries, new Comparator<Map.Entry<String, String>>() {
            @Override
            public int compare(Map.Entry<String, String> a, Map.Entry<String, String> b) {
                return a.getValue().compareToIgnoreCase(b.getValue());
            }
        });
        for (Map.Entry<String, String> e : entries) {
            apps.add(new AppInfo(e.getKey(), e.getValue()));
        }
    }

    private void collect(Map<String, String> byPackage, PackageManager pm, ResolveInfo info) {
        if (info.activityInfo == null) {
            return;
        }
        String pkg = info.activityInfo.packageName;
        CharSequence label = info.loadLabel(pm);
        byPackage.put(pkg, (label == null || label.length() == 0) ? pkg : label.toString());
    }

    private void buildRows() {
        if (apps.isEmpty()) {
            TextView empty = new TextView(this);
            empty.setText(R.string.app_picker_empty);
            empty.setTextSize(20);
            appList.addView(empty);
            btnFilterMode.requestFocus();
            return;
        }
        for (final AppInfo app : apps) {
            final Button row = new Button(this);
            row.setBackgroundResource(R.drawable.focus_bg);
            row.setFocusable(true);
            row.setAllCaps(false);
            row.setTextSize(18);
            row.setPadding(16, 12, 16, 12);
            LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT);
            lp.bottomMargin = 6;
            row.setLayoutParams(lp);
            row.setText(rowText(app));
            row.setOnClickListener(v -> {
                if (selected.contains(app.pkg)) {
                    selected.remove(app.pkg);
                } else {
                    selected.add(app.pkg);
                }
                prefs.setAppSet(selected);
                row.setText(rowText(app));
            });
            appList.addView(row);
        }
        appList.getChildAt(0).requestFocus();
    }

    private String rowText(AppInfo app) {
        return (selected.contains(app.pkg) ? "[✓] " : "[  ] ")
                + app.label + "  (" + app.pkg + ")";
    }

    private void refreshModeLabel() {
        int mode = prefs.getFilterMode();
        btnFilterMode.setText(mode == Prefs.FILTER_EXCLUDE
                ? R.string.filter_mode_exclude
                : mode == Prefs.FILTER_ONLY
                ? R.string.filter_mode_only
                : R.string.filter_mode_none);
    }
}
