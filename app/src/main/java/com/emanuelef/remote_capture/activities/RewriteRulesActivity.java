/*
 * This file is part of PCAPdroid.
 *
 * PCAPdroid is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * PCAPdroid is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with PCAPdroid.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Copyright 2026 - antoniojacksonsilvad-cloud
 */

package com.emanuelef.remote_capture.activities;

import android.app.Activity;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.provider.OpenableColumns;
import android.view.LayoutInflater;
import android.view.View;
import android.widget.ImageButton;
import android.widget.LinearLayout;
import android.widget.TextView;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.widget.SwitchCompat;
import androidx.core.content.ContextCompat;
import androidx.preference.PreferenceManager;

import com.emanuelef.remote_capture.CaptureHelper;
import com.emanuelef.remote_capture.CaptureService;
import com.emanuelef.remote_capture.Log;
import com.emanuelef.remote_capture.MitmAddon;
import com.emanuelef.remote_capture.R;
import com.emanuelef.remote_capture.Utils;
import com.emanuelef.remote_capture.VpnReconnectService;
import com.emanuelef.remote_capture.interfaces.MitmListener;
import com.emanuelef.remote_capture.model.CaptureSettings;
import com.emanuelef.remote_capture.model.Prefs;
import com.emanuelef.remote_capture.model.RewriteFiles;
import com.emanuelef.remote_capture.model.RewriteXmlParser;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/* Screen to manage the XML files with the HTTP response rewrite rules.
 * The rules are parsed and enforced by the mitmproxy addon: this screen only
 * stores them, shows them and controls the capture. */
public class RewriteRulesActivity extends BaseActivity {
    private static final String TAG = "RewriteRulesActivity";

    // the XML documents are sent to the addon inside a Messenger bundle, keep
    // them well below the binder transaction limit
    private static final int MAX_RULES_SIZE = 512 * 1024;

    private static final long POLL_INTERVAL = 1000;

    private final ActivityResultLauncher<Intent> mFileLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(), this::fileResult);

    private SharedPreferences mPrefs;
    private RewriteFiles mFiles;
    private CaptureHelper mCapHelper;

    private SwitchCompat mMasterSwitch;
    private View mMasterHint;
    private LinearLayout mFilesLayout;
    private TextView mFilesTitle;
    private View mEmptyView;
    private View mEmptyHint;
    private TextView mCaptureStatus;
    private ImageButton mPlayButton;

    private final Handler mHandler = new Handler(Looper.getMainLooper());
    private final Runnable mPoll = new Runnable() {
        @Override
        public void run() {
            refreshCaptureState();
            mHandler.postDelayed(this, POLL_INTERVAL);
        }
    };

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.rewrite_rules_activity);

        setSupportActionBar(findViewById(R.id.toolbar));
        setTitle(R.string.rewrite_rules);
        displayBackAction();

        mPrefs = PreferenceManager.getDefaultSharedPreferences(this);
        mFiles = new RewriteFiles(mPrefs);
        mCapHelper = new CaptureHelper(this);

        mMasterSwitch = findViewById(R.id.rewrite_master_switch);
        mMasterHint = findViewById(R.id.rewrite_master_hint);
        mFilesLayout = findViewById(R.id.rewrite_files);
        mFilesTitle = findViewById(R.id.rewrite_files_title);
        mEmptyView = findViewById(R.id.rewrite_empty);
        mEmptyHint = findViewById(R.id.rewrite_empty_hint);
        mCaptureStatus = findViewById(R.id.rewrite_capture_status);
        mPlayButton = findViewById(R.id.rewrite_play);

        mMasterSwitch.setChecked(mFiles.isEnabled());
        mMasterSwitch.setOnCheckedChangeListener((btn, checked) -> {
            mFiles.setEnabled(checked);
            refreshMasterHint();
            pushRulesToAddon();
        });

        findViewById(R.id.rewrite_import).setOnClickListener(v -> pickFile());
        findViewById(R.id.rewrite_clear).setOnClickListener(v -> confirmClear());
        mPlayButton.setOnClickListener(v -> onPlayClicked());

        refreshUI();
    }

    @Override
    protected void onResume() {
        super.onResume();
        mHandler.post(mPoll);
    }

    @Override
    protected void onPause() {
        mHandler.removeCallbacks(mPoll);
        super.onPause();
    }

    private void refreshUI() {
        refreshMasterHint();

        mFilesTitle.setText(getString(R.string.rewrite_files_title, mFiles.size()));
        int empty = mFiles.isEmpty() ? View.VISIBLE : View.GONE;
        mEmptyView.setVisibility(empty);
        mEmptyHint.setVisibility(empty);

        mFilesLayout.removeAllViews();
        LayoutInflater inflater = LayoutInflater.from(this);

        for (int i = 0; i < mFiles.size(); i++)
            mFilesLayout.addView(buildFileCard(inflater, mFiles.get(i), i));
    }

    private View buildFileCard(LayoutInflater inflater, RewriteFiles.Entry entry, int pos) {
        View card = inflater.inflate(R.layout.rewrite_file_item, mFilesLayout, false);

        TextView name = card.findViewById(R.id.file_name);
        TextView count = card.findViewById(R.id.file_count);
        View header = card.findViewById(R.id.file_header);
        SwitchCompat fileSwitch = card.findViewById(R.id.file_switch);
        View delete = card.findViewById(R.id.file_delete);
        LinearLayout rules = card.findViewById(R.id.file_rules);

        name.setText(entry.name.isEmpty() ? getString(R.string.rewrite_none) : entry.name);

        RewriteXmlParser.Result parsed = RewriteXmlParser.parse(entry.xml);
        int num = parsed.count();
        count.setText(num == 1
                ? getString(R.string.rewrite_one_rule, num)
                : getString(R.string.rewrite_rules_count, num));

        // the rules are shown by default, tapping the header collapses them
        buildRules(inflater, rules, parsed);

        fileSwitch.setChecked(entry.enabled);
        fileSwitch.setOnCheckedChangeListener((btn, checked) -> {
            mFiles.setEntryEnabled(pos, checked);
            pushRulesToAddon();
        });

        delete.setOnClickListener(v -> confirmRemove(entry, pos));

        header.setOnClickListener(v -> {
            boolean visible = (rules.getVisibility() == View.VISIBLE);
            rules.setVisibility(visible ? View.GONE : View.VISIBLE);
        });

        return card;
    }

    private void buildRules(LayoutInflater inflater, LinearLayout container, RewriteXmlParser.Result parsed) {
        container.removeAllViews();

        for (RewriteXmlParser.Rule rule : parsed.rules) {
            View view = inflater.inflate(R.layout.rewrite_rule_item, container, false);

            TextView pattern = view.findViewById(R.id.rule_pattern);
            TextView status = view.findViewById(R.id.rule_status);
            TextView headers = view.findViewById(R.id.rule_headers);
            TextView body = view.findViewById(R.id.rule_body);

            pattern.setText(rule.pattern);

            if (rule.status > 0) {
                status.setVisibility(View.VISIBLE);
                status.setText(getString(R.string.rewrite_status, rule.status));
            }

            if (!rule.headers.isEmpty()) {
                StringBuilder sb = new StringBuilder();
                for (String[] header : rule.headers) {
                    if (sb.length() > 0)
                        sb.append('\n');
                    sb.append(getString(R.string.rewrite_header, header[0], header[1]));
                }

                headers.setVisibility(View.VISIBLE);
                headers.setText(sb.toString());
            }

            if (rule.hasBody()) {
                body.setVisibility(View.VISIBLE);
                String text = rule.body.trim();
                body.setText(getString(R.string.rewrite_body, text.isEmpty()
                        ? getString(R.string.rewrite_body_empty) : text));
            }
        }
    }

    private void refreshMasterHint() {
        mMasterHint.setVisibility(mFiles.isEnabled() ? View.GONE : View.VISIBLE);
    }

    // ----- import

    private void pickFile() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{
                "text/xml", "application/xml", "text/plain", "*/*"
        });

        try {
            mFileLauncher.launch(intent);
        } catch (Exception e) {
            Log.w(TAG, "Cannot open the file picker: " + e);
        }
    }

    private void fileResult(ActivityResult result) {
        if (result.getResultCode() != Activity.RESULT_OK)
            return;

        Uri uri = result.getData() != null ? result.getData().getData() : null;
        if (uri == null) {
            Log.w(TAG, "null file uri");
            Utils.showToastLong(this, R.string.rewrite_import_failed);
            return;
        }

        String content;
        try {
            content = readFile(uri);
        } catch (FileTooLargeException e) {
            Log.w(TAG, "The rewrite file is too large");
            Utils.showToastLong(this, R.string.rewrite_too_big, MAX_RULES_SIZE / 1024);
            return;
        } catch (IOException | OutOfMemoryError e) {
            Log.e(TAG, "Error reading the rewrite file: " + e);
            Utils.showToastLong(this, R.string.rewrite_import_failed);
            return;
        }

        if (content.trim().isEmpty()) {
            Utils.showToastLong(this, R.string.rewrite_import_failed);
            return;
        }

        // NOTE: the rules are only parsed by the addon, store them as they are
        String name = getFileName(uri);
        mFiles.add(name, content);
        pushRulesToAddon();

        refreshUI();
        Utils.showToastLong(this, R.string.rewrite_imported, name, mFiles.get(mFiles.size() - 1).getRuleCount());
    }

    /* Raised when the file does not fit in the size allowed for the rules */
    private static class FileTooLargeException extends IOException {}

    private String readFile(Uri uri) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try (InputStream istream = getContentResolver().openInputStream(uri)) {
            if (istream == null)
                throw new IOException("null input stream");

            byte[] buf = new byte[8192];
            int len;
            while ((len = istream.read(buf)) > 0) {
                if (baos.size() + len > MAX_RULES_SIZE)
                    throw new FileTooLargeException();

                baos.write(buf, 0, len);
            }
        }

        return new String(baos.toByteArray(), StandardCharsets.UTF_8);
    }

    private String getFileName(Uri uri) {
        try (Cursor cursor = getContentResolver().query(uri, null, null, null, null)) {
            if ((cursor != null) && cursor.moveToFirst()) {
                int idx = cursor.getColumnIndex(OpenableColumns.DISPLAY_NAME);
                if (idx >= 0) {
                    String name = cursor.getString(idx);
                    if ((name != null) && !name.isEmpty())
                        return name;
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Could not get the file name: " + e);
        }

        return "";
    }

    // ----- remove

    private void confirmClear() {
        if (mFiles.isEmpty())
            return;

        new AlertDialog.Builder(this)
                .setMessage(R.string.rewrite_clear_confirm)
                .setPositiveButton(R.string.ok, (dialog, which) -> {
                    mFiles.clear();
                    pushRulesToAddon();
                    refreshUI();
                    Utils.showToastLong(this, R.string.rewrite_cleared);
                })
                .setNegativeButton(R.string.cancel_action, null)
                .show();
    }

    private void confirmRemove(RewriteFiles.Entry entry, int pos) {
        new AlertDialog.Builder(this)
                .setMessage(getString(R.string.rewrite_remove_confirm, entry.name))
                .setPositiveButton(R.string.ok, (dialog, which) -> {
                    mFiles.remove(pos);
                    pushRulesToAddon();
                    refreshUI();
                })
                .setNegativeButton(R.string.cancel_action, null)
                .show();
    }

    // ----- send the rules to the addon

    /* Sends the enabled rules to the running addon, so that the changes are
     * applied without restarting the capture. If the capture is not running,
     * the rules are sent by MitmReceiver when the proxy starts. */
    private void pushRulesToAddon() {
        if (!CaptureService.isServiceActive())
            return;

        if (!Prefs.getTlsDecryptionEnabled(mPrefs))
            return;

        try {
            MitmAddon addon = new MitmAddon(getApplicationContext(), mMitmListener);
            if (!addon.connect(0)) {
                Log.w(TAG, "Cannot connect to the mitm addon");
                return;
            }

            // the rules are sent and the binding released in the callbacks
            mPendingAddon = addon;
        } catch (Exception e) {
            Log.w(TAG, "Cannot reach the mitm addon: " + e);
            mPendingAddon = null;
        }
    }

    private MitmAddon mPendingAddon;

    private final MitmListener mMitmListener = new MitmListener() {
        @Override
        public void onMitmGetCaCertificateResult(@Nullable String ca_pem) {
            // not needed here
        }

        @Override
        public void onMitmServiceConnect() {
            if (mPendingAddon == null)
                return;

            mPendingAddon.setRewriteRules(mFiles.getEnabledXmls());
            mPendingAddon.disconnect();
            mPendingAddon = null;
        }

        @Override
        public void onMitmServiceDisconnect() {
            mPendingAddon = null;
        }
    };

    // ----- capture control

    private void onPlayClicked() {
        if (CaptureService.isServiceActive())
            stopCapture();
        else
            startCapture();
    }

    private void startCapture() {
        if (VpnReconnectService.isAvailable())
            VpnReconnectService.stopService();

        if (Prefs.getTlsDecryptionEnabled(mPrefs)) {
            if (MitmAddon.needsSetup(this)) {
                Utils.startActivity(this, new Intent(this, MitmSetupWizard.class));
                return;
            }

            // the rules are enforced by the addon, it must be up to date
            String new_version = MitmAddon.getNewVersionAvailable(this);
            if (!new_version.isEmpty()) {
                Utils.showToast(this, R.string.mitm_addon_update_available);
                Utils.startActivity(this, new Intent(this, MitmSetupWizard.class));
                return;
            }
        }

        if (!Prefs.isRootCaptureEnabled(mPrefs) && (Utils.getRunningVpn(this) != null)) {
            new AlertDialog.Builder(this)
                    .setMessage(R.string.disconnect_vpn_confirm)
                    .setPositiveButton(R.string.ok, (dialog, which) -> doStartCapture())
                    .setNegativeButton(R.string.cancel_action, null)
                    .show();
        } else
            doStartCapture();
    }

    private void doStartCapture() {
        CaptureSettings settings = new CaptureSettings(this, mPrefs);

        // the rewritten body is only visible if the full payload is captured
        settings.full_payload = true;

        mCapHelper.startCapture(settings);
    }

    private void stopCapture() {
        CaptureService.stopService();
    }

    private void refreshCaptureState() {
        boolean running = CaptureService.isServiceActive();

        mCaptureStatus.setText(running
                ? R.string.rewrite_capture_running
                : R.string.rewrite_capture_stopped);
        mCaptureStatus.setTextColor(ContextCompat.getColor(this,
                running ? R.color.rewriteOk : R.color.rewriteTextDim));

        mPlayButton.setImageResource(running ? R.drawable.ic_media_stop : R.drawable.ic_play_arrow);
        mPlayButton.setBackgroundTintList(ColorStateList.valueOf(ContextCompat.getColor(this,
                running ? R.color.rewriteDanger : R.color.rewriteCyan)));
        mPlayButton.setContentDescription(getString(running
                ? R.string.rewrite_capture_stop : R.string.rewrite_capture_start));
    }
}
