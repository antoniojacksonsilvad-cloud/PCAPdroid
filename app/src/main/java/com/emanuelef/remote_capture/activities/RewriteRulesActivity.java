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
import android.database.Cursor;
import android.net.Uri;
import android.os.Bundle;
import android.provider.OpenableColumns;
import android.widget.Button;
import android.widget.TextView;

import androidx.activity.result.ActivityResult;
import androidx.activity.result.ActivityResultLauncher;
import androidx.activity.result.contract.ActivityResultContracts;
import androidx.preference.PreferenceManager;

import com.emanuelef.remote_capture.Log;
import com.emanuelef.remote_capture.R;
import com.emanuelef.remote_capture.Utils;
import com.emanuelef.remote_capture.model.Prefs;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/* Activity to import the XML rules used to rewrite the HTTP responses.
 * The rules are parsed by the mitmproxy addon, which is the one actually
 * rewriting the traffic: this activity only stores the XML. */
public class RewriteRulesActivity extends BaseActivity {
    private static final String TAG = "RewriteRulesActivity";

    // the XML is sent to the addon inside a Messenger bundle, keep it well
    // below the binder transaction limit
    private static final int MAX_RULES_SIZE = 512 * 1024;

    private final ActivityResultLauncher<Intent> mFileLauncher = registerForActivityResult(
            new ActivityResultContracts.StartActivityForResult(), this::fileResult);

    private SharedPreferences mPrefs;
    private TextView mStatus;
    private Button mRemove;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.rewrite_rules_activity);

        setSupportActionBar(findViewById(R.id.toolbar));
        setTitle(R.string.rewrite_rules);
        displayBackAction();

        mPrefs = PreferenceManager.getDefaultSharedPreferences(this);
        mStatus = findViewById(R.id.rewrite_status);
        mRemove = findViewById(R.id.rewrite_remove);

        findViewById(R.id.rewrite_import).setOnClickListener(v -> pickFile());
        mRemove.setOnClickListener(v -> removeRules());

        refreshUI();
    }

    private void pickFile() {
        Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        intent.addCategory(Intent.CATEGORY_OPENABLE);
        intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{
                "text/xml", "application/xml", "text/plain", "*/*"
        });

        mFileLauncher.launch(intent);
    }

    private void fileResult(ActivityResult result) {
        if (result.getResultCode() != Activity.RESULT_OK)
            return;

        Uri uri = result.getData() != null ? result.getData().getData() : null;
        if (uri == null) {
            Log.w(TAG, "null file uri");
            Utils.showToastLong(this, R.string.rewrite_rules_import_failed);
            return;
        }

        String content;
        try {
            content = readFile(uri);
        } catch (IOException | OutOfMemoryError e) {
            Log.e(TAG, "Error reading the rewrite rules: " + e);
            Utils.showToastLong(this, R.string.rewrite_rules_import_failed);
            return;
        }

        if (content.isEmpty()) {
            Utils.showToastLong(this, R.string.rewrite_rules_import_failed);
            return;
        }

        // NOTE: the rules are only parsed by the addon, store them as they are
        Prefs.setRewriteRulesXml(mPrefs, content);
        Prefs.setRewriteRulesName(mPrefs, getFileName(uri));

        refreshUI();
        Utils.showToastLong(this, R.string.rewrite_rules_imported,
                content.length(), getFileName(uri));
    }

    private String readFile(Uri uri) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        try (InputStream istream = getContentResolver().openInputStream(uri)) {
            if (istream == null)
                throw new IOException("null input stream");

            byte[] buf = new byte[8192];
            int len;
            while ((len = istream.read(buf)) > 0) {
                if (baos.size() + len > MAX_RULES_SIZE)
                    throw new IOException("the rules file is too large");

                baos.write(buf, 0, len);
            }
        }

        return new String(baos.toByteArray(), StandardCharsets.UTF_8);
    }

    private void removeRules() {
        Prefs.setRewriteRulesXml(mPrefs, "");
        Prefs.setRewriteRulesName(mPrefs, "");

        refreshUI();
        Utils.showToastLong(this, R.string.rewrite_rules_removed);
    }

    private void refreshUI() {
        String xml = Prefs.getRewriteRulesXml(mPrefs);
        String name = Prefs.getRewriteRulesName(mPrefs);

        if (xml.isEmpty()) {
            mStatus.setText(R.string.rewrite_rules_none);
            mRemove.setEnabled(false);
        } else {
            mStatus.setText(getString(R.string.rewrite_rules_loaded, name, xml.length()));
            mRemove.setEnabled(true);
        }
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
}
