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

package com.emanuelef.remote_capture.model;

import android.content.SharedPreferences;

import androidx.annotation.NonNull;

import com.emanuelef.remote_capture.Log;
import com.google.gson.Gson;
import com.google.gson.JsonParseException;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

/* Stores the XML files with the rewrite rules, each one with its own enabled
 * state, plus the master switch which enables/disables the whole rewriting.
 * Only the content of the enabled files is sent to the mitmproxy addon. */
public class RewriteFiles {
    private static final String TAG = "RewriteFiles";

    public static class Entry {
        public String name;
        public String xml;

        // NOTE: Gson does not call the constructor, the default is applied
        // only when the field is missing from the serialized JSON
        public boolean enabled = true;

        public int getRuleCount() {
            return RewriteXmlParser.countRules(xml);
        }
    }

    private final SharedPreferences mPrefs;
    private final ArrayList<Entry> mEntries = new ArrayList<>();

    public RewriteFiles(SharedPreferences prefs) {
        mPrefs = prefs;
        load();
    }

    private void load() {
        String serialized = mPrefs.getString(Prefs.PREF_REWRITE_FILES, "");
        if ((serialized == null) || serialized.isEmpty())
            return;

        ArrayList<Entry> entries;
        try {
            Type listOfEntries = new TypeToken<ArrayList<Entry>>() {}.getType();
            entries = new Gson().fromJson(serialized, listOfEntries);
        } catch (JsonParseException e) {
            Log.w(TAG, "Error loading the rewrite files: " + e);
            return;
        }

        if (entries == null)
            return;

        // skip the entries which cannot be used
        Iterator<Entry> it = entries.iterator();
        while (it.hasNext()) {
            Entry entry = it.next();

            if ((entry == null) || (entry.xml == null) || entry.xml.isEmpty()) {
                Log.w(TAG, "Skipping invalid rewrite file");
                it.remove();
            } else if (entry.name == null)
                entry.name = "";
        }

        mEntries.addAll(entries);
    }

    public void save() {
        mPrefs.edit()
                .putString(Prefs.PREF_REWRITE_FILES, new Gson().toJson(mEntries))
                .apply();
    }

    /* The master switch */
    public boolean isEnabled() {
        return mPrefs.getBoolean(Prefs.PREF_REWRITE_ENABLED, true);
    }

    public void setEnabled(boolean enabled) {
        mPrefs.edit().putBoolean(Prefs.PREF_REWRITE_ENABLED, enabled).apply();
    }

    public int size() {
        return mEntries.size();
    }

    public boolean isEmpty() {
        return mEntries.isEmpty();
    }

    public int getEnabledCount() {
        if (!isEnabled())
            return 0;

        int count = 0;
        for (Entry entry : mEntries) {
            if (entry.enabled)
                count++;
        }

        return count;
    }

    /* Total number of rules across all the files */
    public int getTotalRules() {
        int total = 0;
        for (Entry entry : mEntries)
            total += entry.getRuleCount();

        return total;
    }

    public Entry get(int pos) {
        return mEntries.get(pos);
    }

    public @NonNull List<Entry> getEntries() {
        return mEntries;
    }

    public void add(@NonNull String name, @NonNull String xml) {
        Entry entry = new Entry();
        entry.name = name;
        entry.xml = xml;
        entry.enabled = true;

        mEntries.add(entry);
        save();
    }

    public void remove(int pos) {
        mEntries.remove(pos);
        save();
    }

    public void setEntryEnabled(int pos, boolean enabled) {
        mEntries.get(pos).enabled = enabled;
        save();
    }

    /* The XML documents to be enforced, one per enabled file. An empty array
     * disables the rewriting. */
    public @NonNull String[] getEnabledXmls() {
        if (!isEnabled())
            return new String[0];

        ArrayList<String> xmls = new ArrayList<>();
        for (Entry entry : mEntries) {
            if (entry.enabled && !entry.xml.isEmpty())
                xmls.add(entry.xml);
        }

        return xmls.toArray(new String[0]);
    }

    public void clear() {
        mEntries.clear();
        save();
    }
}
