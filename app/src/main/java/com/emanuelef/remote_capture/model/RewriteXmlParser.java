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

import android.util.Xml;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import com.emanuelef.remote_capture.Log;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;

import java.io.IOException;
import java.io.StringReader;
import java.util.ArrayList;

/* Lightweight XML parse of the rewrite rules, used ONLY to display the rules
 * in the app (their number and their content).
 * The rules which are actually applied to the traffic are parsed and enforced
 * by the mitmproxy addon, see modules/rewrite_rules.py in PCAPdroid-mitm. */
public class RewriteXmlParser {
    private static final String TAG = "RewriteXmlParser";

    /* A single rule, as shown in the app */
    public static class Rule {
        public String pattern = "";
        public int status = -1;
        public final ArrayList<String[]> headers = new ArrayList<>();
        public String body;

        public boolean hasBody() {
            return (body != null);
        }
    }

    public static class Result {
        public final ArrayList<Rule> rules = new ArrayList<>();
        public String error;

        public int count() {
            return rules.size();
        }
    }

    /* Returns the rules found in the document. Never throws: a parse error is
     * reported in the result, together with the rules read so far. */
    public static @NonNull Result parse(@Nullable String xml) {
        Result res = new Result();

        if ((xml == null) || xml.isEmpty())
            return res;

        XmlPullParser parser = Xml.newPullParser();

        Rule current = null;
        int rule_depth = -1;
        boolean in_rewrite = false;
        boolean in_headers = false;

        try {
            // NOTE: setFeature throws a checked exception, it must be inside the try
            parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, false);
            parser.setInput(new StringReader(xml));

            int event = parser.getEventType();
            while (event != XmlPullParser.END_DOCUMENT) {
                if (event == XmlPullParser.START_TAG) {
                    String name = localName(parser.getName());
                    int depth = parser.getDepth();

                    if (name.equals("rule")) {
                        current = new Rule();
                        rule_depth = depth;
                    } else if (name.equals("rewrite")) {
                        in_rewrite = (current != null);
                    } else if (name.equals("headers")) {
                        in_headers = (current != null);
                    } else if (current != null && isLeafOfRule(depth, rule_depth, in_rewrite, in_headers)) {
                        // the rewrite element is optional: its children can be
                        // placed directly inside the rule
                        switch (name) {
                            case "pattern":
                                current.pattern = parser.nextText();
                                break;
                            case "status_code":
                            case "status":
                                current.status = parseStatus(parser.nextText());
                                break;
                            case "header":
                                addHeader(current, parser);
                                break;
                            case "body":
                                current.body = parser.nextText();
                                break;
                        }
                    }
                } else if (event == XmlPullParser.END_TAG) {
                    String name = localName(parser.getName());

                    if (name.equals("rewrite"))
                        in_rewrite = false;
                    else if (name.equals("headers"))
                        in_headers = false;
                    else if (name.equals("rule") && (current != null)) {
                        res.rules.add(current);
                        current = null;
                        rule_depth = -1;
                    }
                }

                event = parser.next();
            }
        } catch (XmlPullParserException | IOException e) {
            Log.w(TAG, "Error parsing the rewrite rules: " + e.getMessage());
            res.error = e.getMessage();
        }

        return res;
    }

    /* Returns the number of rules in the document, 0 if it cannot be parsed. */
    public static int countRules(@Nullable String xml) {
        return parse(xml).count();
    }

    /* True when the element is one of the values a rule can be built from:
     * either a direct child of <rule>, or a child of the optional <rewrite>.
     * The <header> elements are nested one level deeper, inside <headers>. */
    private static boolean isLeafOfRule(int depth, int rule_depth, boolean in_rewrite, boolean in_headers) {
        if (rule_depth < 0)
            return false;

        // a direct child of <rule>
        if (depth == rule_depth + 1)
            return true;

        if (!in_rewrite)
            return false;

        // a child of <rewrite>: status_code, headers, body
        if (depth == rule_depth + 2)
            return true;

        // a <header> inside <headers>
        return in_headers && (depth == rule_depth + 3);
    }

    private static void addHeader(Rule rule, XmlPullParser parser) {
        String name = parser.getAttributeValue(null, "name");
        if ((name == null) || name.isEmpty())
            return;

        String value = parser.getAttributeValue(null, "value");
        rule.headers.add(new String[]{name, (value != null) ? value : ""});
    }

    private static int parseStatus(String value) {
        if (value == null)
            return -1;

        try {
            return Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return -1;
        }
    }

    private static String localName(String tag) {
        if ((tag == null) || !tag.startsWith("{"))
            return tag;

        int idx = tag.indexOf('}');
        return (idx >= 0) ? tag.substring(idx + 1) : tag;
    }
}
