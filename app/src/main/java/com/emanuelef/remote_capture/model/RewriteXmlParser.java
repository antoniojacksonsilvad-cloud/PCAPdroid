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
    private static final String S_ARROW = "→";
    private static final String S_REMOVE = "(remover)";

    /* A single rule, as shown in the app */
    public static class Rule {
        public String pattern = "";
        public int status = -1;
        public final ArrayList<String[]> headers = new ArrayList<>();
        public String body;

        /* set only for the rules coming from a Charles rewrite set */
        public String type;
        public String scope;
        public String setName;
        public boolean charles;
        public String matchValue = "";
        public String newValue = "";
        /* the two flags are kept apart because their order in the document is
         * not guaranteed, the scope is computed once the rule is complete */
        public boolean matchRequest;
        public boolean matchResponse;

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
     * reported in the result, together with the rules read so far.
     * Both the native format and the Charles Proxy format are accepted, the
     * format is detected from the root element of the document. */
    public static @NonNull Result parse(@Nullable String xml) {
        Result res = new Result();

        if ((xml == null) || xml.isEmpty())
            return res;

        XmlPullParser parser = Xml.newPullParser();

        try {
            // NOTE: setFeature throws a checked exception, it must be inside the try
            parser.setFeature(XmlPullParser.FEATURE_PROCESS_NAMESPACES, false);
            parser.setInput(new StringReader(xml));

            // look at the root element to know which format the document uses
            int event = parser.getEventType();
            while ((event != XmlPullParser.END_DOCUMENT) && (event != XmlPullParser.START_TAG))
                event = parser.next();

            if (event == XmlPullParser.END_DOCUMENT)
                return res;

            String root = localName(parser.getName());
            if (root.equals("rewriteSet-array"))
                readCharles(parser, res);
            else if (root.equals("rules") || root.equals("rule"))
                readNative(parser, res);
            else
                res.error = "Unrecognized rewrite rules format, the root element is <" + root + ">";
        } catch (XmlPullParserException | IOException e) {
            Log.w(TAG, "Error parsing the rewrite rules: " + e.getMessage());
            res.error = e.getMessage();
        }

        return res;
    }

    /* Reads the native <rules>/<rule> format. The parser is positioned on the
     * root element. */
    private static void readNative(XmlPullParser parser, Result res)
            throws XmlPullParserException, IOException {
        Rule current = null;
        int rule_depth = -1;
        boolean in_rewrite = false;
        boolean in_headers = false;

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
    }

    /* Reads the Charles <rewriteSet-array> format. The parser is positioned on
     * the root element. */
    private static void readCharles(XmlPullParser parser, Result res)
            throws XmlPullParserException, IOException {
        String set_name = null;
        String host = null;
        Rule current = null;
        boolean set_active = true;
        boolean rule_active = true;

        int event = parser.getEventType();
        while (event != XmlPullParser.END_DOCUMENT) {
            if (event == XmlPullParser.START_TAG) {
                String name = localName(parser.getName());

                switch (name) {
                    case "name":
                        set_name = parser.nextText();
                        break;

                    case "location":
                        // an empty <location/> means the set applies to any host
                        String value = parser.nextText();
                        if (!value.isEmpty())
                            host = value;
                        break;

                    case "rewriteRule":
                        current = new Rule();
                        current.charles = true;
                        current.setName = set_name;
                        current.pattern = (host != null) ? host : "";
                        rule_active = true;
                        break;

                    case "ruleType":
                        if (current != null)
                            current.type = charlesType(parser.nextText());
                        break;

                    case "matchValue":
                        if (current != null)
                            current.matchValue = parser.nextText();
                        break;

                    case "newValue":
                        if (current != null)
                            current.newValue = parser.nextText();
                        break;

                    case "matchRequest":
                        if (current != null)
                            current.matchRequest = isTrue(parser.nextText());
                        break;

                    case "matchResponse":
                        if (current != null)
                            current.matchResponse = isTrue(parser.nextText());
                        break;

                    case "matchHeader":
                        // displayed like a header of the rule
                        if (current != null) {
                            String h = parser.nextText();
                            if (!h.isEmpty())
                                current.headers.add(new String[]{h, ""});
                        }
                        break;

                    case "active":
                        // the addon skips the inactive sets and rules, they
                        // are skipped here too so that the number shown in the
                        // app is the number of rules actually applied
                        if (current != null)
                            rule_active = isTrue(parser.nextText());
                        else
                            set_active = isTrue(parser.nextText());
                        break;
                }
            } else if (event == XmlPullParser.END_TAG) {
                String name = localName(parser.getName());

                if (name.equals("rewriteSet")) {
                    set_name = null;
                    host = null;
                } else if (name.equals("rewriteRule") && (current != null)) {
                    current.scope = charlesScope(current.matchRequest, current.matchResponse);

                    // show what the rule matches and what it replaces
                    StringBuilder body = new StringBuilder();
                    if (!current.matchValue.isEmpty()) {
                        body.append(current.matchValue).append(' ').append(S_ARROW).append(' ');
                        // an empty replacement removes the matched text
                        body.append(current.newValue.isEmpty() ? S_REMOVE : current.newValue);
                    } else if (!current.newValue.isEmpty()) {
                        // no match value, the rule simply sets this value
                        body.append(S_ARROW).append(' ').append(current.newValue);
                    }

                    current.body = body.toString();

                    // RESPONSE_STATUS rules show the status, like the native ones
                    if ("RESPONSE_STATUS".equals(current.type))
                        current.status = parseStatus(current.newValue);

                    if (set_active && rule_active)
                        res.rules.add(current);

                    current = null;
                }
            }

            event = parser.next();
        }
    }

    /* The numeric ruleType of the Charles format, as mapped by the addon. The
     * numeric mapping was taken from the RewriteType enum of the Niddler
     * project, see modules/charles_rules.py. */
    private static String charlesType(String value) {
        int code;
        try {
            code = Integer.parseInt(value.trim());
        } catch (NumberFormatException e) {
            return value.trim();
        }

        switch (code) {
            case 1: return "ADD_HEADER";
            case 2: return "REMOVE_HEADER";
            case 3: return "MODIFY_HEADER";
            case 4: return "HOST";
            case 5: return "PATH";
            case 6: return "URL";
            case 7: return "BODY";
            case 8: return "ADD_QUERY_PARAM";
            case 9: return "MODIFY_QUERY_PARAM";
            case 10: return "REMOVE_QUERY_PARAM";
            case 11: return "RESPONSE_STATUS";
            default: return "TYPE_" + code;
        }
    }

    private static String charlesScope(boolean request, boolean response) {
        if (request && response)
            return "both";
        if (request)
            return "request";
        // Charles applies the rule to the response when no flag is set
        return "response";
    }

    private static boolean isTrue(String value) {
        return (value != null) && value.trim().equalsIgnoreCase("true");
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
