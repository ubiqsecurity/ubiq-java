package com.ubiqsecurity;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

class ConfigParser {
    private Map<String, Map<String, String>> sections;
    private Pattern sectionPattern = Pattern.compile("\\s*\\[([^]]*)\\]\\s*");
    private Pattern keyValuePattern = Pattern.compile("\\s*([^=]*)=(.*)");

    ConfigParser(String pathname) throws IOException {
        sections = new HashMap<>();

        if ((pathname == null) || pathname.isEmpty()) {
            throw new IllegalArgumentException("pathname");
        }

        File temp = new File(pathname);
        if (!temp.exists()) {
            throw new IllegalArgumentException(String.format("file does not exist: %s", pathname));
        }

        readLines(pathname);
    }

    String fetchValue(String section, String key) {
        Map<String, String> kv = this.sections.get(section);
        if (kv != null) {
            return kv.get(key);
        }

        return null;
    }

    private void readLines(String pathname) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(pathname))) {
            String line;
            String section = null;
            while ((line = reader.readLine()) != null) {
                Matcher m = sectionPattern.matcher(line);
                if (m.matches()) {
                    section = m.group(1).trim();
                } else if (section != null) {
                    m = keyValuePattern.matcher(line);
                    if (m.matches()) {
                        String key = m.group(1).trim().toLowerCase();
                        String value = m.group(2).trim();
                        Map<String, String> kv = this.sections.get(section);
                        if (kv == null) {
                            this.sections.put(section, kv = new HashMap<>());
                        }
                        kv.put(key, value);
                    }
                }
            }
        }
    }
}
