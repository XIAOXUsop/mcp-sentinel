package io.github.xiaoxusop.mcpsentinel;

import com.fasterxml.jackson.databind.JsonNode;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.TreeSet;

/** Structural evidence, independent of whether a semantic rule recognizes it. */
public record PathChange(String toolName, int occurrence, String path, JsonNode before, JsonNode after) {
    static List<PathChange> between(String tool, int occurrence, JsonNode before, JsonNode after) {
        List<PathChange> changes = new ArrayList<>();
        collect(tool, occurrence, "", before, after, changes);
        return changes;
    }
    private static void collect(String tool, int occurrence, String path, JsonNode before, JsonNode after, List<PathChange> out) {
        if (Objects.equals(before, after)) return;
        if (before != null && after != null && before.isObject() && after.isObject()) {
            var keys = new TreeSet<String>();
            before.fieldNames().forEachRemaining(keys::add); after.fieldNames().forEachRemaining(keys::add);
            for (String key : keys) collect(tool, occurrence, path + "/" + key.replace("~", "~0").replace("/", "~1"),
                    before.get(key), after.get(key), out);
        } else if (before != null && after != null && before.isArray() && after.isArray()) {
            for (int i = 0; i < Math.max(before.size(), after.size()); i++) collect(tool, occurrence, path + "/" + i, before.get(i), after.get(i), out);
        } else {
            out.add(new PathChange(tool, occurrence, path, before == null ? null : before.deepCopy(), after == null ? null : after.deepCopy()));
        }
    }
}
