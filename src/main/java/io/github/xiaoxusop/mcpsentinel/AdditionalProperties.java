package io.github.xiaoxusop.mcpsentinel;
import com.fasterxml.jackson.databind.JsonNode;

/** Shared default semantics for diff and static rules. */
public enum AdditionalProperties {
    OMITTED, TRUE, FALSE, SCHEMA, OTHER;
    public static AdditionalProperties of(JsonNode node) {
        if (node == null || node.isMissingNode()) return OMITTED;
        if (node.isBoolean()) return node.booleanValue() ? TRUE : FALSE;
        return node.isObject() ? SCHEMA : OTHER;
    }
    public boolean allowsAny() { return this == OMITTED || this == TRUE; }
    public static boolean isUnrestricted(JsonNode node) {
        return of(node).allowsAny() || (node != null && node.isObject() && node.isEmpty());
    }
}
