package service;

import java.util.*;
import model.LogEntry;

/**
 * LogAnalyzer — Aggregates log entries by action type and IP address.
 *
 * Provides:
 *   - countAction(): Count occurrences of a specific action grouped by IP
 *   - sortByIp()   : Sort a list of log entries alphabetically by IP
 *
 * Used primarily by SecurityBot to compute per-IP risk scores.
 */
public class LogAnalyzer {

    /**
     * Counts how many times a specific action appears per IP address.
     *
     * Example: countAction(logs, "LOGIN_FAIL") with data:
     *   192.168.1.15 LOGIN_FAIL (x5)
     *   192.168.1.20 LOGIN_FAIL (x2)
     * → Result: {"192.168.1.15": 5, "192.168.1.20": 2}
     *
     * @param logs   List of LogEntry to analyze
     * @param action Action name to count (e.g. "LOGIN_FAIL", "REQUEST", "LOGIN_SUCCESS")
     * @return Map<IP, Count> — number of times the action appears per IP
     */
    public Map<String, Integer> countAction(List<LogEntry> logs, String action) {

        Map<String, Integer> map = new HashMap<>();

        for (LogEntry log : logs) {
            // Use equals() for null-safe comparison
            if (action.equals(log.getAction())) {
                String ip = log.getIp();
                map.put(ip, map.getOrDefault(ip, 0) + 1);
            }
        }

        return map;
    }

    /**
     * Sorts a list of log entries in-place by IP address (alphabetical).
     *
     * Note: This modifies the original list. Pass a copy if the original must be preserved.
     *
     * @param logs List of LogEntry to sort
     * @return The same list, now sorted by IP
     */
    public List<LogEntry> sortByIp(List<LogEntry> logs) {
        logs.sort(Comparator.comparing(LogEntry::getIp));
        return logs;
    }
}
