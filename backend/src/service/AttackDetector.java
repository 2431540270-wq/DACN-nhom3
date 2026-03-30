package service;

import alert.AlertSystem;
import java.util.*;

/**
 * AttackDetector — Detects network attacks based on configurable thresholds.
 *
 * Detects two attack types:
 *   - BRUTE_FORCE   : IP with >= 5 LOGIN_FAIL events
 *   - REQUEST_FLOOD : IP with >= 10 REQUEST events
 *
 * Note: This class is currently NOT used in the main flow.
 * Equivalent logic (with different thresholds: BRUTE_FORCE >= 5, REQUEST_FLOOD >= 20)
 * is embedded directly in SecurityBot.
 * Kept here for future use when decoupling detection logic.
 */
public class AttackDetector {

    /** Minimum LOGIN_FAIL count to classify as brute force */
    private static final int LOGIN_FAIL_THRESHOLD = 5;

    /** Minimum REQUEST count to classify as request flood */
    private static final int REQUEST_THRESHOLD = 10;

    /**
     * Scans loginFailMap and requestMap for suspicious IPs.
     *
     * Steps:
     *   1. Iterate loginFailMap — if count >= 5 → mark as BRUTE_FORCE
     *   2. Iterate requestMap   — if count >= 10 → mark as REQUEST_FLOOD
     *   3. Send an alert via AlertSystem for each detected IP
     *
     * @param loginFailMap Map<IP, FailCount>    from LogAnalyzer
     * @param requestMap   Map<IP, RequestCount> from LogAnalyzer
     * @param alert        AlertSystem to emit warnings
     * @return Map<IP, AttackType> of all detected IPs
     */
    public Map<String, String> detect(
            Map<String, Integer> loginFailMap,
            Map<String, Integer> requestMap,
            AlertSystem alert) {

        Map<String, String> detected = new HashMap<>();

        // Detect Brute Force — >= 5 LOGIN_FAIL from the same IP
        for (String ip : loginFailMap.keySet()) {
            int count = loginFailMap.get(ip);
            if (count >= LOGIN_FAIL_THRESHOLD) {
                detected.put(ip, "BRUTE_FORCE");
                String msg = "🚨 IP " + ip
                        + " suspected BRUTE_FORCE (" + count + " LOGIN_FAIL)";
                alert.addAlert(msg);
            }
        }

        // Detect Request Flood — >= 10 REQUEST from the same IP
        for (String ip : requestMap.keySet()) {
            int count = requestMap.get(ip);
            if (count >= REQUEST_THRESHOLD) {
                detected.put(ip, "REQUEST_FLOOD");
                String msg = "⚠ IP " + ip
                        + " abnormal REQUEST volume (" + count + " requests)";
                alert.addAlert(msg);
            }
        }

        return detected;
    }
}