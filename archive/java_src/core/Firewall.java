package core;

import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 * Firewall — Manages the in-memory IP blocklist.
 *
 * Features:
 *   - blockIP()      : Add an IP to the blocklist
 *   - unblockIP()    : Remove an IP from the blocklist
 *   - isBlocked()    : Check if an IP is currently blocked
 *   - getBlockedIPs(): Return a snapshot of all blocked IPs
 *
 * Thread-safety: Uses Collections.synchronizedSet() so both the
 * API thread and the monitor thread can access safely.
 */
public class Firewall {

    /** Thread-safe set of blocked IP addresses */
    private final Set<String> blockedIPs = Collections.synchronizedSet(new HashSet<>());

    /**
     * Adds an IP to the blocklist.
     * If the IP is already blocked, this is a no-op (Set guarantees uniqueness).
     *
     * @param ip IP address to block (e.g. "192.168.1.15")
     */
    public void blockIP(String ip) {
        blockedIPs.add(ip);
        System.out.println("[Firewall] BLOCKED IP: " + ip);
    }

    /**
     * Removes an IP from the blocklist.
     * If the IP is not in the list, this is a no-op.
     *
     * @param ip IP address to unblock (e.g. "192.168.1.15")
     */
    public void unblockIP(String ip) {
        blockedIPs.remove(ip);
        System.out.println("[Firewall] UNBLOCKED IP: " + ip);
    }

    /**
     * Checks whether an IP is currently blocked.
     *
     * @param ip IP address to check
     * @return true if blocked, false otherwise
     */
    public boolean isBlocked(String ip) {
        return blockedIPs.contains(ip);
    }

    /**
     * Returns a snapshot copy of all currently blocked IPs.
     * Returns a copy (not the live set) to prevent concurrent modification
     * when ApiServer iterates from a different thread.
     *
     * @return Snapshot Set<String> of blocked IPs
     */
    public Set<String> getBlockedIPs() {
        return new HashSet<>(blockedIPs);
    }
}