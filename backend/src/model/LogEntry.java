package model;

/**
 * LogEntry — Model representing a single network log event.
 *
 * Fields:
 *   - time       : Timestamp when the event was recorded
 *   - ip         : Source IP address
 *   - action     : Event type (LOGIN_FAIL, LOGIN_SUCCESS, REQUEST)
 *   - score      : Risk score computed by SecurityBot (0–100, default 0)
 *   - status     : Status label (PASS, SUSPICIOUS, MONITORING, BLOCKED)
 *   - attackType : Attack classification (NORMAL, BRUTE_FORCE, REQUEST_FLOOD)
 *
 * score, status, and attackType are assigned by SecurityBot AFTER analysis.
 */
public class LogEntry {

    /** Database row ID (0 if not yet persisted) */
    private int id;

    /** Timestamp of the log event */
    private String time;

    /** Source IP address */
    private String ip;

    /** Recorded action (LOGIN_FAIL, LOGIN_SUCCESS, REQUEST) */
    private String action;

    /** Risk score (0–100); computed by SecurityBot — default: 0 */
    private int score;

    /** Status after analysis — default: "PASS" */
    private String status;

    /** Detected attack type — default: "NORMAL" */
    private String attackType;

    /** Optional detailed description (from database, may be null) */
    private String description;

    /** Flag indicating whether properties were modified after loaded */
    private boolean isModified;

    /**
     * Creates a LogEntry with basic data from a log file or generator.
     * score / status / attackType will be set by SecurityBot later.
     *
     * @param time   Timestamp (e.g. ISO format or "HH:mm:ss")
     * @param ip     Source IP address (e.g. "192.168.1.15")
     * @param action Event type (e.g. "LOGIN_FAIL")
     */
    public LogEntry(String time, String ip, String action) {
        this.time = time;
        this.ip = ip;
        this.action = action;
        this.score = 0;
        this.status = "PASS";
        this.attackType = "NORMAL";
        this.isModified = false;
    }

    // ===================== GETTERS =====================

    /** @return true if log has been modified by bot since creation */
    public boolean isModified() { return isModified; }

    /** @return Database row ID */
    public int getId() { return id; }

    /** @return Timestamp string */
    public String getTime() { return time; }

    /** @return Source IP address */
    public String getIp() { return ip; }

    /** @return Action type (LOGIN_FAIL / LOGIN_SUCCESS / REQUEST) */
    public String getAction() { return action; }

    /** @return Risk score (0–100) */
    public int getScore() { return score; }

    /** @return Current status (PASS / SUSPICIOUS / MONITORING / BLOCKED) */
    public String getStatus() { return status; }

    /** @return Detected attack type (NORMAL / BRUTE_FORCE / REQUEST_FLOOD) */
    public String getAttackType() { return attackType; }

    /** @return Optional description (may be null) */
    public String getDescription() { return description; }

    // ===================== SETTERS =====================

    /** Sets the risk score (called by SecurityBot). */
    public void setScore(int score) { 
        if (this.score != score) {
            this.score = score;
            this.isModified = true;
        }
    }

    /** Sets the status label (called by SecurityBot). */
    public void setStatus(String status) { 
        if (this.status == null || !this.status.equals(status)) {
            this.status = status;
            this.isModified = true;
        }
    }

    /** Sets the attack type (called by SecurityBot). */
    public void setAttackType(String attackType) { 
        if (this.attackType == null || !this.attackType.equals(attackType)) {
            this.attackType = attackType;
            this.isModified = true;
        }
    }

    /** Sets the database row ID. */
    public void setId(int id) { this.id = id; }

    /** Sets the optional description. */
    public void setDescription(String description) { this.description = description; }

    /**
     * Resets the isModified flag to false.
     * Called after loading a LogEntry from DB so that updateLogs() only writes
     * back entries that SecurityBot actually modified during analysis,
     * not every log on every cycle.
     */
    public void resetModified() { this.isModified = false; }

    /**
     * Returns a string representation for debugging.
     */
    @Override
    public String toString() {
        return "[" + time + "] " + ip + " " + action
                + " | score=" + score
                + " | status=" + status
                + " | attack=" + attackType;
    }
}