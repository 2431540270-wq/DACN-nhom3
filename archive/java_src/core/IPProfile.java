package core;

/**
 * IPProfile — Tracks the behavior of a single IP address.
 *
 * Counters: LOGIN_FAIL, LOGIN_SUCCESS, REQUEST
 * Risk score formula: (loginFail * 3) + (request * 1) - (loginSuccess * 2)
 * Score is clamped to a minimum of 0.
 *
 * Note: This class is currently NOT used in the main flow.
 * Equivalent logic is embedded directly in SecurityBot.
 * Kept here for future refactoring (decoupling scoring from SecurityBot).
 */
public class IPProfile {

    /** IP address this profile belongs to */
    private String ip;

    /** Number of failed login attempts */
    private int loginFail;

    /** Number of successful logins */
    private int loginSuccess;

    /** Number of requests sent */
    private int request;

    /** Computed risk score */
    private int riskScore;

    /**
     * Creates a new IPProfile for the given IP address.
     * All counters start at 0.
     *
     * @param ip IP address (e.g. "192.168.1.15")
     */
    public IPProfile(String ip) {
        this.ip = ip;
    }

    /** Increments the LOGIN_FAIL counter by 1. */
    public void increaseFail() {
        loginFail++;
    }

    /** Increments the LOGIN_SUCCESS counter by 1. */
    public void increaseSuccess() {
        loginSuccess++;
    }

    /** Increments the REQUEST counter by 1. */
    public void increaseRequest() {
        request++;
    }

    /**
     * Calculates the risk score using the weighted formula:
     *   riskScore = (loginFail * 3) + (request * 1) - (loginSuccess * 2)
     *
     *   - LOGIN_FAIL  weight x3 — clearest indicator of attack
     *   - REQUEST     weight x1 — could be normal traffic
     *   - LOGIN_SUCCESS weight -2 — reduces suspicion
     *
     * Result is clamped to >= 0.
     */
    public void calculateRiskScore() {
        riskScore = (loginFail * 3) + (request * 1) - (loginSuccess * 2);
        if (riskScore < 0) {
            riskScore = 0;
        }
    }

    // ===================== GETTERS =====================

    /** @return Computed risk score (call calculateRiskScore() first) */
    public int getRiskScore() {
        return riskScore;
    }

    /** @return IP address */
    public String getIp() {
        return ip;
    }

    /** @return Number of LOGIN_FAIL events */
    public int getLoginFail() {
        return loginFail;
    }

    /** @return Number of LOGIN_SUCCESS events */
    public int getLoginSuccess() {
        return loginSuccess;
    }

    /** @return Number of REQUEST events */
    public int getRequest() {
        return request;
    }
}