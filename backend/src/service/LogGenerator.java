package service;

import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Random;
import model.LogEntry;
import database.LogDAO;

/**
 * LogGenerator — Generates random network log entries and saves them to the
 * database.
 *
 * Runs an infinite loop every 1 second, producing a log entry with:
 * - A random IPv4 address
 * - A random action: LOGIN_FAIL, LOGIN_SUCCESS, or REQUEST
 * - Status: SUSPICIOUS (for LOGIN_FAIL), PASS (otherwise)
 * - AttackType: always NORMAL (SecurityBot will update later)
 *
 * Each entry is persisted via LogDAO.insertLog().
 */
public class LogGenerator {

    // Possible actions to generate randomly
    private static final String[] ACTIONS = {
            "LOGIN_FAIL",
            "LOGIN_SUCCESS",
            "REQUEST"
    };

    // DAO used to persist log entries to the database
    private LogDAO logDAO = new LogDAO();

    // Shared random number generator
    private Random random = new Random();

    /**
     * Main loop: generate → save to DB → print to console → sleep 1 second.
     * Runs indefinitely until the thread is interrupted.
     */
    public void startGenerating() {
        System.out.println("[LogGenerator] Started generating logs...");

        while (true) {
            try {
                // Step 1: Generate random data
                String ip = randomIP();
                String action = randomAction();
                // Use MySQL-compatible DATETIME format: 'yyyy-MM-dd HH:mm:ss'
                String time = LocalDateTime.now()
                        .format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
                String status = mapStatus(action);
                String attackType = "NORMAL";

                // Step 2: Build LogEntry using the 3-argument constructor
                LogEntry log = new LogEntry(time, ip, action);

                // Step 3: Assign status and attackType
                log.setStatus(status);
                log.setAttackType(attackType);

                // Step 4: Persist to database
                logDAO.insertLog(log);

                // Step 5: Print to console for monitoring
                System.out.println("[LOG] " + ip + " - " + action + " - " + status);

                // Sleep 1 second before generating the next log
                Thread.sleep(1000);

            } catch (InterruptedException e) {
                System.err.println("[LogGenerator] Stopped.");
                break;
            }
        }
    }

    /**
     * Generates a random IPv4 address (all octets 0–255).
     *
     * @return Random IPv4 string
     */
    private String randomIP() {
        int a = random.nextInt(256);
        int b = random.nextInt(256);
        int c = random.nextInt(256);
        int d = random.nextInt(256);
        return a + "." + b + "." + c + "." + d;
    }

    /**
     * Picks a random action from the ACTIONS array.
     *
     * @return "LOGIN_FAIL", "LOGIN_SUCCESS", or "REQUEST"
     */
    private String randomAction() {
        return ACTIONS[random.nextInt(ACTIONS.length)];
    }

    /**
     * Maps an action to a status:
     * LOGIN_FAIL → SUSPICIOUS
     * LOGIN_SUCCESS → PASS
     * REQUEST → PASS
     *
     * @param action The action string
     * @return Corresponding status string
     */
    private String mapStatus(String action) {
        if ("LOGIN_FAIL".equals(action)) {
            return "SUSPICIOUS";
        }
        return "PASS";
    }
}
