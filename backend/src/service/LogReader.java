package service;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import model.LogEntry;

/**
 * LogReader — Reads a plain-text network log file line by line
 * and parses each line into a LogEntry object.
 */
public class LogReader {

    /**
     * Reads a text log file and parses each line into a LogEntry.
     * @param fileName Path to the log file (e.g. "logs/network.log")
     * @return List of parsed LogEntry objects, or empty list if file not found
     */
    public List<LogEntry> readLog(String fileName) {

        List<LogEntry> logs = new ArrayList<>();
        File logFile = new File(fileName);

        // File not found — return empty list safely (no NullPointerException)
        if (!logFile.exists()) {
            System.err.println("[LogReader] File not found: " + fileName + " — skipping file read.");
            return logs;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(logFile))) {

            String line;
            while ((line = br.readLine()) != null) {

                // Skip blank lines
                if (line.trim().isEmpty()) {
                    continue;
                }

                // Split by whitespace (space or tab)
                String[] parts = line.split("\\s+");

                // Skip malformed lines (need at least timestamp + IP)
                if (parts.length < 2) {
                    System.err.println("[LogReader] Skipping malformed line: " + line);
                    continue;
                }

                String time   = parts[0]; // e.g. "10:05:03"
                String ip     = parts[1]; // e.g. "192.168.1.15"

                // Default action to REQUEST if not provided
                String action = (parts.length > 2) ? parts[2] : "REQUEST";

                LogEntry entry = new LogEntry(time, ip, action);
                logs.add(entry);
            }
        } catch (IOException e) {
            System.err.println("[LogReader] IOException while reading file: " + e.getMessage());
        }

        return logs;
    }
}