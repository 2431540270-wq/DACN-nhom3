package service;

import java.io.*;
import java.util.ArrayList;
import java.util.List;
import model.LogEntry;

/**
 * LỚP: LogReader (Cái Máy Quét Tài Liệu Dữ Liệu Rác Mạng).
 * 
 * Mục Đích: Mọi gói tin (Network Data) được Firewall ngoài bắt về sẽ lưu nằm trong dạng File Rỗng (Text File).
 * Nhiệm vụ của lớp này là lôi File đó ra, đọc từng dòng String. Cắt cái chuỗi văng thành MẢNG (Array), rồi đút thông số vào
 * class Mẫu (Model - LogEntry) đã được nhào nặn.
 */
public class LogReader {

    /**
     * Đọc File Txt và nhổ các hạt đậu Dữ liệu về.
     * @param fileName Tên File log cần xới. (VD: "logs/network.log")
     * @return List (Danh sách các đối tượng LogEntry có đầy đủ thông số như thời gian, ip).
     */
    public List<LogEntry> readLog(String fileName) {

        List<LogEntry> logs = new ArrayList<>(); // Rổ hứng đậu đen.
        File logFile = new File(fileName);

        // Mất file thì đền. Cấm chạy tiếp lỗi tọt NullPointer!
        if (!logFile.exists()) {
            System.err.println("⚠️ Nguy hiểm: File " + fileName + " Không nằm trong ổ cứng Mất Tích Rồi!");
            return logs;
        }

        try (BufferedReader br = new BufferedReader(new FileReader(logFile))) {

            String line;
            // Biến "line" sẽ hút từng con dòng, lặp tới khi kiệt thì văng.
            while ((line = br.readLine()) != null) {

                // Lọc bỏ 3 cái dòng cách dòng \n mướn đi mờ chữ.
                if (line.trim().isEmpty()) {
                    continue; 
                }

                // regex "\\s+" ý nghĩa là : Cắt (Split) mỗi khi Cây đọc đụng phải dấu CÁCH " " hoặc N dấu lặp nhau (Tab \t).
                // Nếu "192 1" => ra 2 mảnh mảng [ "192", "1" ]
                String[] parts = line.split("\\s+");

                // Thẳng thừng từ chối nhận nếu log cùi bị rách cấu trúc (VD chỉ có 1 cột do Log Generator hỏng)
                if (parts.length < 2) {
                    System.err.println("⚠️ Skip dòng hỏng (đứt đoạn): " + line);
                    continue;
                }

                String time = parts[0];   // Phần tử số Thức 0 : Giờ (VD "10:05:03")
                String ip = parts[1];     // Vị trí thứ 1 (Cái 2): IP  (Còn các phần sau lười, đệ qui sau).
                
                // Mặc định ném đại "REQUEST" nếu không cho cái action vào. (Tùy lòng hảo tâm của LogGenerator có thả đuôi không)
                String action = (parts.length > 2) ? parts[2] : "REQUEST";

                // Sau Trại Bắt Đậu. Ta rinh vào cái máy nhào bột LogEntry Object
                // Model giúp Java quản lý dễ dàng thay vì quăng cả đống String Array hỗn loạn qua lại giữa các file.
                LogEntry entry = new LogEntry(time, ip, action);

                // Cho rớt vô Rổ Đậu Đen thôi.
                logs.add(entry);
            }
        } catch (IOException e) {
            System.err.println("⚠️ Bị Gì Đó Không Đọc Được Rồi " + e.getMessage());
        }

        return logs; // Trả rổ đem về đút vô Miệng ApiServer.
    }
}