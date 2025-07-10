#include <fcntl.h>
#include <grp.h>
#include <pwd.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>

#include "lib/secure_string.h"

// Globals
pid_t vaultPid = -1;
std::string securePath;
bool mountedTmpfs = false;

// Function to securely read a password from stdin
std::string readPassword(const std::string& prompt = "Enter password: ") {
  std::string password;
  struct termios oldt, newt;

  std::cout << prompt;
  std::cout.flush();

  tcgetattr(STDIN_FILENO, &oldt);
  newt = oldt;
  newt.c_lflag &= ~ECHO;

  tcsetattr(STDIN_FILENO, TCSANOW, &newt);
  std::getline(std::cin, password);
  tcsetattr(STDIN_FILENO, TCSANOW, &oldt);

  std::cout << "\n";
  return password;
}

// Cleanup function
void cleanup(int signum) {
  std::cout << "\n[*] Cleaning up...\n";

  if (mountedTmpfs && !securePath.empty()) {
    std::cout << "[*] Unmounting tmpfs and deleting " << securePath << "\n";
    umount(securePath.c_str());
    rmdir(securePath.c_str());
  }

  if (vaultPid > 0) {
    std::cout << "[*] Killing VaultServer (PID " << vaultPid << ")...\n";
    kill(vaultPid, SIGTERM);
    waitpid(vaultPid, nullptr, 0);
  }

  std::cout << "[*] Stopping NGINX...\n";
  system("sudo pkill -f nginx");

  std::cout << "[*] Checking if ports 2222 and 2223 are still bound...\n";
  system("sudo lsof -i :2222 -i :2223 || echo \"[*] Ports are clean.\"");

  std::cout << "[✔] Cleanup complete.\n";
  std::exit(0);
}

// Launch a process and return PID
pid_t launchProcess(const char* execPath, char* const args[]) {
  pid_t pid = fork();
  if (pid == 0) {
    execvp(execPath, args);
    perror("execvp failed");
    std::exit(1);
  }
  return pid;
}

int main() {
  // Handle signals for cleanup
  struct sigaction sa{};
  sa.sa_handler = cleanup;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, nullptr);
  sigaction(SIGTERM, &sa, nullptr);

  SecureString password(std::move(readPassword("Enter Vault password: ")));

  char tmpfsDir[] = "/home/fg/Desktop/tableTopVault/secrets";
  if (!mkdtemp(tmpfsDir)) {
    perror("mkdtemp failed");
    return 1;
  }

  if (mount("tmpfs", tmpfsDir, "tmpfs", MS_NOEXEC | MS_NOSUID | MS_NODEV, "size=1M,mode=0700") !=
      0) {
    perror("mount tmpfs failed");
    rmdir(tmpfsDir);
    return 1;
  }

  // Set restrictive permissions just in case
  chmod(tmpfsDir, 0700);

  // Now tmpfsDir is your RAM-only private secure directory
  std::string securePath(tmpfsDir);

  securePath = tmpfsDir;
  mountedTmpfs = true;

  std::cout << "[*] Starting VaultServer...\n";
  char* vaultArgs[] = {(char*)"/home/fg/Desktop/tableTopVaultServer/build/VaultServer",
                       (char*)"/home/fg/Desktop/tableTopVaultServer/vault.conf", nullptr};
  vaultPid = launchProcess(vaultArgs[0], vaultArgs);

  sleep(4);

  std::cout << "[*] Starting NGINX...\n";
  system(
      "sudo /home/fg/Desktop/tableTopVaultServer/nginx-1.28.0/sbin/nginx -c "
      "/home/fg/Desktop/tableTopVaultServer/nginx/nginx.conf");

  std::cout << "[✔] All services started. Press Ctrl+C to stop.\n";

  int status;
  waitpid(vaultPid, &status, 0);
  vaultPid = -1;

  cleanup(0);
  return 0;
}
