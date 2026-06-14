#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define BUFFER_SIZE 4096
#define MAX_USER 16

int password[1024];
char *sessions[MAX_USER];

void printHelp() {
  puts("Enter number: ");
  puts("  (1) Open a new session");
  puts("  (2) Input password");
  puts("  (3) Modify a password block (8 bytes)");
  puts("  (4) Close a session");
  puts("  (5) Login");
  puts("  (6) Quit");
  printf("%s", "> ");
}

void openSession() {
  static int current = 0;
  if (current >= MAX_USER) {
    puts("Cannot open new session!");
    return;
  } else {
    sessions[current] = malloc(BUFFER_SIZE);
    printf("New session: %d\n", current++);
  }
}

void inputPassword() {
  int n;
  printf("%s", "Please enter session id\n> ");
  scanf("%d", &n);
  if (sessions[n] != NULL) {
    printf("%s", "Please enter password\n> ");
    int c = 0, i = 0;
    // Consume remain newline char
    getchar();
    // Read line
    while ((c = getchar()) != '\n') sessions[n][i++] = c;
  } else {
    puts("Session not found!");
  }
}

void modifyPassword() {
  int n;
  printf("%s", "Please enter session id\n> ");
  scanf("%d", &n);
  if (sessions[n] != NULL) {
    int pos;
    uint64_t value;
    printf("%s", "Please enter position and value\n> ");
    scanf("%d %" SCNu64, &pos, &value);
    if (pos < 0 || pos >= (BUFFER_SIZE / 8)) {
      puts("Don't hack me :(");
    } else {
      ((uint64_t *)sessions[n])[pos] = value;
    }
  } else {
    puts("Session not found!");
  }
}

void closeSession() {
  int n;
  printf("%s", "Please enter session id\n> ");
  scanf("%d", &n);
  if (sessions[n] != NULL) {
    free(sessions[n]);
    sessions[n] = NULL;
  } else {
    puts("Session not found!");
  }
}

void login() {
  int n;
  printf("%s", "Please enter session id\n> ");
  scanf("%d", &n);
  if (sessions[n] != NULL) {
    // Setup new random password!
    FILE *fp = fopen("/dev/urandom", "rb");
    uint32_t seed;
    fread(&seed, sizeof(uint32_t), 1, fp);
    fclose(fp);
    srand(seed);
    for (int i = 0; i < 1024; i++) password[i] = rand();

    if (memcmp(sessions[n], password, BUFFER_SIZE) == 0) {
      puts(getenv("FLAG"));
    } else {
      puts("You cannot break my super secure password!");
    }
  } else {
    puts("Session not found!");
  }
}

int main() {
  setbuf(stdin, NULL);
  setbuf(stdout, NULL);
  int op;
  while (1) {
    printHelp();
    scanf("%d", &op);
    switch (op) {
      case 1: openSession(); break;
      case 2: inputPassword(); break;
      case 3: modifyPassword(); break;
      case 4: closeSession(); break;
      case 5: login(); break;
      case 6:
      default: return 0;
    }
  }
}
