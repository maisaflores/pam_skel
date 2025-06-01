#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define CODE_LEN 5  // 4 digits + '\0'
#define EMAIL_FILE "/etc/pam_skel_emails"

// Função para gerar código aleatório de 4 dígitos
void generate_code(char *code) {
    srand(time(NULL) ^ getpid());
    snprintf(code, CODE_LEN, "%04d", rand() % 10000);
}

// Função para obter email do usuário a partir de um arquivo
int get_user_email(const char *user, char *email, size_t len) {
    FILE *fp = fopen(EMAIL_FILE, "r");
    if (!fp) return -1;

    char line[256];
    while (fgets(line, sizeof(line), fp)) {
        char file_user[64], file_email[128];
        if (sscanf(line, "%63[^:]:%127s", file_user, file_email) == 2) {
            if (strcmp(user, file_user) == 0) {
                strncpy(email, file_email, len);
                fclose(fp);
                return 0;
            }
        }
    }
    fclose(fp);
    return -1;
}

// Função para enviar o email com o código
void send_email(const char *email, const char *code) {
    char cmd[512];
    snprintf(cmd, sizeof(cmd),
        "echo 'Seu código de autenticação: %s' | mail -s 'Código 2FA' %s",
        code, email);
    system(cmd);
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *user;
    char code[CODE_LEN];
    char input_code[CODE_LEN];
    char email[128];

    // Obtém o nome do usuário
    if (pam_get_user(pamh, &user, NULL) != PAM_SUCCESS) {
        return PAM_AUTH_ERR;
    }

    // Obtém email do usuário
    if (get_user_email(user, email, sizeof(email)) != 0) {
        return PAM_AUTH_ERR;
    }

    // Gera e envia o código
    generate_code(code);
    send_email(email, code);

    // Solicita código ao usuário
    printf("Digite o código de autenticação enviado para %s: ", email);
    if (fgets(input_code, sizeof(input_code), stdin) == NULL) {
        return PAM_AUTH_ERR;
    }

    // Remove \n
    input_code[strcspn(input_code, "\n")] = '\0';

    // Verifica se o código está correto
    if (strcmp(code, input_code) == 0) {
        return PAM_SUCCESS;
    } else {
        return PAM_AUTH_ERR;
    }
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
