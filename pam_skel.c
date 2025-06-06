#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_LINE 256

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username;
    char filepath[512];
    FILE *fp;
    char *questions[3];
    char *answers[3];
    char line[MAX_LINE];
    int count = 0;

    if (pam_get_user(pamh, &username, NULL) != PAM_SUCCESS || !username) {
        pam_syslog(pamh, LOG_ERR, "Não foi possível obter o nome do usuário");
        return PAM_AUTH_ERR;
    }

    snprintf(filepath, sizeof(filepath), "/etc/security/perguntas/%s.txt", username);
    fp = fopen(filepath, "r");
    if (!fp) {
        pam_syslog(pamh, LOG_ERR, "Erro ao abrir arquivo de perguntas: %s", filepath);
        return PAM_AUTH_ERR;
    }

    while (fgets(line, sizeof(line), fp) && count < 3) {
        char *sep = strchr(line, '|');
        if (!sep) {
            pam_syslog(pamh, LOG_ERR, "Formato inválido na linha %d", count + 1);
            fclose(fp);
            return PAM_AUTH_ERR;
        }

        *sep = '\0';
        questions[count] = strdup(line);
        answers[count] = strdup(sep + 1);

        // Remove quebra de linha da resposta
        char *newline = strchr(answers[count], '\n');
        if (newline) *newline = '\0';

        count++;
    }

    fclose(fp);

    if (count < 3) {
        pam_syslog(pamh, LOG_ERR, "Arquivo possui menos de 3 perguntas");
        return PAM_AUTH_ERR;
    }

    srand(time(NULL));
    int selected = rand() % 3;

    char *user_answer = NULL;
    int pam_result = pam_prompt(pamh, PAM_PROMPT_ECHO_ON, &user_answer, "%s ", questions[selected]);

    if (pam_result != PAM_SUCCESS || !user_answer) {
        pam_syslog(pamh, LOG_ERR, "Erro ao obter resposta do usuário");
        return PAM_AUTH_ERR;
    }

    if (strcmp(user_answer, answers[selected]) != 0) {
        pam_syslog(pamh, LOG_NOTICE, "Usuário %s errou a resposta da pergunta", username);
        return PAM_AUTH_ERR;
    }

    pam_syslog(pamh, LOG_INFO, "Usuário %s respondeu corretamente", username);
    return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
