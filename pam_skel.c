#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_QUESTIONS 3
#define MAX_LINE 512
#define MAX_RESP 256

typedef struct {
    char question[MAX_LINE];
    char answer[MAX_LINE];
} SecurityQA;

int read_questions(const char *username, SecurityQA qa_list[MAX_QUESTIONS]) {
    char filepath[256];
    snprintf(filepath, sizeof(filepath), "/etc/security/perguntas/%s.txt", username);

    FILE *file = fopen(filepath, "r");
    if (!file) return -1;

    char line[MAX_LINE];
    int count = 0;
    while (fgets(line, sizeof(line), file) && count < MAX_QUESTIONS) {
        char *sep = strchr(line, '|');
        if (!sep) continue;

        *sep = '\0';
        strncpy(qa_list[count].question, line, MAX_LINE);
        qa_list[count].question[MAX_LINE - 1] = '\0';

        strncpy(qa_list[count].answer, sep + 1, MAX_LINE);
        qa_list[count].answer[MAX_LINE - 1] = '\0';

        // Remover \n do final da resposta
        size_t len = strlen(qa_list[count].answer);
        if (len > 0 && qa_list[count].answer[len - 1] == '\n') {
            qa_list[count].answer[len - 1] = '\0';
        }

        count++;
    }

    fclose(file);
    return (count == MAX_QUESTIONS) ? 0 : -2;
}

int ask_question(pam_handle_t *pamh, const char *question, char *response) {
    const struct pam_message msg = {
        .msg_style = PAM_PROMPT_ECHO_ON,
        .msg = question
    };
    const struct pam_message *msgp = &msg;
    struct pam_response *resp = NULL;
    struct pam_conv *conv;

    if (pam_get_item(pamh, PAM_CONV, (const void **) &conv) != PAM_SUCCESS || !conv) {
        return PAM_CONV_ERR;
    }

    int retval = conv->conv(1, &msgp, &resp, conv->appdata_ptr);
    if (retval != PAM_SUCCESS || !resp || !resp->resp) {
        return PAM_CONV_ERR;
    }

    strncpy(response, resp->resp, MAX_RESP - 1);
    response[MAX_RESP - 1] = '\0';
    free(resp->resp);
    free(resp);

    return PAM_SUCCESS;
}

int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    const char *username = NULL;
    if (pam_get_user(pamh, &username, "Usuário: ") != PAM_SUCCESS || username == NULL) {
        pam_syslog(pamh, LOG_ERR, "Não foi possível obter o nome do usuário");
        return PAM_AUTH_ERR;
    }

    if (strcmp(username, "maisa") != 0) {
        return PAM_IGNORE;
    }

    SecurityQA qa_list[MAX_QUESTIONS];
    if (read_questions(username, qa_list) != 0) {
        pam_syslog(pamh, LOG_ERR, "Não foi possível ler o arquivo de perguntas para o usuário %s", username);
        return PAM_AUTH_ERR;
    }

    char user_answer[MAX_RESP];
    for (int i = 0; i < MAX_QUESTIONS; i++) {
        if (ask_question(pamh, qa_list[i].question, user_answer) != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_ERR, "Erro ao perguntar: %s", qa_list[i].question);
            return PAM_AUTH_ERR;
        }

        if (strcasecmp(user_answer, qa_list[i].answer) != 0) {
            pam_syslog(pamh, LOG_NOTICE, "Usuário %s errou a pergunta %d", username, i + 1);
            return PAM_AUTH_ERR;
        }
    }

    return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}

