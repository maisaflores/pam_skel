#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include <string.h>
#include <stdio.h>

#define MAX_RESP 256

// Respostas esperadas (pode ser adaptado para ler de um arquivo futuramente)
const char *expected_answers[3] = {
    "azul",    // Exemplo: "Qual sua cor favorita?"
    "fluffy",  // Exemplo: "Nome do seu primeiro animal de estimação?"
    "sao paulo"// Exemplo: "Cidade onde você nasceu?"
};

const char *questions[3] = {
    "Qual sua cor favorita?",
    "Qual o nome do seu primeiro animal de estimação?",
    "Em que cidade você nasceu?"
};

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
    char user_answer[MAX_RESP];

    for (int i = 0; i < 3; i++) {
        if (ask_question(pamh, questions[i], user_answer) != PAM_SUCCESS) {
            pam_syslog(pamh, LOG_ERR, "Erro ao fazer pergunta %d", i + 1);
            return PAM_AUTH_ERR;
        }

        if (strcasecmp(user_answer, expected_answers[i]) != 0) {
            pam_syslog(pamh, LOG_NOTICE, "Resposta incorreta para a pergunta %d", i + 1);
            return PAM_AUTH_ERR;
        }
    }

    return PAM_SUCCESS;
}

int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc, const char **argv) {
    return PAM_SUCCESS;
}
