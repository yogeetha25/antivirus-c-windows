#include "../include/antivirus.h"

SigNode* signatures_load(const char *file) {
    FILE *f = fopen(file, "r");
    if (!f) return NULL;

    SigNode *head = NULL, *tail = NULL;
    char line[256];

    while (fgets(line, sizeof(line), f)) {
        char *p = line;
        while (*p && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
        if (*p == '\0') continue;

        char *end = p + strlen(p) - 1;
        while (end > p && (*end == '\r' || *end == '\n' || *end == ' ')) {
            *end = '\0'; end--;
        }

        SigNode *n = (SigNode*)malloc(sizeof(SigNode));
        n->hashhex = _strdup(p);
        n->next = NULL;

        if (!head) head = tail = n;
        else { tail->next = n; tail = n; }
    }
    fclose(f);
    return head;
}

int signatures_contains(SigNode *head, const char *hex) {
    for (SigNode *p = head; p; p = p->next)
        if (_stricmp(p->hashhex, hex) == 0) return 1;
    return 0;
}

void signatures_free(SigNode *head) {
    while (head) {
        SigNode *t = head;
        head = head->next;
        free(t->hashhex);
        free(t);
    }
}
