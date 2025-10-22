#include "../include/antivirus.h"

int main(int argc, char **argv) {
    if (argc < 3) {
        printf("Usage: %s <scan-path> <signatures-file> [quarantine-dir] [log-file]\n", argv[0]);
        return 1;
    }

    const char *scanPath = argv[1];
    const char *sigFile = argv[2];
    const char *quarantine = (argc >= 4) ? argv[3] : "quarantine";
    const char *logfile = (argc >= 5) ? argv[4] : "scan.log";

    SigNode *sigs = signatures_load(sigFile);
    if (!sigs) {
        printf("Failed to load signatures from %s\n", sigFile);
        return 2;
    }

    printf("Starting scan of %s using signatures %s\n", scanPath, sigFile);
    log_event(logfile, "SCAN_START: %s", scanPath);

    scan_path(scanPath, sigs, quarantine, logfile);

    log_event(logfile, "SCAN_END: %s", scanPath);
    signatures_free(sigs);

    printf("Scan complete. Log: %s\n", logfile);
    return 0;
}
