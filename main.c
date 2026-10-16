#include <stdio.h>
#include <string.h>

#define MAX_LOGS 100
#define MAX_USERS 100

typedef struct {
    char ip[40];
    char username[50];
    char timestamp[30];
    int success;
} SecurityLog;

typedef struct {
    char username[50];
    int failed;
    int successful;
    int risk;
    char level[15];
} ThreatAlert;

SecurityLog logs[MAX_LOGS];
ThreatAlert alerts[MAX_USERS];

int logCount = 0;
int alertCount = 0;

/* Add a security log */
void addLog(const char *ip, const char *user,
            int success, const char *time) {
    if (logCount >= MAX_LOGS) {
        printf("Log storage is full!\n");
        return;
    }

    strcpy(logs[logCount].ip, ip);
    strcpy(logs[logCount].username, user);
    strcpy(logs[logCount].timestamp, time);
    logs[logCount].success = success;
    logCount++;
}

/* Sample data for demonstration */
void loadSampleData(void) {
    logCount = 0;

    addLog("192.0.2.15", "student01", 0, "10:30:00");
    addLog("192.0.2.15", "student01", 0, "10:31:00");
    addLog("192.0.2.15", "student01", 0, "10:32:00");
    addLog("192.0.2.15", "student01", 0, "10:33:00");
    addLog("192.0.2.15", "student01", 0, "10:34:00");
    addLog("192.0.2.20", "student02", 1, "10:35:00");
    addLog("192.0.2.21", "student03", 0, "10:36:00");
    addLog("192.0.2.21", "student03", 1, "10:37:00");
    addLog("192.0.2.22", "admin", 0, "10:38:00");
    addLog("192.0.2.22", "admin", 0, "10:39:00");
    addLog("192.0.2.22", "admin", 0, "10:40:00");

    printf("\n%d sample security logs loaded.\n", logCount);
}

/* Load security logs from a CSV file */
void loadCSV(void) {
    FILE *fp = fopen("logs.csv", "r");
    char line[200];
    char ip[40], username[50], timestamp[30];
    int success;
    int loaded = 0;

    if (fp == NULL) {
        printf("\nlogs.csv not found!\n");
        printf("Create logs.csv in the project folder first.\n");
        return;
    }

    /* Skip the CSV header */
    if (fgets(line, sizeof(line), fp) == NULL) {
        printf("\nCSV file is empty.\n");
        fclose(fp);
        return;
    }

    logCount = 0;

    while (fgets(line, sizeof(line), fp) != NULL
           && logCount < MAX_LOGS) {

        if (sscanf(line, "%39[^,],%49[^,],%d,%29[^\n]",
                   ip, username, &success, timestamp) == 4) {

            if (success == 0 || success == 1) {
                addLog(ip, username, success, timestamp);
                loaded++;
            }
        }
    }

    fclose(fp);

    printf("\n%d security logs loaded from CSV.\n", loaded);
}

/* Display all log records */
void displayLogs(void) {
    int i;

    if (logCount == 0) {
        printf("\nNo logs available. Load sample data first.\n");
        return;
    }

    printf("\n%-5s %-18s %-15s %-10s %-12s\n",
           "No.", "IP Address", "Username",
           "Login", "Time");
    printf("------------------------------------------------------------\n");

    for (i = 0; i < logCount; i++) {
        printf("%-5d %-18s %-15s %-10s %-12s\n",
               i + 1, logs[i].ip, logs[i].username,
               logs[i].success ? "Success" : "Failed",
               logs[i].timestamp);
    }
}

/* Find or create a user alert */
int findUser(const char *username) {
    int i;

    for (i = 0; i < alertCount; i++) {
        if (strcmp(alerts[i].username, username) == 0) {
            return i;
        }
    }

    if (alertCount >= MAX_USERS) {
        return -1;
    }

    strcpy(alerts[alertCount].username, username);
    alerts[alertCount].failed = 0;
    alerts[alertCount].successful = 0;
    alerts[alertCount].risk = 0;
    strcpy(alerts[alertCount].level, "Low");

    alertCount++;
    return alertCount - 1;
}

/* Calculate risk and identify suspicious login activity */
void analyseLogs(void) {
    int i, index;

    if (logCount == 0) {
        printf("\nPlease load sample data first.\n");
        return;
    }

    alertCount = 0;

    for (i = 0; i < logCount; i++) {
        index = findUser(logs[i].username);

        if (index == -1) {
            printf("Alert storage is full.\n");
            return;
        }

        if (logs[i].success == 0) {
            alerts[index].failed++;
        } else {
            alerts[index].successful++;
        }
    }

    for (i = 0; i < alertCount; i++) {
        int score = alerts[i].failed * 20;

        if (alerts[i].failed >= 3) {
            score += 20;
        }

        if (alerts[i].failed >= 5) {
            score += 20;
        }

        if (score > 100) {
            score = 100;
        }

        alerts[i].risk = score;

        if (score >= 80) {
            strcpy(alerts[i].level, "Critical");
        } else if (score >= 60) {
            strcpy(alerts[i].level, "High");
        } else if (score >= 30) {
            strcpy(alerts[i].level, "Medium");
        } else {
            strcpy(alerts[i].level, "Low");
        }
    }

    /* Sort alerts by risk score: highest first */
    for (i = 0; i < alertCount - 1; i++) {
        int j;

        for (j = 0; j < alertCount - i - 1; j++) {
            if (alerts[j].risk < alerts[j + 1].risk) {
                ThreatAlert temp = alerts[j];
                alerts[j] = alerts[j + 1];
                alerts[j + 1] = temp;
            }
        }
    }

    printf("\n========== THREAT ANALYSIS REPORT ==========\n");
    printf("%-15s %-10s %-10s %-10s %-12s\n",
           "Username", "Failed", "Success", "Risk", "Level");
    printf("----------------------------------------------------------\n");

    for (i = 0; i < alertCount; i++) {
        printf("%-15s %-10d %-10d %-10d %-12s\n",
               alerts[i].username,
               alerts[i].failed,
               alerts[i].successful,
               alerts[i].risk,
               alerts[i].level);
    }

    printf("\nAnalysis complete. Alerts ranked by risk.\n");
    printf("Note: Risk scores are rule-based indicators, not proof of an attack.\n");
}

/* Export analysis to a text report */
void exportReport(void) {
    FILE *fp;
    int i;

    if (alertCount == 0) {
        printf("\nAnalyse the logs before exporting the report.\n");
        return;
    }

    fp = fopen("threat_report.txt", "w");

    if (fp == NULL) {
        printf("\nCould not create report file.\n");
        return;
    }

    fprintf(fp, "CYBER THREAT DETECTION SYSTEM\n");
    fprintf(fp, "====================================\n");
    fprintf(fp, "Total logs analysed: %d\n\n", logCount);
    fprintf(fp, "%-15s %-10s %-10s %-10s %-12s\n",
            "Username", "Failed", "Success", "Risk", "Level");

    for (i = 0; i < alertCount; i++) {
        fprintf(fp, "%-15s %-10d %-10d %-10d %-12s\n",
                alerts[i].username,
                alerts[i].failed,
                alerts[i].successful,
                alerts[i].risk,
                alerts[i].level);
    }

    fprintf(fp, "\nRisk scores are rule-based indicators, not proof of attacks.\n");
    fclose(fp);

    printf("\nReport saved as threat_report.txt\n");
}

/* Main menu */
int main(void) {
    int choice;

    do {
        printf("\n========================================\n");
        printf(" INTELLIGENT CYBER THREAT DETECTION\n");
        printf("========================================\n");
        printf("1. Load sample security logs\n");
        printf("2. Display security logs\n");
        printf("3. Analyse threats and calculate risk\n");
        printf("4. Export threat report\n");
       printf("5. Exit\n");
        printf("6. Load logs from CSV file\n");
        printf("Enter your choice: ");

        if (scanf("%d", &choice) != 1) {
            printf("\nInvalid input. Please enter a number.\n");
            while (getchar() != '\n') {
                /* Clear invalid input */
            }
            choice = 0;
            continue;
        }

        switch (choice) {
            case 1:
                loadSampleData();
                break;
            case 2:
                displayLogs();
                break;
            case 3:
                analyseLogs();
                break;
            case 4:
                exportReport();
                break;
            case 5:
                printf("\nThank you for using the system!\n");
                break;
            case 6:
                 loadCSV();
                 break;
            default:
               printf("\nInvalid choice. Select 1 to 6.\n");
        }

    } while (choice != 5);

    return 0;
}