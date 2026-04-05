#ifndef SECRETS_H
#define SECRETS_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

static inline int secrets_push_offset(
    uint64_t **vec,
    size_t *count,
    size_t *cap,
    uint64_t off
) {
    if (*count == *cap) {
        size_t new_cap = (*cap == 0) ? 16u : (*cap << 1);
        if (new_cap < *cap) return 0;

        uint64_t *tmp = (uint64_t *)realloc(*vec, new_cap * sizeof(uint64_t));
        if (tmp == NULL) return 0;

        *vec = tmp;
        *cap = new_cap;
    }

    (*vec)[(*count)++] = off;
    return 1;
}

static inline uint64_t* find_all_secrets(
    const char *s,
    size_t len,
    size_t *out_count
) {
    const unsigned char *base;
    const unsigned char *YYCURSOR;
    const unsigned char *YYLIMIT;
    const unsigned char *YYMARKER = NULL;
    const unsigned char *match;

    uint64_t *results = NULL;
    size_t count = 0;
    size_t capacity = 0;

    if (out_count == NULL) return NULL;
    *out_count = 0;

    if (s == NULL || len == 0) return NULL;

    base = (const unsigned char *)s;
    YYCURSOR = base;
    YYLIMIT = base + len;
    (void)YYMARKER;

#define SECRETS_HIT()                                                        \
    do {                                                                     \
        if (!secrets_push_offset(                                            \
                &results, &count, &capacity, (uint64_t)(match - base))) {    \
            goto oom;                                                        \
        }                                                                    \
        goto scan;                                                           \
    } while (0)

scan:
    if (YYCURSOR >= YYLIMIT) goto done;
    match = YYCURSOR;

    /*!re2c
        re2c:define:YYCTYPE = "unsigned char";
        re2c:yyfill:enable = 0;

        DIGIT      = [0-9];
        HEX        = [0-9A-Fa-f];
        UPPERNUM   = [A-Z0-9];
        ALNUM      = [A-Za-z0-9];
        ALNUM_US   = [A-Za-z0-9_];
        ALNUM_DASH = [A-Za-z0-9_-];
        B64URL     = [A-Za-z0-9_-];

        /*
         * High-confidence tokens / keys
         */

        AWS_ACCESS_KEY =
              "AKIA" UPPERNUM{16}
            | "ASIA" UPPERNUM{16}
            ;

        GITHUB_TOKEN =
              "ghp_" ALNUM{36}
            | "gho_" ALNUM{36}
            | "ghu_" ALNUM{36}
            | "ghs_" ALNUM{36}
            | "ghr_" ALNUM{36}
            ;

        GITHUB_FINE_GRAINED =
            "github_pat_" ALNUM_US{82};

        GITLAB_PAT =
            "glpat-" ALNUM_DASH{20};

        GOOGLE_API_KEY =
            "AIza" B64URL{35};

        SLACK_TOKEN =
              "xoxb-" DIGIT{10,13} "-" DIGIT{10,13} "-" ALNUM{24}
            | "xoxp-" DIGIT{10,13} "-" DIGIT{10,13} "-" ALNUM{24}
            | "xoxa-" DIGIT{10,13} "-" DIGIT{10,13} "-" ALNUM{24}
            | "xoxr-" DIGIT{10,13} "-" DIGIT{10,13} "-" ALNUM{24}
            | "xoxs-" DIGIT{10,13} "-" DIGIT{10,13} "-" ALNUM{24}
            ;

        SLACK_WEBHOOK =
            "https://hooks.slack.com/services/T" ALNUM{8,12}
            "/B" ALNUM{8,12}
            "/" B64URL{20,30};

        STRIPE_LIVE =
              "sk_live_" ALNUM{24}
            | "rk_live_" ALNUM{24}
            ;

        SENDGRID =
            "SG." B64URL{22} "." B64URL{43};

        NPM_TOKEN =
            "npm_" ALNUM{36};

        SHOPIFY_PAT =
            "shpat_" HEX{32};

        TWILIO_KEY =
            "SK" HEX{32};

        PRIVATE_KEY =
              "-----BEGIN RSA PRIVATE KEY-----"
            | "-----BEGIN DSA PRIVATE KEY-----"
            | "-----BEGIN EC PRIVATE KEY-----"
            | "-----BEGIN OPENSSH PRIVATE KEY-----"
            | "-----BEGIN PGP PRIVATE KEY BLOCK-----"
            | "-----BEGIN PRIVATE KEY-----"
            | "-----BEGIN ENCRYPTED PRIVATE KEY-----"
            ;

        /*
         * Order: più specifici prima, fallback dopo.
         */

        GITHUB_FINE_GRAINED { SECRETS_HIT(); }
        GITHUB_TOKEN        { SECRETS_HIT(); }
        GITLAB_PAT          { SECRETS_HIT(); }
        AWS_ACCESS_KEY      { SECRETS_HIT(); }
        GOOGLE_API_KEY      { SECRETS_HIT(); }
        SLACK_TOKEN         { SECRETS_HIT(); }
        SLACK_WEBHOOK       { SECRETS_HIT(); }
        STRIPE_LIVE         { SECRETS_HIT(); }
        SENDGRID            { SECRETS_HIT(); }
        NPM_TOKEN           { SECRETS_HIT(); }
        SHOPIFY_PAT         { SECRETS_HIT(); }
        TWILIO_KEY          { SECRETS_HIT(); }
        PRIVATE_KEY         { SECRETS_HIT(); }

        $                   { goto done; }
        *                   { goto scan; }
    */

done:
    *out_count = count;
    goto finish;

oom:
    free(results);
    results = NULL;
    *out_count = 0;

finish:
#undef SECRETS_HIT
    return results;
}

#endif /* SECRETS_H */
