#ifndef GITLEAKS_REGEX_H
#define GITLEAKS_REGEX_H

typedef struct {
    const char *id;
    const char *regex;
} default_rule;

#define DEFAULT_REGEX_COUNT 216

static const default_rule gitleaks_regex_list[DEFAULT_REGEX_COUNT] = {
    {
        .id            = "1password-secret-key",
        .regex         = "\\bA3-[A-Z0-9]{6}-(?:(?:[A-Z0-9]{11})|(?:[A-Z0-9]{6}-[A-Z0-9]{5}))-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\\b",
    },
    {
        .id            = "1password-service-account-token",
        .regex         = "ops_eyJ[a-zA-Z0-9+/]{250,}={0,3}",
    },
    {
        .id            = "adafruit-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:adafruit)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "adobe-client-id",
        .regex         = "(?i)[\\w.-]{0,50}?(?:adobe)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "adobe-client-secret",
        .regex         = "\\b(p8e-(?i)[a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "age-secret-key",
        .regex         = "AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}",
    },
    {
        .id            = "airtable-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:airtable)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{17})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "airtable-personnal-access-token",
        .regex         = "\\b(pat[[:alnum:]]{14}\\.[a-f0-9]{64})\\b",
    },
    {
        .id            = "algolia-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:algolia)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "alibaba-access-key-id",
        .regex         = "\\b(LTAI(?i)[a-z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "alibaba-secret-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:alibaba)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "anthropic-admin-api-key",
        .regex         = "\\b(sk-ant-admin01-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "anthropic-api-key",
        .regex         = "\\b(sk-ant-api03-[a-zA-Z0-9_\\-]{93}AA)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "artifactory-api-key",
        .regex         = "\\bAKCp[A-Za-z0-9]{69}\\b",
    },
    {
        .id            = "artifactory-reference-token",
        .regex         = "\\bcmVmd[A-Za-z0-9]{59}\\b",
    },
    {
        .id            = "asana-client-id",
        .regex         = "(?i)[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "asana-client-secret",
        .regex         = "(?i)[\\w.-]{0,50}?(?:asana)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "authress-service-client-access-key",
        .regex         = "\\b((?:sc|ext|scauth|authress)_(?i)[a-z0-9]{5,30}\\.[a-z0-9]{4,6}\\.(?-i:acc)[_-][a-z0-9-]{10,32}\\.[a-z0-9+/_=-]{30,120})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "aws-access-token",
        .regex         = "\\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\\b",
    },
    {
        .id            = "aws-amazon-bedrock-api-key-long-lived",
        .regex         = "\\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "aws-amazon-bedrock-api-key-short-lived",
        .regex         = "bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t",
    },
    {
        .id            = "azure-ad-client-secret",
        .regex         = "(?:^|[\\\\'\"\\x60\\s>=:(,)])([a-zA-Z0-9_~.]{3}\\dQ~[a-zA-Z0-9_~.-]{31,34})(?:$|[\\\\'\"\\x60\\s<),])",
    },
    {
        .id            = "beamer-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:beamer)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(b_[a-z0-9=_\\-]{44})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "bitbucket-client-id",
        .regex         = "(?i)[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "bitbucket-client-secret",
        .regex         = "(?i)[\\w.-]{0,50}?(?:bitbucket)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "bittrex-access-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "bittrex-secret-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:bittrex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "cisco-meraki-api-key",
        .regex         = "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:(?-i:[Mm]eraki|MERAKI))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "clickhouse-cloud-api-secret-key",
        .regex         = "\\b(4b1d[A-Za-z0-9]{38})\\b",
    },
    {
        .id            = "clojars-api-token",
        .regex         = "(?i)CLOJARS_[a-z0-9]{60}",
    },
    {
        .id            = "cloudflare-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "cloudflare-global-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:cloudflare)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{37})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "cloudflare-origin-ca-key",
        .regex         = "\\b(v1\\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "codecov-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:codecov)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "cohere-api-token",
        .regex         = "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:cohere|CO_API_KEY)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-zA-Z0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "coinbase-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:coinbase)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "confluent-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "confluent-secret-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:confluent)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "contentful-delivery-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:contentful)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{43})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "curl-auth-header",
        .regex         = "\\bcurl\\b(?:.*?|.*?(?:[\\r\\n]{1,2}.*?){1,5})[ \\t\\n\\r](?:-H|--header)(?:=|[ \\t]{0,5})(?:\"(?i)(?:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))\"|'(?i)(?:Authorization:[ \\t]{0,5}(?:Basic[ \\t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \\t]([\\w=~@.+/-]{8,})|([\\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \\t]{0,5}([\\w=~@.+/-]{8,}))')(?:\\B|\\s|\\z)",
    },
    {
        .id            = "curl-auth-user",
        .regex         = "\\bcurl\\b(?:.*|.*(?:[\\r\\n]{1,2}.*){1,5})[ \\t\\n\\r](?:-u|--user)(?:=|[ \\t]{0,5})(\"(:[^\"]{3,}|[^:\"]{3,}:|[^:\"]{3,}:[^\"]{3,})\"|'([^:']{3,}:[^']{3,})'|((?:\"[^\"]{3,}\"|'[^']{3,}'|[\\w$@.-]+):(?:\"[^\"]{3,}\"|'[^']{3,}'|[\\w${}@.-]+)))(?:\\s|\\z)",
    },
    {
        .id            = "databricks-api-token",
        .regex         = "\\b(dapi[a-f0-9]{32}(?:-\\d)?)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "datadog-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:datadog)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "defined-networking-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:dnkey)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(dnkey-[a-z0-9=_\\-]{26}-[a-z0-9=_\\-]{52})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "digitalocean-access-token",
        .regex         = "\\b(doo_v1_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "digitalocean-pat",
        .regex         = "\\b(dop_v1_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "digitalocean-refresh-token",
        .regex         = "(?i)\\b(dor_v1_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "discord-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "discord-client-id",
        .regex         = "(?i)[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{18})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "discord-client-secret",
        .regex         = "(?i)[\\w.-]{0,50}?(?:discord)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "doppler-api-token",
        .regex         = "dp\\.pt\\.(?i)[a-z0-9]{43}",
    },
    {
        .id            = "droneci-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:droneci)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "dropbox-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{15})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "dropbox-long-lived-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\\-_=]{43})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "dropbox-short-lived-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:dropbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(sl\\.[a-z0-9\\-=_]{135})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "duffel-api-token",
        .regex         = "duffel_(?:test|live)_(?i)[a-z0-9_\\-=]{43}",
    },
    {
        .id            = "dynatrace-api-token",
        .regex         = "dt0c01\\.(?i)[a-z0-9]{24}\\.[a-z0-9]{64}",
    },
    {
        .id            = "easypost-api-token",
        .regex         = "\\bEZAK(?i)[a-z0-9]{54}\\b",
    },
    {
        .id            = "easypost-test-api-token",
        .regex         = "\\bEZTK(?i)[a-z0-9]{54}\\b",
    },
    {
        .id            = "etsy-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:(?-i:ETSY|[Ee]tsy))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "facebook-access-token",
        .regex         = "(?i)\\b(\\d{15,16}(\\||%)[0-9a-z\\-_]{27,40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "facebook-secret",
        .regex         = "(?i)[\\w.-]{0,50}?(?:facebook)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "fastly-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:fastly)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "finicity-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:finicity)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "finicity-client-secret",
        .regex         = "(?i)[\\w.-]{0,50}?(?:finicity)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "finnhub-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:finnhub)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "flickr-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:flickr)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "flutterwave-encryption-key",
        .regex         = "FLWSECK_TEST-(?i)[a-h0-9]{12}",
    },
    {
        .id            = "flutterwave-public-key",
        .regex         = "FLWPUBK_TEST-(?i)[a-h0-9]{32}-X",
    },
    {
        .id            = "flutterwave-secret-key",
        .regex         = "FLWSECK_TEST-(?i)[a-h0-9]{32}-X",
    },
    {
        .id            = "flyio-access-token",
        .regex         = "\\b((?:fo1_[\\w-]{43}|fm1[ar]_[a-zA-Z0-9+\\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\\/]{100,}={0,3}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "frameio-api-token",
        .regex         = "fio-u-(?i)[a-z0-9\\-_=]{64}",
    },
    {
        .id            = "freemius-secret-key",
        .regex         = "(?i)[\"']secret_key[\"']\\s*=>\\s*[\"'](sk_[\\S]{29})[\"']",
    },
    {
        .id            = "freshbooks-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:freshbooks)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "gcp-api-key",
        .regex         = "\\b(AIza[\\w-]{35})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "generic-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:access|auth|(?-i:[Aa]pi|API)|credential|creds|key|passw(?:or)?d|secret|token)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([\\w.=-]{10,150}|[a-z0-9][a-z0-9+/]{11,}={0,3})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "github-app-token",
        .regex         = "(?:ghu|ghs)_[0-9a-zA-Z]{36}",
    },
    {
        .id            = "github-fine-grained-pat",
        .regex         = "github_pat_\\w{82}",
    },
    {
        .id            = "github-oauth",
        .regex         = "gho_[0-9a-zA-Z]{36}",
    },
    {
        .id            = "github-pat",
        .regex         = "ghp_[0-9a-zA-Z]{36}",
    },
    {
        .id            = "github-refresh-token",
        .regex         = "ghr_[0-9a-zA-Z]{36}",
    },
    {
        .id            = "gitlab-cicd-job-token",
        .regex         = "glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}",
    },
    {
        .id            = "gitlab-deploy-token",
        .regex         = "gldt-[0-9a-zA-Z_\\-]{20}",
    },
    {
        .id            = "gitlab-feature-flag-client-token",
        .regex         = "glffct-[0-9a-zA-Z_\\-]{20}",
    },
    {
        .id            = "gitlab-feed-token",
        .regex         = "glft-[0-9a-zA-Z_\\-]{20}",
    },
    {
        .id            = "gitlab-incoming-mail-token",
        .regex         = "glimt-[0-9a-zA-Z_\\-]{25}",
    },
    {
        .id            = "gitlab-kubernetes-agent-token",
        .regex         = "glagent-[0-9a-zA-Z_\\-]{50}",
    },
    {
        .id            = "gitlab-oauth-app-secret",
        .regex         = "gloas-[0-9a-zA-Z_\\-]{64}",
    },
    {
        .id            = "gitlab-pat",
        .regex         = "glpat-[\\w-]{20}",
    },
    {
        .id            = "gitlab-pat-routable",
        .regex         = "\\bglpat-[0-9a-zA-Z_-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
    },
    {
        .id            = "gitlab-ptt",
        .regex         = "glptt-[0-9a-f]{40}",
    },
    {
        .id            = "gitlab-rrt",
        .regex         = "GR1348941[\\w-]{20}",
    },
    {
        .id            = "gitlab-runner-authentication-token",
        .regex         = "glrt-[0-9a-zA-Z_\\-]{20}",
    },
    {
        .id            = "gitlab-runner-authentication-token-routable",
        .regex         = "\\bglrt-t\\d_[0-9a-zA-Z_\\-]{27,300}\\.[0-9a-z]{2}[0-9a-z]{7}\\b",
    },
    {
        .id            = "gitlab-scim-token",
        .regex         = "glsoat-[0-9a-zA-Z_\\-]{20}",
    },
    {
        .id            = "gitlab-session-cookie",
        .regex         = "_gitlab_session=[0-9a-z]{32}",
    },
    {
        .id            = "gitter-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:gitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "gocardless-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:gocardless)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(live_(?i)[a-z0-9\\-_=]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "grafana-cloud-api-token",
        .regex         = "(?i)\\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "grafana-service-account-token",
        .regex         = "(?i)\\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "harness-api-key",
        .regex         = "(?:pat|sat)\\.[a-zA-Z0-9_-]{22}\\.[a-zA-Z0-9]{24}\\.[a-zA-Z0-9]{20}",
    },
    {
        .id            = "hashicorp-tf-api-token",
        .regex         = "(?i)[a-z0-9]{14}\\.(?-i:atlasv1)\\.[a-z0-9\\-_=]{60,70}",
    },
    {
        .id            = "hashicorp-tf-password",
        .regex         = "(?i)[\\w.-]{0,50}?(?:administrator_login_password|password)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(\"[a-z0-9=_\\-]{8,20}\")(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "heroku-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:heroku)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "heroku-api-key-v2",
        .regex         = "\\b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "hubspot-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:hubspot)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "huggingface-access-token",
        .regex         = "\\b(hf_(?i:[a-z]{34}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "huggingface-organization-api-token",
        .regex         = "\\b(api_org_(?i:[a-z]{34}))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "infracost-api-token",
        .regex         = "\\b(ico-[a-zA-Z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "intercom-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:intercom)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{60})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "intra42-client-secret",
        .regex         = "\\b(s-s4t2(?:ud|af)-(?i)[abcdef0123456789]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "jfrog-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{73})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "jfrog-identity-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "jwt",
        .regex         = "\\b(ey[a-zA-Z0-9]{17,}\\.ey[a-zA-Z0-9\\/\\\\_-]{17,}\\.(?:[a-zA-Z0-9\\/\\\\_-]{10,}={0,2})?)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "jwt-base64",
        .regex         = "\\bZXlK(?:(?P<alg>aGJHY2lPaU)|(?P<apu>aGNIVWlPaU)|(?P<apv>aGNIWWlPaU)|(?P<aud>aGRXUWlPaU)|(?P<b64>aU5qUWlP)|(?P<crit>amNtbDBJanBi)|(?P<cty>amRIa2lPaU)|(?P<epk>bGNHc2lPbn)|(?P<enc>bGJtTWlPaU)|(?P<jku>cWEzVWlPaU)|(?P<jwk>cWQyc2lPb)|(?P<iss>cGMzTWlPaU)|(?P<iv>cGRpSTZJ)|(?P<kid>cmFXUWlP)|(?P<key_ops>clpYbGZiM0J6SWpwY)|(?P<kty>cmRIa2lPaUp)|(?P<nonce>dWIyNWpaU0k2)|(?P<p2c>d01tTWlP)|(?P<p2s>d01uTWlPaU)|(?P<ppt>d2NIUWlPaU)|(?P<sub>emRXSWlPaU)|(?P<svt>emRuUWlP)|(?P<tag>MFlXY2lPaU)|(?P<typ>MGVYQWlPaUp)|(?P<url>MWNtd2l)|(?P<use>MWMyVWlPaUp)|(?P<ver>MlpYSWlPaU)|(?P<version>MlpYSnphVzl1SWpv)|(?P<x>NElqb2)|(?P<x5c>NE5XTWlP)|(?P<x5t>NE5YUWlPaU)|(?P<x5ts256>NE5YUWpVekkxTmlJNkl)|(?P<x5u>NE5YVWlPaU)|(?P<zip>NmFYQWlPaU))[a-zA-Z0-9\\/\\\\_+\\-\\r\\n]{40,}={0,2}",
    },
    {
        .id            = "kucoin-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:kucoin)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "kucoin-secret-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:kucoin)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "launchdarkly-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:launchdarkly)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "linear-api-key",
        .regex         = "lin_api_(?i)[a-z0-9]{40}",
    },
    {
        .id            = "linear-client-secret",
        .regex         = "(?i)[\\w.-]{0,50}?(?:linear)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "linkedin-client-id",
        .regex         = "(?i)[\\w.-]{0,50}?(?:linked[_-]?in)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{14})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "linkedin-client-secret",
        .regex         = "(?i)[\\w.-]{0,50}?(?:linked[_-]?in)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "lob-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((live|test)_[a-f0-9]{35})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "lob-pub-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:lob)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((test|live)_pub_[a-f0-9]{31})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "looker-client-id",
        .regex         = "(?i)[\\w.-]{0,50}?(?:looker)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "looker-client-secret",
        .regex         = "(?i)[\\w.-]{0,50}?(?:looker)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "mailchimp-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:MailchimpSDK.initialize|mailchimp)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{32}-us\\d\\d)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "mailgun-private-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(key-[a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "mailgun-pub-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(pubkey-[a-f0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "mailgun-signing-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:mailgun)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "mapbox-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:mapbox)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(pk\\.[a-z0-9]{60}\\.[a-z0-9]{22})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "mattermost-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:mattermost)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{26})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "maxmind-license-key",
        .regex         = "\\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "messagebird-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:message[_-]?bird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{25})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "messagebird-client-id",
        .regex         = "(?i)[\\w.-]{0,50}?(?:message[_-]?bird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "microsoft-teams-webhook",
        .regex         = "https://[a-z0-9]+\\.webhook\\.office\\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}",
    },
    {
        .id            = "netlify-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:netlify)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{40,46})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "new-relic-browser-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(NRJS-[a-f0-9]{19})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "new-relic-insert-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(NRII-[a-z0-9-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "new-relic-user-api-id",
        .regex         = "(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "new-relic-user-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(NRAK-[a-z0-9]{27})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "notion-api-token",
        .regex         = "\\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "npm-access-token",
        .regex         = "(?i)\\b(npm_[a-z0-9]{36})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "nuget-config-password",
        .regex         = "(?i)<add key=\\\"(?:(?:ClearText)?Password)\\\"\\s*value=\\\"(.{8,})\\\"\\s*/>",
    },
    {
        .id            = "nytimes-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:nytimes|new-york-times,|newyorktimes)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9=_\\-]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "octopus-deploy-api-key",
        .regex         = "\\b(API-[A-Z0-9]{26})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "okta-access-token",
        .regex         = "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:(?-i:[Oo]kta|OKTA))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(00[\\w=\\-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "openai-api-key",
        .regex         = "\\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "openshift-user-token",
        .regex         = "\\b(sha256~[\\w-]{43})(?:[^\\w-]|\\z)",
    },
    {
        .id            = "perplexity-api-key",
        .regex         = "\\b(pplx-[a-zA-Z0-9]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$|\\b)",
    },
    {
        .id            = "plaid-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "plaid-client-id",
        .regex         = "(?i)[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{24})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "plaid-secret-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:plaid)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "planetscale-api-token",
        .regex         = "\\b(pscale_tkn_(?i)[\\w=\\.-]{32,64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "planetscale-oauth-token",
        .regex         = "\\b(pscale_oauth_[\\w=\\.-]{32,64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "planetscale-password",
        .regex         = "(?i)\\b(pscale_pw_(?i)[\\w=\\.-]{32,64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "postman-api-token",
        .regex         = "\\b(PMAK-(?i)[a-f0-9]{24}\\-[a-f0-9]{34})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "prefect-api-token",
        .regex         = "\\b(pnu_[a-zA-Z0-9]{36})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "private-key",
        .regex         = "(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\\s\\S-]{64,}?KEY(?: BLOCK)?-----",
    },
    {
        .id            = "privateai-api-token",
        .regex         = "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:private[_-]?ai)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{32})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "pulumi-api-token",
        .regex         = "\\b(pul-[a-f0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "pypi-upload-token",
        .regex         = "pypi-AgEIcHlwaS5vcmc[\\w-]{50,1000}",
    },
    {
        .id            = "rapidapi-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:rapidapi)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9_-]{50})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "readme-api-token",
        .regex         = "\\b(rdme_[a-z0-9]{70})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "rubygems-api-token",
        .regex         = "\\b(rubygems_[a-f0-9]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "scalingo-api-token",
        .regex         = "\\b(tk-us-[\\w-]{48})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "sendbird-access-id",
        .regex         = "(?i)[\\w.-]{0,50}?(?:sendbird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "sendbird-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:sendbird)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "sendgrid-api-token",
        .regex         = "\\b(SG\\.(?i)[a-z0-9=_\\-\\.]{66})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "sendinblue-api-token",
        .regex         = "\\b(xkeysib-[a-f0-9]{64}\\-(?i)[a-z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "sentry-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:sentry)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "sentry-org-token",
        .regex         = "\\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|\\z)",
    },
    {
        .id            = "sentry-user-token",
        .regex         = "\\b(sntryu_[a-f0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "settlemint-application-access-token",
        .regex         = "\\b(sm_aat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "settlemint-personal-access-token",
        .regex         = "\\b(sm_pat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "settlemint-service-access-token",
        .regex         = "\\b(sm_sat_[a-zA-Z0-9]{16})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "shippo-api-token",
        .regex         = "\\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "shopify-access-token",
        .regex         = "shpat_[a-fA-F0-9]{32}",
    },
    {
        .id            = "shopify-custom-access-token",
        .regex         = "shpca_[a-fA-F0-9]{32}",
    },
    {
        .id            = "shopify-private-app-access-token",
        .regex         = "shppa_[a-fA-F0-9]{32}",
    },
    {
        .id            = "shopify-shared-secret",
        .regex         = "shpss_[a-fA-F0-9]{32}",
    },
    {
        .id            = "sidekiq-secret",
        .regex         = "(?i)[\\w.-]{0,50}?(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "sidekiq-sensitive-url",
        .regex         = "(?i)\\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\\/|\\#|\\?|:]|$)",
    },
    {
        .id            = "slack-app-token",
        .regex         = "(?i)xapp-\\d-[A-Z0-9]+-\\d+-[a-z0-9]+",
    },
    {
        .id            = "slack-bot-token",
        .regex         = "xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*",
    },
    {
        .id            = "slack-config-access-token",
        .regex         = "(?i)xoxe.xox[bp]-\\d-[A-Z0-9]{163,166}",
    },
    {
        .id            = "slack-config-refresh-token",
        .regex         = "(?i)xoxe-\\d-[A-Z0-9]{146}",
    },
    {
        .id            = "slack-legacy-bot-token",
        .regex         = "xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}",
    },
    {
        .id            = "slack-legacy-token",
        .regex         = "xox[os]-\\d+-\\d+-\\d+-[a-fA-F\\d]+",
    },
    {
        .id            = "slack-legacy-workspace-token",
        .regex         = "xox[ar]-(?:\\d-)?[0-9a-zA-Z]{8,48}",
    },
    {
        .id            = "slack-user-token",
        .regex         = "xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}",
    },
    {
        .id            = "slack-webhook-url",
        .regex         = "(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}",
    },
    {
        .id            = "snyk-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "sonar-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:sonar[_.-]?(login|token))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_\\-]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "sourcegraph-access-token",
        .regex         = "(?i)\\b(\\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\\b)(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "square-access-token",
        .regex         = "\\b((?:EAAA|sq0atp-)[\\w-]{22,60})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "squarespace-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:squarespace)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "stripe-access-token",
        .regex         = "\\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "sumologic-access-id",
        .regex         = "[\\w.-]{0,50}?(?i:[\\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3})(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(su[a-zA-Z0-9]{12})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "sumologic-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{64})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "telegram-bot-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:telegr)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{5,16}:(?-i:A)[a-z0-9_\\-]{34})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "travisci-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:travis)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{22})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "twilio-api-key",
        .regex         = "SK[0-9a-fA-F]{32}",
    },
    {
        .id            = "twitch-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:twitch)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{30})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "twitter-access-secret",
        .regex         = "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{45})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "twitter-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "twitter-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{25})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "twitter-api-secret",
        .regex         = "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{50})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "twitter-bearer-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:twitter)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "typeform-api-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:typeform)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(tfp_[a-z0-9\\-_\\.=]{59})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "vault-batch-token",
        .regex         = "\\b(hvb\\.[\\w-]{138,300})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "vault-service-token",
        .regex         = "\\b((?:hvs\\.[\\w-]{90,120}|s\\.(?i:[a-z0-9]{24})))(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "yandex-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(t1\\.[A-Z0-9a-z_-]+[=]{0,2}\\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "yandex-api-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(AQVN[A-Za-z0-9_\\-]{35,38})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "yandex-aws-access-token",
        .regex         = "(?i)[\\w.-]{0,50}?(?:yandex)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}(YC[a-zA-Z0-9_\\-]{38})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
    {
        .id            = "zendesk-secret-key",
        .regex         = "(?i)[\\w.-]{0,50}?(?:zendesk)(?:[ \\t\\w.-]{0,20})[\\s'\"]{0,3}(?:=|>|:{1,3}=|\\|\\||:|=>|\\?=|,)[\\x60'\"\\s=]{0,5}([a-z0-9]{40})(?:[\\x60'\"\\s;]|\\\\[nr]|$)",
    },
};

/* Macro */
#define LEAK_RULE_ID(i)       (gitleaks_regex_list[i].id)
#define LEAK_RULE_REGEX(i)    (gitleaks_regex_list[i].regex)

#endif /* DEFAULT_REGEX_H */
