export interface KeyPattern {
  name: string;
  pattern: RegExp;
  severity: "critical" | "high" | "medium" | "low";
}

export const KEY_PATTERNS: KeyPattern[] = [
  // ============================================================================
  // CRITICAL SEVERITY
  // ============================================================================

  // --- AWS ---
  {
    name: "AWS Access Key ID",
    pattern: /(?:^|[^A-Za-z0-9/+=])(?:[\s=:"'`]?((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}))(?:[^A-Za-z0-9/+=]|$)/g,
    severity: "critical",
  },
  {
    name: "AWS Secret Access Key",
    pattern: /(?:aws_secret_access_key|aws_secret_key|aws_secret|secret_access_key)\s*[=:]\s*["']?([A-Za-z0-9/+=]{40})["']?/gi,
    severity: "critical",
  },
  {
    name: "AWS Session Token",
    pattern: /(?:aws_session_token|aws_security_token)\s*[=:]\s*["']?([A-Za-z0-9/+=]{100,})["']?/gi,
    severity: "critical",
  },
  {
    name: "AWS MWS Key",
    pattern: /(amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/g,
    severity: "critical",
  },

  // --- OpenAI ---
  {
    name: "OpenAI API Key (Legacy)",
    pattern: /(sk-[A-Za-z0-9]{20,}T3BlbkFJ[A-Za-z0-9]{20,})/g,
    severity: "critical",
  },
  {
    name: "OpenAI API Key (Project)",
    pattern: /(sk-proj-[A-Za-z0-9_-]{40,})/g,
    severity: "critical",
  },
  {
    name: "OpenAI API Key (Service)",
    pattern: /(sk-svcacct-[A-Za-z0-9_-]{40,})/g,
    severity: "critical",
  },

  // --- Anthropic ---
  {
    name: "Anthropic API Key",
    pattern: /(sk-ant-api03-[A-Za-z0-9_-]{90,})/g,
    severity: "critical",
  },

  // --- GitHub ---
  {
    name: "GitHub Token (Classic)",
    pattern: /(ghp_[A-Za-z0-9]{36,})/g,
    severity: "critical",
  },
  {
    name: "GitHub Token (Fine-grained)",
    pattern: /(github_pat_[A-Za-z0-9_]{22,})/g,
    severity: "critical",
  },
  {
    name: "GitHub App Token",
    pattern: /(ghs_[A-Za-z0-9]{36,})/g,
    severity: "critical",
  },
  {
    name: "GitHub App Refresh Token",
    pattern: /(ghr_[A-Za-z0-9]{36,})/g,
    severity: "critical",
  },

  // --- GitLab ---
  {
    name: "GitLab Personal Access Token",
    pattern: /(glpat-[A-Za-z0-9_-]{20,})/g,
    severity: "critical",
  },
  {
    name: "GitLab Pipeline Token",
    pattern: /(glptt-[A-Za-z0-9_-]{20,})/g,
    severity: "critical",
  },
  {
    name: "GitLab Runner Token",
    pattern: /(glrt-[A-Za-z0-9_-]{20,})/g,
    severity: "critical",
  },

  // --- Slack ---
  {
    name: "Slack Bot Token",
    pattern: /(xoxb-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{24,})/g,
    severity: "critical",
  },
  {
    name: "Slack User Token",
    pattern: /(xoxp-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[A-Fa-f0-9]{32})/g,
    severity: "critical",
  },
  {
    name: "Slack App Token",
    pattern: /(xapp-[0-9]-[A-Z0-9]{10,}-[0-9]{13}-[A-Za-z0-9]{64})/g,
    severity: "critical",
  },
  {
    name: "Slack Legacy Token",
    pattern: /(xoxs-[0-9]{10,}-[0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{10,})/g,
    severity: "critical",
  },

  // --- Stripe ---
  {
    name: "Stripe Secret Key (Live)",
    pattern: /(sk_live_[A-Za-z0-9]{20,})/g,
    severity: "critical",
  },
  {
    name: "Stripe Restricted Key (Live)",
    pattern: /(rk_live_[A-Za-z0-9]{20,})/g,
    severity: "critical",
  },

  // --- SendGrid ---
  {
    name: "SendGrid API Key",
    pattern: /(SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43})/g,
    severity: "critical",
  },

  // --- Twilio ---
  {
    name: "Twilio Auth Token",
    pattern: /(?:twilio[_\s]*(?:auth)?[_\s]*token|TWILIO_AUTH_TOKEN)\s*[=:]\s*["']?([0-9a-f]{32})["']?/gi,
    severity: "critical",
  },
  {
    name: "Twilio Account SID",
    pattern: /(AC[0-9a-f]{32})/g,
    severity: "critical",
  },

  // --- Discord ---
  {
    name: "Discord Bot Token",
    pattern: /([MN][A-Za-z0-9]{23,}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,})/g,
    severity: "critical",
  },
  {
    name: "Discord Webhook URL",
    pattern: /(https:\/\/discord(?:app)?\.com\/api\/webhooks\/\d{17,20}\/[A-Za-z0-9_-]{60,})/g,
    severity: "critical",
  },

  // --- Shopify ---
  {
    name: "Shopify Access Token",
    pattern: /(shpat_[A-Fa-f0-9]{32})/g,
    severity: "critical",
  },
  {
    name: "Shopify Shared Secret",
    pattern: /(shpss_[A-Fa-f0-9]{32})/g,
    severity: "critical",
  },
  {
    name: "Shopify Custom App Token",
    pattern: /(shpca_[A-Fa-f0-9]{32})/g,
    severity: "critical",
  },
  {
    name: "Shopify Private App Token",
    pattern: /(shppa_[A-Fa-f0-9]{32})/g,
    severity: "critical",
  },

  // --- DigitalOcean ---
  {
    name: "DigitalOcean Personal Access Token",
    pattern: /(dop_v1_[a-f0-9]{64})/g,
    severity: "critical",
  },
  {
    name: "DigitalOcean OAuth Token",
    pattern: /(doo_v1_[a-f0-9]{64})/g,
    severity: "critical",
  },
  {
    name: "DigitalOcean Refresh Token",
    pattern: /(dor_v1_[a-f0-9]{64})/g,
    severity: "critical",
  },

  // --- Private Keys ---
  {
    name: "RSA Private Key",
    pattern: /(-----BEGIN RSA PRIVATE KEY-----)/g,
    severity: "critical",
  },
  {
    name: "EC Private Key",
    pattern: /(-----BEGIN EC PRIVATE KEY-----)/g,
    severity: "critical",
  },
  {
    name: "DSA Private Key",
    pattern: /(-----BEGIN DSA PRIVATE KEY-----)/g,
    severity: "critical",
  },
  {
    name: "OpenSSH Private Key",
    pattern: /(-----BEGIN OPENSSH PRIVATE KEY-----)/g,
    severity: "critical",
  },
  {
    name: "PGP Private Key",
    pattern: /(-----BEGIN PGP PRIVATE KEY BLOCK-----)/g,
    severity: "critical",
  },
  {
    name: "Generic Private Key",
    pattern: /(-----BEGIN PRIVATE KEY-----)/g,
    severity: "critical",
  },
  {
    name: "Encrypted Private Key",
    pattern: /(-----BEGIN ENCRYPTED PRIVATE KEY-----)/g,
    severity: "critical",
  },

  // --- Database Connection Strings ---
  {
    name: "MongoDB Connection String",
    pattern: /(mongodb\+srv:\/\/[^\s"'`<>{}|\\^]+:[^\s"'`<>{}|\\^]+@[^\s"'`<>{}|\\^]+)/g,
    severity: "critical",
  },
  {
    name: "MongoDB Connection String (Standard)",
    pattern: /(mongodb:\/\/[^\s"'`<>{}|\\^]+:[^\s"'`<>{}|\\^]+@[^\s"'`<>{}|\\^]+)/g,
    severity: "critical",
  },
  {
    name: "PostgreSQL Connection String",
    pattern: /(postgres(?:ql)?:\/\/[^\s"'`<>{}|\\^]+:[^\s"'`<>{}|\\^]+@[^\s"'`<>{}|\\^]+)/g,
    severity: "critical",
  },
  {
    name: "MySQL Connection String",
    pattern: /(mysql:\/\/[^\s"'`<>{}|\\^]+:[^\s"'`<>{}|\\^]+@[^\s"'`<>{}|\\^]+)/g,
    severity: "critical",
  },
  {
    name: "Redis Connection String",
    pattern: /(redis(?:s)?:\/\/[^\s"'`<>{}|\\^]*:[^\s"'`<>{}|\\^]+@[^\s"'`<>{}|\\^]+)/g,
    severity: "critical",
  },
  {
    name: "MSSQL Connection String",
    pattern: /(mssql:\/\/[^\s"'`<>{}|\\^]+:[^\s"'`<>{}|\\^]+@[^\s"'`<>{}|\\^]+)/g,
    severity: "critical",
  },
  {
    name: "CockroachDB Connection String",
    pattern: /(cockroachdb:\/\/[^\s"'`<>{}|\\^]+:[^\s"'`<>{}|\\^]+@[^\s"'`<>{}|\\^]+)/g,
    severity: "critical",
  },

  // --- Vault ---
  {
    name: "HashiCorp Vault Token",
    pattern: /(hvs\.[A-Za-z0-9_-]{24,})/g,
    severity: "critical",
  },
  {
    name: "HashiCorp Vault Batch Token",
    pattern: /(hvb\.[A-Za-z0-9_-]{24,})/g,
    severity: "critical",
  },

  // --- Doppler ---
  {
    name: "Doppler Service Token",
    pattern: /(dp\.st\.[A-Za-z0-9_-]{40,})/g,
    severity: "critical",
  },
  {
    name: "Doppler CLI Token",
    pattern: /(dp\.ct\.[A-Za-z0-9_-]{40,})/g,
    severity: "critical",
  },
  {
    name: "Doppler SCIM Token",
    pattern: /(dp\.scim\.[A-Za-z0-9_-]{40,})/g,
    severity: "critical",
  },

  // --- Cohere ---
  {
    name: "Cohere API Key",
    pattern: /([a-zA-Z0-9]{40})(?=.*cohere)|(?:cohere[_\s-]*(?:api)?[_\s-]*key)\s*[=:]\s*["']?([a-zA-Z0-9]{40})["']?/gi,
    severity: "critical",
  },

  // --- Databricks ---
  {
    name: "Databricks Access Token",
    pattern: /(dapi[a-f0-9]{32})/g,
    severity: "critical",
  },

  // --- Hugging Face ---
  {
    name: "Hugging Face Token",
    pattern: /(hf_[A-Za-z0-9]{34,})/g,
    severity: "critical",
  },

  // ============================================================================
  // HIGH SEVERITY
  // ============================================================================

  // --- Google ---
  {
    name: "Google API Key",
    pattern: /(AIza[0-9A-Za-z\-_]{35})/g,
    severity: "high",
  },
  {
    name: "Google OAuth Client Secret",
    pattern: /(?:google[_\s-]*)?client[_\s-]*secret\s*[:=]\s*["']([A-Za-z0-9_-]{24,})["']/gi,
    severity: "high",
  },
  {
    name: "Google Cloud Service Account Key",
    pattern: /(?:"type"\s*:\s*"service_account"[\s\S]{0,200}"private_key_id"\s*:\s*"([a-f0-9]{40})")/g,
    severity: "high",
  },
  {
    name: "Google OAuth2 Access Token",
    pattern: /(ya29\.[0-9A-Za-z_-]{50,})/g,
    severity: "high",
  },

  // --- Firebase ---
  {
    name: "Firebase Config API Key",
    pattern: /(?:apiKey)\s*[:=]\s*["']?(AIza[0-9A-Za-z\-_]{35})["']?/gi,
    severity: "high",
  },

  // --- GitHub (lower priority) ---
  {
    name: "GitHub OAuth Token",
    pattern: /(gho_[A-Za-z0-9]{36,})/g,
    severity: "high",
  },

  // --- Slack Webhook ---
  {
    name: "Slack Webhook URL",
    pattern: /(https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]{8,}\/B[A-Z0-9]{8,}\/[A-Za-z0-9]{24,})/g,
    severity: "high",
  },
  {
    name: "Slack Incoming Webhook",
    pattern: /(https:\/\/hooks\.slack\.com\/workflows\/T[A-Z0-9]{8,}\/[A-Za-z0-9/]+)/g,
    severity: "high",
  },

  // --- Twilio API Key ---
  {
    name: "Twilio API Key",
    pattern: /(SK[0-9a-f]{32})/g,
    severity: "high",
  },

  // --- Mailgun ---
  {
    name: "Mailgun API Key",
    pattern: /(key-[0-9a-z]{32})/g,
    severity: "high",
  },
  {
    name: "Mailgun Webhook Signing Key",
    pattern: /(?:mailgun[_\s-]*(?:webhook)?[_\s-]*(?:signing)?[_\s-]*key)\s*[=:]\s*["']?([A-Za-z0-9_-]{30,})["']?/gi,
    severity: "high",
  },

  // --- Mailchimp ---
  {
    name: "Mailchimp API Key",
    pattern: /([a-f0-9]{32}-us\d{1,2})/g,
    severity: "high",
  },

  // --- Heroku ---
  {
    name: "Heroku API Key",
    pattern: /(?:heroku[_\s-]*(?:api)?[_\s-]*key|HEROKU_API_KEY)\s*[=:]\s*["']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})["']?/gi,
    severity: "high",
  },

  // --- Supabase ---
  {
    name: "Supabase Anon/Public Key",
    pattern: /(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,})/g,
    severity: "high",
  },
  {
    name: "Supabase Service Role Key",
    pattern: /(?:supabase[_\s-]*(?:service)?[_\s-]*(?:role)?[_\s-]*key|SUPABASE_SERVICE_ROLE_KEY)\s*[=:]\s*["']?(eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,})["']?/gi,
    severity: "high",
  },

  // --- Telegram ---
  {
    name: "Telegram Bot Token",
    pattern: /(?:telegram|bot[_\s-]*token|TELEGRAM_BOT_TOKEN)\s*[=:]\s*["']?(\d{8,10}:[A-Za-z0-9_-]{35})["']?/gi,
    severity: "high",
  },

  // --- Cloudflare ---
  {
    name: "Cloudflare API Key",
    pattern: /(?:cloudflare[_\s-]*(?:api)?[_\s-]*key|CF_API_KEY)\s*[=:]\s*["']?([0-9a-f]{37})["']?/gi,
    severity: "high",
  },
  {
    name: "Cloudflare API Token",
    pattern: /([A-Za-z0-9_-]{40})(?=.*cloudflare)|(?:cloudflare[_\s-]*(?:api)?[_\s-]*token|CF_API_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9_-]{40})["']?/gi,
    severity: "high",
  },
  {
    name: "Cloudflare Origin CA Key",
    pattern: /(v1\.0-[A-Fa-f0-9]{24}-[A-Fa-f0-9]{146})/g,
    severity: "high",
  },

  // --- npm / PyPI / NuGet / RubyGems ---
  {
    name: "npm Access Token",
    pattern: /(npm_[A-Za-z0-9]{36})/g,
    severity: "high",
  },
  {
    name: "npm Token (Legacy)",
    pattern: /\/\/registry\.npmjs\.org\/:_authToken=([A-Za-z0-9_-]{36,})/g,
    severity: "high",
  },
  {
    name: "PyPI API Token",
    pattern: /(pypi-[A-Za-z0-9_-]{50,})/g,
    severity: "high",
  },
  {
    name: "NuGet API Key",
    pattern: /(?:nuget[_\s-]*(?:api)?[_\s-]*key|NUGET_API_KEY)\s*[=:]\s*["']?([A-Za-z0-9_-]{40,})["']?/gi,
    severity: "high",
  },
  {
    name: "RubyGems API Key",
    pattern: /(rubygems_[A-Fa-f0-9]{48})/g,
    severity: "high",
  },
  {
    name: "Crates.io API Token",
    pattern: /(cio[A-Za-z0-9]{32})/g,
    severity: "high",
  },

  // --- Datadog ---
  {
    name: "Datadog API Key",
    pattern: /(?:datadog[_\s-]*(?:api)?[_\s-]*key|DD_API_KEY)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
    severity: "high",
  },
  {
    name: "Datadog App Key",
    pattern: /(?:datadog[_\s-]*(?:app(?:lication)?)?[_\s-]*key|DD_APP_KEY)\s*[=:]\s*["']?([a-f0-9]{40})["']?/gi,
    severity: "high",
  },

  // --- New Relic ---
  {
    name: "New Relic API Key",
    pattern: /(NRAK-[A-Z0-9]{27})/g,
    severity: "high",
  },
  {
    name: "New Relic Insights Key",
    pattern: /(?:new_relic[_\s-]*insights[_\s-]*key|INSIGHTS_INSERT_KEY)\s*[=:]\s*["']?([A-Za-z0-9_-]{32,})["']?/gi,
    severity: "high",
  },
  {
    name: "New Relic License Key",
    pattern: /(?:new_relic[_\s-]*license[_\s-]*key|NEW_RELIC_LICENSE_KEY)\s*[=:]\s*["']?([a-f0-9]{40})["']?/gi,
    severity: "high",
  },
  {
    name: "New Relic Browser Key",
    pattern: /(NRJS-[A-Fa-f0-9]{19})/g,
    severity: "high",
  },

  // --- Algolia ---
  {
    name: "Algolia API Key",
    pattern: /(?:algolia[_\s-]*(?:api)?[_\s-]*key|ALGOLIA_API_KEY)\s*[=:]\s*["']?([A-Fa-f0-9]{32})["']?/gi,
    severity: "high",
  },
  {
    name: "Algolia Admin Key",
    pattern: /(?:algolia[_\s-]*admin[_\s-]*key|ALGOLIA_ADMIN_KEY)\s*[=:]\s*["']?([A-Fa-f0-9]{32})["']?/gi,
    severity: "high",
  },

  // --- PagerDuty ---
  {
    name: "PagerDuty API Key",
    pattern: /(?:pagerduty[_\s-]*(?:api)?[_\s-]*key|PAGERDUTY_API_KEY)\s*[=:]\s*["']?([A-Za-z0-9_-]{20,})["']?/gi,
    severity: "high",
  },

  // --- Mapbox ---
  {
    name: "Mapbox Public Token",
    pattern: /(pk\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,})/g,
    severity: "high",
  },
  {
    name: "Mapbox Secret Token",
    pattern: /(sk\.eyJ[A-Za-z0-9_-]{50,}\.[A-Za-z0-9_-]{20,})/g,
    severity: "high",
  },

  // --- Okta ---
  {
    name: "Okta API Token",
    pattern: /(?:okta[_\s-]*(?:api)?[_\s-]*token|OKTA_API_TOKEN)\s*[=:]\s*["']?(00[A-Za-z0-9_-]{40,})["']?/gi,
    severity: "high",
  },

  // --- Auth0 ---
  {
    name: "Auth0 Client Secret",
    pattern: /(?:auth0[_\s-]*client[_\s-]*secret|AUTH0_CLIENT_SECRET)\s*[=:]\s*["']?([A-Za-z0-9_-]{32,})["']?/gi,
    severity: "high",
  },
  {
    name: "Auth0 Management API Token",
    pattern: /(?:auth0[_\s-]*(?:management)?[_\s-]*(?:api)?[_\s-]*token|AUTH0_MGMT_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,}\.[A-Za-z0-9_-]{30,})["']?/gi,
    severity: "high",
  },

  // --- Azure ---
  {
    name: "Azure Storage Account Key",
    pattern: /(?:azure[_\s-]*storage[_\s-]*(?:account)?[_\s-]*key|AZURE_STORAGE_KEY|AccountKey)\s*[=:]\s*["']?([A-Za-z0-9/+=]{86,88}==)["']?/gi,
    severity: "high",
  },
  {
    name: "Azure SAS Token",
    pattern: /([?&]sig=[A-Za-z0-9%/+=]{43,}(?:&se=|&sp=|&sv=)[^\s"']*)/g,
    severity: "high",
  },
  {
    name: "Azure DevOps PAT",
    pattern: /(?:azure[_\s-]*devops[_\s-]*pat|AZURE_DEVOPS_PAT|SYSTEM_ACCESSTOKEN)\s*[=:]\s*["']?([A-Za-z0-9]{52,})["']?/gi,
    severity: "high",
  },
  {
    name: "Azure App Secret",
    pattern: /(?:azure[_\s-]*(?:client)?[_\s-]*secret|AZURE_CLIENT_SECRET)\s*[=:]\s*["']?([A-Za-z0-9~._-]{34,})["']?/gi,
    severity: "high",
  },

  // --- Square ---
  {
    name: "Square Access Token",
    pattern: /(sq0atp-[A-Za-z0-9_-]{22,})/g,
    severity: "high",
  },
  {
    name: "Square Access Token (EAAA)",
    pattern: /(EAAAE[A-Za-z0-9]{50,})/g,
    severity: "high",
  },
  {
    name: "Square OAuth Secret",
    pattern: /(sq0csp-[A-Za-z0-9_-]{40,})/g,
    severity: "high",
  },

  // --- Braintree ---
  {
    name: "Braintree Access Token",
    pattern: /(access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32})/g,
    severity: "high",
  },

  // --- CI/CD ---
  {
    name: "CircleCI Token",
    pattern: /(?:circle[_\s-]*(?:ci)?[_\s-]*token|CIRCLECI_TOKEN)\s*[=:]\s*["']?([A-Fa-f0-9]{40})["']?/gi,
    severity: "high",
  },
  {
    name: "Travis CI Token",
    pattern: /(?:travis[_\s-]*(?:ci)?[_\s-]*token|TRAVIS_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9_-]{22,})["']?/gi,
    severity: "high",
  },
  {
    name: "Jenkins API Token",
    pattern: /(?:jenkins[_\s-]*(?:api)?[_\s-]*token|JENKINS_TOKEN)\s*[=:]\s*["']?([A-Fa-f0-9]{32,})["']?/gi,
    severity: "high",
  },
  {
    name: "Vercel Token",
    pattern: /(?:vercel[_\s-]*token|VERCEL_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9]{24,})["']?/gi,
    severity: "high",
  },
  {
    name: "Netlify Token",
    pattern: /(?:netlify[_\s-]*(?:auth)?[_\s-]*token|NETLIFY_AUTH_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9_-]{40,})["']?/gi,
    severity: "high",
  },

  // --- Project Management ---
  {
    name: "Linear API Key",
    pattern: /(lin_api_[A-Za-z0-9]{40,})/g,
    severity: "high",
  },
  {
    name: "Notion Integration Token",
    pattern: /(secret_[A-Za-z0-9]{43})/g,
    severity: "high",
  },
  {
    name: "Notion Token (ntn_)",
    pattern: /(ntn_[A-Za-z0-9]{40,})/g,
    severity: "high",
  },
  {
    name: "Airtable API Key",
    pattern: /(?:airtable[_\s-]*(?:api)?[_\s-]*key|AIRTABLE_API_KEY)\s*[=:]\s*["']?(key[A-Za-z0-9]{14})["']?/gi,
    severity: "high",
  },
  {
    name: "Airtable Personal Access Token",
    pattern: /(pat[A-Za-z0-9]{14}\.[a-f0-9]{64})/g,
    severity: "high",
  },

  // --- Atlassian ---
  {
    name: "Confluence/Jira API Token",
    pattern: /(?:atlassian[_\s-]*(?:api)?[_\s-]*token|JIRA_API_TOKEN|CONFLUENCE_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9]{24,})["']?/gi,
    severity: "high",
  },

  // --- Bitbucket ---
  {
    name: "Bitbucket App Password",
    pattern: /(?:bitbucket[_\s-]*(?:app)?[_\s-]*password|BITBUCKET_APP_PASSWORD)\s*[=:]\s*["']?([A-Za-z0-9]{18,})["']?/gi,
    severity: "high",
  },

  // --- Docker ---
  {
    name: "Docker Hub Personal Access Token",
    pattern: /(dckr_pat_[A-Za-z0-9_-]{27,})/g,
    severity: "high",
  },

  // --- Sentry ---
  {
    name: "Sentry Auth Token",
    pattern: /(sntrys_[A-Za-z0-9_-]{50,})/g,
    severity: "high",
  },
  {
    name: "Sentry DSN",
    pattern: /(https:\/\/[a-f0-9]{32}@(?:o\d+\.)?(?:sentry\.io|[A-Za-z0-9.-]+)\/\d+)/g,
    severity: "high",
  },

  // --- Grafana ---
  {
    name: "Grafana API Key",
    pattern: /(eyJr[A-Za-z0-9_=-]{50,})/g,
    severity: "high",
  },
  {
    name: "Grafana Cloud Token",
    pattern: /(glc_[A-Za-z0-9_=-]{30,})/g,
    severity: "high",
  },
  {
    name: "Grafana Service Account Token",
    pattern: /(glsa_[A-Za-z0-9_=-]{30,})/g,
    severity: "high",
  },

  // --- Lark/Feishu ---
  {
    name: "Lark/Feishu App Token",
    pattern: /(?:lark[_\s-]*(?:app)?[_\s-]*(?:secret|token)|feishu[_\s-]*(?:app)?[_\s-]*(?:secret|token))\s*[=:]\s*["']?([A-Za-z0-9]{30,})["']?/gi,
    severity: "high",
  },

  // --- WeChat ---
  {
    name: "WeChat API Key",
    pattern: /(?:wechat[_\s-]*(?:api)?[_\s-]*(?:key|secret)|WECHAT_SECRET)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
    severity: "high",
  },

  // --- Zendesk ---
  {
    name: "Zendesk API Token",
    pattern: /(?:zendesk[_\s-]*(?:api)?[_\s-]*token|ZENDESK_API_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9]{40,})["']?/gi,
    severity: "high",
  },

  // --- Intercom ---
  {
    name: "Intercom Access Token",
    pattern: /(?:intercom[_\s-]*(?:access)?[_\s-]*token|INTERCOM_ACCESS_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9=_-]{40,})["']?/gi,
    severity: "high",
  },

  // --- HubSpot ---
  {
    name: "HubSpot API Key",
    pattern: /(?:hubspot[_\s-]*(?:api)?[_\s-]*key|HUBSPOT_API_KEY)\s*[=:]\s*["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']?/gi,
    severity: "high",
  },
  {
    name: "HubSpot Private App Token",
    pattern: /(pat-na1-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/g,
    severity: "high",
  },

  // --- Salesforce ---
  {
    name: "Salesforce OAuth Token",
    pattern: /(?:salesforce[_\s-]*(?:oauth)?[_\s-]*token|SALESFORCE_ACCESS_TOKEN|SF_ACCESS_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9!.]{80,})["']?/gi,
    severity: "high",
  },
  {
    name: "Salesforce Refresh Token",
    pattern: /(?:salesforce[_\s-]*refresh[_\s-]*token|SF_REFRESH_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9._!]{80,})["']?/gi,
    severity: "high",
  },

  // --- Analytics ---
  {
    name: "Segment Write Key",
    pattern: /(?:segment[_\s-]*(?:write)?[_\s-]*key|SEGMENT_WRITE_KEY)\s*[=:]\s*["']?([A-Za-z0-9]{32,})["']?/gi,
    severity: "high",
  },
  {
    name: "Mixpanel Token",
    pattern: /(?:mixpanel[_\s-]*(?:project)?[_\s-]*token|MIXPANEL_TOKEN)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
    severity: "high",
  },
  {
    name: "Amplitude API Key",
    pattern: /(?:amplitude[_\s-]*(?:api)?[_\s-]*key|AMPLITUDE_API_KEY)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
    severity: "high",
  },
  {
    name: "Heap Analytics App ID",
    pattern: /(?:heap[_\s-]*(?:app)?[_\s-]*id|HEAP_APP_ID)\s*[=:]\s*["']?([0-9]{8,})["']?/gi,
    severity: "high",
  },

  // --- Feature Flags ---
  {
    name: "LaunchDarkly SDK Key",
    pattern: /(sdk-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})/g,
    severity: "high",
  },
  {
    name: "LaunchDarkly API Key",
    pattern: /(?:launchdarkly[_\s-]*(?:api)?[_\s-]*key|LAUNCHDARKLY_API_KEY)\s*[=:]\s*["']?(api-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']?/gi,
    severity: "high",
  },

  // --- CMS ---
  {
    name: "Contentful Delivery API Key",
    pattern: /(?:contentful[_\s-]*(?:delivery)?[_\s-]*(?:api)?[_\s-]*(?:key|token)|CONTENTFUL_ACCESS_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9_-]{43,})["']?/gi,
    severity: "high",
  },
  {
    name: "Contentful Management Token",
    pattern: /(CFPAT-[A-Za-z0-9_-]{43,})/g,
    severity: "high",
  },
  {
    name: "Prismic API Token",
    pattern: /(?:prismic[_\s-]*(?:api)?[_\s-]*token|PRISMIC_ACCESS_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9._-]{80,})["']?/gi,
    severity: "high",
  },
  {
    name: "Sanity API Token",
    pattern: /(?:sanity[_\s-]*(?:api)?[_\s-]*token|SANITY_TOKEN)\s*[=:]\s*["']?(sk[A-Za-z0-9]{80,})["']?/gi,
    severity: "high",
  },
  {
    name: "Strapi API Token",
    pattern: /(?:strapi[_\s-]*(?:api)?[_\s-]*token|STRAPI_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9]{64,})["']?/gi,
    severity: "high",
  },

  // --- Database Services ---
  {
    name: "PlanetScale Token",
    pattern: /(pscale_tkn_[A-Za-z0-9_-]{40,})/g,
    severity: "high",
  },
  {
    name: "PlanetScale OAuth Token",
    pattern: /(pscale_oauth_[A-Za-z0-9_-]{40,})/g,
    severity: "high",
  },
  {
    name: "Turso Database Token",
    pattern: /(?:turso[_\s-]*(?:database)?[_\s-]*(?:auth)?[_\s-]*token|TURSO_AUTH_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9._-]{100,})["']?/gi,
    severity: "high",
  },
  {
    name: "Upstash Redis Token",
    pattern: /(?:upstash[_\s-]*(?:redis)?[_\s-]*(?:rest)?[_\s-]*token|UPSTASH_REDIS_REST_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9=_-]{30,})["']?/gi,
    severity: "high",
  },
  {
    name: "Neon Database Token",
    pattern: /(?:neon[_\s-]*(?:database)?[_\s-]*(?:api)?[_\s-]*(?:key|token)|NEON_API_KEY)\s*[=:]\s*["']?([A-Za-z0-9_-]{60,})["']?/gi,
    severity: "high",
  },

  // --- CDN / Edge ---
  {
    name: "Fastly API Key",
    pattern: /(?:fastly[_\s-]*(?:api)?[_\s-]*key|FASTLY_API_KEY)\s*[=:]\s*["']?([A-Za-z0-9_-]{32,})["']?/gi,
    severity: "high",
  },

  // --- Infrastructure ---
  {
    name: "Pulumi Access Token",
    pattern: /(pul-[a-f0-9]{40})/g,
    severity: "high",
  },
  {
    name: "Terraform Cloud Token",
    pattern: /(?:terraform[_\s-]*(?:cloud)?[_\s-]*token|TF_TOKEN|TFE_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9._-]{14,})["']?/gi,
    severity: "high",
  },
  {
    name: "Terraform Cloud Token (atlasv1)",
    pattern: /([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9_-]{60,})/g,
    severity: "high",
  },

  // --- API Platforms ---
  {
    name: "Postman API Key",
    pattern: /(PMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34})/g,
    severity: "high",
  },
  {
    name: "RapidAPI Key",
    pattern: /(?:rapidapi[_\s-]*key|X-RapidAPI-Key|RAPIDAPI_KEY)\s*[=:]\s*["']?([A-Za-z0-9]{50})["']?/gi,
    severity: "high",
  },

  // --- Weather / Data APIs ---
  {
    name: "OpenWeatherMap API Key",
    pattern: /(?:openweather(?:map)?[_\s-]*(?:api)?[_\s-]*key|OWM_API_KEY)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
    severity: "high",
  },
  {
    name: "Abstract API Key",
    pattern: /(?:abstract[_\s-]*(?:api)?[_\s-]*key|ABSTRACT_API_KEY)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
    severity: "high",
  },

  // --- Payment ---
  {
    name: "PayPal Client Secret",
    pattern: /(?:paypal[_\s-]*(?:client)?[_\s-]*secret|PAYPAL_CLIENT_SECRET)\s*[=:]\s*["']?([A-Za-z0-9_-]{40,})["']?/gi,
    severity: "high",
  },
  {
    name: "Plaid Client Secret",
    pattern: /(?:plaid[_\s-]*(?:client)?[_\s-]*secret|PLAID_SECRET)\s*[=:]\s*["']?([a-f0-9]{30})["']?/gi,
    severity: "high",
  },
  {
    name: "Coinbase API Key",
    pattern: /(?:coinbase[_\s-]*(?:api)?[_\s-]*(?:key|secret)|COINBASE_API_SECRET)\s*[=:]\s*["']?([A-Za-z0-9]{16,})["']?/gi,
    severity: "high",
  },

  // --- Communication ---
  {
    name: "Vonage/Nexmo API Secret",
    pattern: /(?:vonage[_\s-]*(?:api)?[_\s-]*secret|nexmo[_\s-]*(?:api)?[_\s-]*secret|VONAGE_API_SECRET)\s*[=:]\s*["']?([A-Za-z0-9]{16})["']?/gi,
    severity: "high",
  },
  {
    name: "MessageBird API Key",
    pattern: /(?:messagebird[_\s-]*(?:api)?[_\s-]*key|MESSAGEBIRD_API_KEY)\s*[=:]\s*["']?([A-Za-z0-9]{25})["']?/gi,
    severity: "high",
  },

  // --- Monitoring ---
  {
    name: "Dynatrace API Token",
    pattern: /(dt0c01\.[A-Z0-9]{24}\.[A-Za-z0-9]{64})/g,
    severity: "high",
  },
  {
    name: "Splunk HEC Token",
    pattern: /(?:splunk[_\s-]*(?:hec)?[_\s-]*token|SPLUNK_HEC_TOKEN)\s*[=:]\s*["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']?/gi,
    severity: "high",
  },
  {
    name: "Elastic APM Secret Token",
    pattern: /(?:elastic[_\s-]*(?:apm)?[_\s-]*secret[_\s-]*token|ELASTIC_APM_SECRET_TOKEN)\s*[=:]\s*["']?([A-Za-z0-9_-]{30,})["']?/gi,
    severity: "high",
  },

  // --- Auth / Identity ---
  {
    name: "Clerk Secret Key",
    pattern: /(sk_live_[A-Za-z0-9]{40,})/g,
    severity: "high",
  },
  {
    name: "Clerk Publishable Key",
    pattern: /(pk_live_[A-Za-z0-9]{40,})/g,
    severity: "high",
  },
  {
    name: "Supabase JWT Secret",
    pattern: /(?:supabase[_\s-]*jwt[_\s-]*secret|JWT_SECRET)\s*[=:]\s*["']?([A-Za-z0-9_-]{36,})["']?/gi,
    severity: "high",
  },

  // --- Misc High ---
  {
    name: "Flickr API Key",
    pattern: /(?:flickr[_\s-]*(?:api)?[_\s-]*key|FLICKR_API_KEY)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
    severity: "high",
  },
  {
    name: "Spotify Client Secret",
    pattern: /(?:spotify[_\s-]*(?:client)?[_\s-]*secret|SPOTIFY_CLIENT_SECRET)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
    severity: "high",
  },
  {
    name: "Twitter/X API Key Secret",
    pattern: /(?:twitter[_\s-]*(?:api)?[_\s-]*(?:key)?[_\s-]*secret|TWITTER_API_SECRET)\s*[=:]\s*["']?([A-Za-z0-9]{40,})["']?/gi,
    severity: "high",
  },
  {
    name: "Twitter/X Bearer Token",
    pattern: /(?:twitter[_\s-]*bearer[_\s-]*token|TWITTER_BEARER_TOKEN)\s*[=:]\s*["']?(AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+)["']?/gi,
    severity: "high",
  },
  {
    name: "Facebook App Secret",
    pattern: /(?:facebook[_\s-]*(?:app)?[_\s-]*secret|FB_APP_SECRET|FACEBOOK_APP_SECRET)\s*[=:]\s*["']?([a-f0-9]{32})["']?/gi,
    severity: "high",
  },
  {
    name: "Instagram Access Token",
    pattern: /(?:instagram[_\s-]*(?:access)?[_\s-]*token|INSTAGRAM_ACCESS_TOKEN)\s*[=:]\s*["']?(IGQV[A-Za-z0-9_-]{60,})["']?/gi,
    severity: "high",
  },
  {
    name: "LinkedIn Client Secret",
    pattern: /(?:linkedin[_\s-]*(?:client)?[_\s-]*secret|LINKEDIN_CLIENT_SECRET)\s*[=:]\s*["']?([A-Za-z0-9]{16})["']?/gi,
    severity: "high",
  },
  {
    name: "Dropbox Access Token",
    pattern: /(sl\.[A-Za-z0-9_-]{100,})/g,
    severity: "high",
  },
  {
    name: "ClickUp API Token",
    pattern: /(pk_[0-9]{7,}_[A-Z0-9]{32,})/g,
    severity: "high",
  },
  {
    name: "Asana Personal Access Token",
    pattern: /(?:asana[_\s-]*(?:personal)?[_\s-]*(?:access)?[_\s-]*token|ASANA_ACCESS_TOKEN)\s*[=:]\s*["']?([0-9]{1}\/[0-9]{10,}\/[A-Za-z0-9]{32,})["']?/gi,
    severity: "high",
  },
  {
    name: "Figma Personal Access Token",
    pattern: /(figd_[A-Za-z0-9_-]{40,})/g,
    severity: "high",
  },
  {
    name: "Buildkite Agent Token",
    pattern: /(bkua_[A-Fa-f0-9]{40})/g,
    severity: "high",
  },
  {
    name: "Render API Key",
    pattern: /(rnd_[A-Za-z0-9]{32,})/g,
    severity: "high",
  },
  {
    name: "Fly.io Access Token",
    pattern: /(FlyV1\s+fm[12]_[A-Za-z0-9_-]{40,})/g,
    severity: "high",
  },
  {
    name: "Railway API Token",
    pattern: /([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})(?=.*railway)/gi,
    severity: "high",
  },
  {
    name: "Replicate API Token",
    pattern: /(r8_[A-Za-z0-9]{38,})/g,
    severity: "high",
  },
  {
    name: "Pinecone API Key",
    pattern: /(?:pinecone[_\s-]*(?:api)?[_\s-]*key|PINECONE_API_KEY)\s*[=:]\s*["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']?/gi,
    severity: "high",
  },
  {
    name: "Weaviate API Key",
    pattern: /(?:weaviate[_\s-]*(?:api)?[_\s-]*key|WEAVIATE_API_KEY)\s*[=:]\s*["']?([A-Za-z0-9]{40,})["']?/gi,
    severity: "high",
  },
  {
    name: "Snyk API Token",
    pattern: /(?:snyk[_\s-]*(?:api)?[_\s-]*token|SNYK_TOKEN)\s*[=:]\s*["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']?/gi,
    severity: "high",
  },
  {
    name: "SonarQube Token",
    pattern: /(sqp_[A-Fa-f0-9]{40})/g,
    severity: "high",
  },
  {
    name: "Codecov Token",
    pattern: /(?:codecov[_\s-]*token|CODECOV_TOKEN)\s*[=:]\s*["']?([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})["']?/gi,
    severity: "high",
  },

  // ============================================================================
  // MEDIUM SEVERITY
  // ============================================================================

  // --- Stripe (public-facing) ---
  {
    name: "Stripe Publishable Key (Live)",
    pattern: /(pk_live_[A-Za-z0-9]{20,})/g,
    severity: "medium",
  },

  // --- Generic API Key Patterns ---
  {
    name: "Generic API Key Assignment",
    pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*["']([A-Za-z0-9_\-]{24,})["']/gi,
    severity: "medium",
  },
  {
    name: "Generic API Secret Assignment",
    pattern: /(?:api[_-]?secret)\s*[=:]\s*["']([A-Za-z0-9_\-]{24,})["']/gi,
    severity: "medium",
  },
  {
    name: "Generic API Token Assignment",
    pattern: /(?:api[_-]?token)\s*[=:]\s*["']([A-Za-z0-9_\-]{24,})["']/gi,
    severity: "medium",
  },
  {
    name: "Generic Client Secret Assignment",
    pattern: /(?:client[_-]?secret)\s*[=:]\s*["']([A-Za-z0-9_\-]{24,})["']/gi,
    severity: "medium",
  },
  {
    name: "Generic App Secret Assignment",
    pattern: /(?:app[_-]?secret)\s*[=:]\s*["']([A-Za-z0-9_\-]{24,})["']/gi,
    severity: "medium",
  },

  // --- Generic Secret Patterns ---
  {
    name: "Generic Secret Assignment",
    pattern: /(?:secret)\s*[=:]\s*["']([A-Za-z0-9_\-!@#$%^&*]{16,})["']/gi,
    severity: "medium",
  },
  {
    name: "Generic Password Assignment",
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*["']([^\s"']{12,})["']/gi,
    severity: "medium",
  },
  {
    name: "Generic Encryption Key",
    pattern: /(?:encryption[_-]?key|encrypt[_-]?key|crypto[_-]?key)\s*[=:]\s*["']([A-Za-z0-9_\-/+=]{16,})["']/gi,
    severity: "medium",
  },
  {
    name: "Generic Signing Key",
    pattern: /(?:signing[_-]?key|sign[_-]?key|hmac[_-]?(?:key|secret))\s*[=:]\s*["']([A-Za-z0-9_\-/+=]{16,})["']/gi,
    severity: "medium",
  },

  // --- Generic Token Patterns ---
  {
    name: "Generic Token Assignment",
    pattern: /(?:^|[^a-z])(?:token)\s*[=:]\s*["']([A-Za-z0-9_\-]{24,})["']/gi,
    severity: "medium",
  },
  {
    name: "Generic Access Token Assignment",
    pattern: /(?:access[_-]?token)\s*[=:]\s*["']([A-Za-z0-9_\-]{24,})["']/gi,
    severity: "medium",
  },
  {
    name: "Generic Auth Token Assignment",
    pattern: /(?:auth[_-]?token)\s*[=:]\s*["']([A-Za-z0-9_\-]{24,})["']/gi,
    severity: "medium",
  },
  {
    name: "Generic Refresh Token Assignment",
    pattern: /(?:refresh[_-]?token)\s*[=:]\s*["']([A-Za-z0-9_\-]{24,})["']/gi,
    severity: "medium",
  },

  // --- Authorization Headers ---
  {
    name: "Bearer Token in Authorization Header",
    pattern: /(?:Authorization|authorization)\s*[:=]\s*["']?Bearer\s+([A-Za-z0-9_\-.~+/]+=*)["']?/g,
    severity: "medium",
  },
  {
    name: "Basic Auth in Authorization Header",
    pattern: /(?:Authorization|authorization)\s*[:=]\s*["']?Basic\s+([A-Za-z0-9+/]{20,}={0,2})["']?/g,
    severity: "medium",
  },

  // --- Basic Auth in URL ---
  {
    name: "Basic Auth in URL",
    pattern: /(https?:\/\/[^\s:@"']+:[^\s:@"']+@[^\s"']+)/g,
    severity: "medium",
  },

  // --- Connection Strings ---
  {
    name: "JDBC Connection String with Password",
    pattern: /(jdbc:[a-z]+:\/\/[^\s"'`]+(?:password|pwd)=[^\s;&"'`]+)/gi,
    severity: "medium",
  },
  {
    name: "ODBC Connection String with Password",
    pattern: /(?:odbc|dsn)\s*[=:]\s*["']?[^"']*(?:Password|Pwd)\s*=\s*([^\s;'"]+)/gi,
    severity: "medium",
  },
  {
    name: "SQL Server Connection String",
    pattern: /(?:Server|Data Source)\s*=\s*[^;]+;\s*(?:.*?)\s*(?:Password|Pwd)\s*=\s*([^\s;'"]+)/gi,
    severity: "medium",
  },

  // --- Credentials in Protocols ---
  {
    name: "SMTP Credentials",
    pattern: /(smtp:\/\/[^\s"'`<>]+:[^\s"'`<>]+@[^\s"'`<>]+)/g,
    severity: "medium",
  },
  {
    name: "SMTP Password Configuration",
    pattern: /(?:smtp[_\s-]*password|SMTP_PASSWORD|MAIL_PASSWORD)\s*[=:]\s*["']([^\s"']{8,})["']/gi,
    severity: "medium",
  },
  {
    name: "FTP Credentials",
    pattern: /(ftp:\/\/[^\s"'`<>]+:[^\s"'`<>]+@[^\s"'`<>]+)/g,
    severity: "medium",
  },
  {
    name: "SSH Password in URL",
    pattern: /(ssh:\/\/[^\s"'`<>]+:[^\s"'`<>]+@[^\s"'`<>]+)/g,
    severity: "medium",
  },
  {
    name: "AMQP Connection String",
    pattern: /(amqps?:\/\/[^\s"'`<>]+:[^\s"'`<>]+@[^\s"'`<>]+)/g,
    severity: "medium",
  },

  // --- Webhook URLs ---
  {
    name: "Generic Webhook URL with Token",
    pattern: /(https?:\/\/[^\s"']*webhook[^\s"']*(?:token|key|secret)[=\/][^\s"']+)/gi,
    severity: "medium",
  },
  {
    name: "Teams Webhook URL",
    pattern: /(https:\/\/[a-z0-9]+\.webhook\.office\.com\/webhookb2\/[^\s"']+)/g,
    severity: "medium",
  },

  // --- Environment Variable Patterns ---
  {
    name: "Environment Variable with API Key",
    pattern: /^([A-Z_]*(?:API[_-]?KEY|SECRET[_-]?KEY|ACCESS[_-]?KEY|AUTH[_-]?TOKEN|PRIVATE[_-]?KEY)[A-Z_]*)\s*=\s*["']?([A-Za-z0-9_\-/+=]{16,})["']?\s*$/gm,
    severity: "medium",
  },
  {
    name: "Environment Variable with Password",
    pattern: /^([A-Z_]*(?:PASSWORD|PASSWD|DB_PASS|ADMIN_PASS)[A-Z_]*)\s*=\s*["']?([^\s"']{8,})["']?\s*$/gm,
    severity: "medium",
  },
  {
    name: "Environment Variable with Secret",
    pattern: /^([A-Z_]*(?:SECRET|PRIVATE|CREDENTIAL)[A-Z_]*)\s*=\s*["']?([A-Za-z0-9_\-/+=]{12,})["']?\s*$/gm,
    severity: "medium",
  },

  // --- Infrastructure ---
  {
    name: "Hardcoded IP Address with Port",
    pattern: /((?:10|172\.(?:1[6-9]|2[0-9]|3[01])|192\.168)\.\d{1,3}\.\d{1,3}:\d{2,5})/g,
    severity: "medium",
  },
  {
    name: "S3 Bucket URL",
    pattern: /((?:https?:\/\/)?([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])\.s3(?:\.[a-z0-9-]+)?\.amazonaws\.com(?:\/[^\s"']*)?)/g,
    severity: "medium",
  },
  {
    name: "S3 Bucket URL (Path Style)",
    pattern: /(https?:\/\/s3(?:\.[a-z0-9-]+)?\.amazonaws\.com\/([a-z0-9][a-z0-9.-]{1,61}[a-z0-9])(?:\/[^\s"']*)?)/g,
    severity: "medium",
  },
  {
    name: "GCS Bucket URL",
    pattern: /(https?:\/\/storage\.googleapis\.com\/[a-z0-9][a-z0-9._-]{1,61}[a-z0-9](?:\/[^\s"']*)?)/g,
    severity: "medium",
  },

  // --- Crypto / Blockchain ---
  {
    name: "Infura API Key",
    pattern: /(https:\/\/(?:mainnet|ropsten|rinkeby|kovan|goerli)\.infura\.io\/v3\/[a-f0-9]{32})/g,
    severity: "medium",
  },
  {
    name: "Alchemy API Key",
    pattern: /(https:\/\/[a-z]+-(?:mainnet|goerli)\.g\.alchemy\.com\/v2\/[A-Za-z0-9_-]{32})/g,
    severity: "medium",
  },

  // --- Miscellaneous Medium ---
  {
    name: "Stripe Webhook Secret",
    pattern: /(whsec_[A-Za-z0-9]{32,})/g,
    severity: "medium",
  },
  {
    name: "Twitch Client Secret",
    pattern: /(?:twitch[_\s-]*(?:client)?[_\s-]*secret|TWITCH_CLIENT_SECRET)\s*[=:]\s*["']?([a-z0-9]{30})["']?/gi,
    severity: "medium",
  },
  {
    name: "GitHub Client Secret",
    pattern: /(?:github[_\s-]*(?:client)?[_\s-]*secret|GITHUB_CLIENT_SECRET)\s*[=:]\s*["']?([a-f0-9]{40})["']?/gi,
    severity: "medium",
  },
  {
    name: "Google Maps API Key in URL",
    pattern: /(https:\/\/maps\.googleapis\.com\/maps\/api\/[^\s"']*key=AIza[0-9A-Za-z\-_]{35})/g,
    severity: "medium",
  },
  {
    name: "reCAPTCHA Secret Key",
    pattern: /(?:recaptcha[_\s-]*(?:secret)?[_\s-]*key|RECAPTCHA_SECRET)\s*[=:]\s*["']?([A-Za-z0-9_-]{40})["']?/gi,
    severity: "medium",
  },
  {
    name: "Django Secret Key",
    pattern: /(?:SECRET_KEY|DJANGO_SECRET_KEY)\s*[=:]\s*["']([^\s"']{30,})["']/g,
    severity: "medium",
  },
  {
    name: "Laravel App Key",
    pattern: /(?:APP_KEY)\s*=\s*(?:base64:)?([A-Za-z0-9+/=]{32,})/g,
    severity: "medium",
  },
  {
    name: "Rails Secret Key Base",
    pattern: /(?:secret_key_base)\s*[:=]\s*["']?([a-f0-9]{64,})["']?/gi,
    severity: "medium",
  },
  {
    name: "Flask Secret Key",
    pattern: /(?:FLASK[_\s-]*SECRET[_\s-]*KEY|app\.secret_key)\s*[=:]\s*["']([^\s"']{16,})["']/gi,
    severity: "medium",
  },
  {
    name: "Next.js Auth Secret",
    pattern: /(?:NEXTAUTH_SECRET|AUTH_SECRET)\s*=\s*["']?([A-Za-z0-9_\-/+=]{20,})["']?/g,
    severity: "medium",
  },
  {
    name: "Session Secret",
    pattern: /(?:session[_\s-]*secret|SESSION_SECRET)\s*[=:]\s*["']([^\s"']{16,})["']/gi,
    severity: "medium",
  },
  {
    name: "Cookie Secret",
    pattern: /(?:cookie[_\s-]*secret|COOKIE_SECRET)\s*[=:]\s*["']([^\s"']{16,})["']/gi,
    severity: "medium",
  },
  {
    name: "JWT Secret Key",
    pattern: /(?:jwt[_\s-]*secret(?:[_\s-]*key)?|JWT_SECRET)\s*[=:]\s*["']([^\s"']{16,})["']/gi,
    severity: "medium",
  },
  {
    name: "Database Password Env Var",
    pattern: /(?:DB_PASSWORD|DATABASE_PASSWORD|MYSQL_PASSWORD|POSTGRES_PASSWORD|PGPASSWORD)\s*=\s*["']?([^\s"']{8,})["']?/g,
    severity: "medium",
  },

  // ============================================================================
  // LOW SEVERITY
  // ============================================================================

  // --- Stripe Test Keys ---
  {
    name: "Stripe Secret Key (Test)",
    pattern: /(sk_test_[A-Za-z0-9]{20,})/g,
    severity: "low",
  },
  {
    name: "Stripe Publishable Key (Test)",
    pattern: /(pk_test_[A-Za-z0-9]{20,})/g,
    severity: "low",
  },
  {
    name: "Stripe Restricted Key (Test)",
    pattern: /(rk_test_[A-Za-z0-9]{20,})/g,
    severity: "low",
  },

  // --- Test/Sandbox Keys ---
  {
    name: "Square Sandbox Token",
    pattern: /(sq0atp-[A-Za-z0-9_-]{22,})(?=.*sandbox)/gi,
    severity: "low",
  },
  {
    name: "PayPal Sandbox Credentials",
    pattern: /(?:paypal[_\s-]*sandbox[_\s-]*(?:client)?[_\s-]*(?:id|secret))\s*[=:]\s*["']?([A-Za-z0-9_-]{20,})["']?/gi,
    severity: "low",
  },
  {
    name: "Twilio Test Credentials",
    pattern: /(AC[0-9a-f]{32})(?=.*test)/gi,
    severity: "low",
  },
  {
    name: "Plaid Sandbox Key",
    pattern: /(?:plaid[_\s-]*sandbox[_\s-]*(?:client)?[_\s-]*(?:id|secret))\s*[=:]\s*["']?([A-Za-z0-9_-]{20,})["']?/gi,
    severity: "low",
  },
  {
    name: "Braintree Sandbox Key",
    pattern: /(access_token\$sandbox\$[a-z0-9]{16}\$[a-f0-9]{32})/g,
    severity: "low",
  },

  // --- Expired / Example Patterns ---
  {
    name: "Expired JWT Token",
    pattern: /(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]*"exp"\s*:\s*[0-9]{10}[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{20,})/g,
    severity: "low",
  },
  {
    name: "Example API Key Placeholder",
    pattern: /(?:api[_-]?key|apikey)\s*[=:]\s*["']((?:your|example|test|demo|sample|placeholder|dummy|fake|insert)[_\-]?[A-Za-z0-9_\-]{5,})["']/gi,
    severity: "low",
  },
  {
    name: "TODO/FIXME Secret Marker",
    pattern: /(?:TODO|FIXME|HACK|XXX)[:\s]+.*(?:secret|password|token|key|credential|api.key).*["']([^\s"']{8,})["']/gi,
    severity: "low",
  },

  // --- Development / Local ---
  {
    name: "Localhost Database Connection",
    pattern: /((?:mongodb|postgres|mysql|redis):\/\/[^\s"']*(?:localhost|127\.0\.0\.1)[^\s"']*)/g,
    severity: "low",
  },
  {
    name: "Docker Compose Secret",
    pattern: /(?:MYSQL_ROOT_PASSWORD|POSTGRES_PASSWORD|REDIS_PASSWORD)\s*[:=]\s*["']?([^\s"']{4,})["']?/g,
    severity: "low",
  },
  {
    name: "Development Environment Flag",
    pattern: /(?:NODE_ENV|RAILS_ENV|FLASK_ENV|APP_ENV)\s*=\s*(development|staging)/g,
    severity: "low",
  },

  // --- Weak / Common Secrets ---
  {
    name: "Common Weak Password",
    pattern: /(?:password|passwd|pwd)\s*[=:]\s*["'](password|admin|root|test|123456|letmein|welcome|default|changeme)["']/gi,
    severity: "low",
  },
  {
    name: "Hardcoded Boolean/Flag Secret",
    pattern: /(?:(?:is[_-]?)?(?:debug|verbose|testing|dev[_-]?mode))\s*[=:]\s*["'](true|yes|on)["']/gi,
    severity: "low",
  },
];
