# Attachra --- Project Vision

## Vision

Attachra is an open-core, self-hosted Attachment Policy Engine for
enterprise email systems.

Mission: become for attachment lifecycle management what Rspamd is for
spam filtering.

## Core Principles

-   Open Core
-   Self-hosted first
-   API-first
-   Plugin-first
-   Policy-driven
-   Transport agnostic
-   Storage agnostic
-   Enterprise ready
-   Community edition must be production-ready

## Initial Scope

Outbound email attachment management:

-   Postfix Milter integration
-   Detect attachments
-   Evaluate policies
-   Upload files to S3-compatible storage
-   Replace attachments with recipient-specific links
-   Rewrite MIME message
-   Track downloads
-   Revoke links
-   Audit events
-   REST API
-   Web UI
-   CLI

## Future Scope

Inbound attachment processing:

-   Attachment quarantine
-   Antivirus
-   DLP
-   OCR
-   Sandbox
-   Safe Preview
-   Approval workflows

## Architecture

Core components:

-   Policy Engine
-   Storage Engine
-   Link Engine
-   Statistics
-   Audit
-   REST API
-   Plugin Loader
-   Web UI
-   CLI

Adapters:

-   Postfix Milter (MVP)
-   SMTP Proxy
-   Exchange (future)
-   Stalwart (future)
-   Exim (future)
-   Haraka (future)

Storage:

-   S3
-   MinIO
-   Ceph
-   Filesystem
-   Azure Blob (future)
-   Google Cloud Storage (future)
-   Wasabi / Backblaze (future)

## Plugin Ecosystem

Official plugin SDK.

Preferred execution model: - WebAssembly (WASI) for sandboxed plugins.

Plugin examples:

-   LDAP
-   Active Directory
-   OIDC
-   SAML
-   VirusTotal
-   ICAP
-   YARA
-   OCR
-   Slack
-   Teams
-   Telegram
-   Splunk
-   Elastic
-   Wazuh
-   QRadar

Marketplace sections:

-   Official
-   Verified
-   Community

## Policy Engine

Human-readable declarative policies.

Example concepts:

-   sender
-   recipient
-   attachment
-   storage
-   time
-   geography
-   download count

Policy Packs:

-   GDPR
-   PCI DSS
-   HIPAA
-   NIS2
-   Finance
-   Government
-   Healthcare
-   Legal

## Licensing

Community:

-   fully functional
-   production ready
-   Web UI
-   REST API
-   CLI
-   Policy Engine
-   Statistics
-   Audit
-   Docker
-   Kubernetes

Enterprise:

Distributed as commercial plugin packs:

-   Identity Pack
-   Security Pack
-   Compliance Pack
-   Cloud Pack
-   Notification Pack
-   AI Pack

No separate Enterprise binary.

## Branding

Product name: Attachra

Tagline:

Open Attachment Gateway

Long-term positioning:

"Rspamd for attachment lifecycle management."
