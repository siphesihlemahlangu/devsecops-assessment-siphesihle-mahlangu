This Doc outlines the comprehensive response plan for Scenario-B (Suspicious commits and deployments detected in your GitHub Actions)
Step-by-step response procedures
1. Preparation
    *Ensure you have incident runbooks, on-call contacts, and backups of workflow configs.
    *Verify GitHub audit log retention is enabled (Enterprise or Org level).
2. Collect evidence:
    *GitHub Audit Log: actor, IP, timestamp, repository, workflow triggered.
    *Commit details: hash, author, signed-off info, diff.
    *Workflow run logs & artifacts.
    *Determine scope: Repositories, workflows, environments, secrets involved.
3. Containment
    *Immediate access control:
    Suspend suspicious user accounts or PATs.
    Rotate affected tokens/secrets (e.g., GITHUB_TOKEN, cloud provider keys).
    Restrict branch protections to read-only until analysis is done.
    *Pause pipeline:
    Disable vulnerable workflows (Settings → Actions → Disable).
    Stop active deployments and roll back to last trusted build.
4. Eradication & Recovery
    Revert unauthorized commits.
    Remove malicious workflows or changes.
    Audit runners (self-hosted) for persistence/backdoors.
    Re-enable workflows with patched configurations.
    Rotate all credentials used in the pipeline.

Detection and containment strategies:
- Unauthorized workflow modifications 
- Suspicious commit patterns or unknown authors 
- Unexpected production deployments 
- Security tool alerts on malicious code 
- Unusual access patterns from unexpected locations

Containment Strategies
* Block force-push. Require Pull-request reviews & signed commits. Therefore no changes will be made on branch without an approved PR 
* Workflow Approval	Use workflow_dispatch + required reviewers for deployments.
* Use PATs Token Security have expiration. Regenerate a new token on suspicion.
* Enable GitHub Advanced Security audit logs. Send to SIEM. Alert on: unusual runner IP, unreviewed commits, workflow file edits.
* Runner Hardening	Use ephemeral runners with least privileges. Avoid storing long-lived secrets.

Preventation Improvements
* Use AWS Secrets Manager or SSM Parameter Store for DB credentials, API tokens, etc.
* Restrict permissions to least privilege for pipeline, deployments, and secrets
* add job approval on the pipeline for the tech leader to approve the pipeline

Monitoring Improvements
Use CloudWatch and set alarms on:
    * Unauthorized deployments or failed CI/CD jobs
    * Unexpected container image pulls or rebuilds
    * Secret access events in AWS Secrets Manager

Communication plan outline
Stage	        Audience	                    Message
Detection	    SecOps, DevOps leads	        Initial alert, suspected compromise scope
Containment	    Engineering team	            Status of access restrictions, workflows paused
Investigation	Management.                 	Evidence, timeline, estimated impact
Remediation	    All developers	                Updated configs, required secret rotation
Postmortem	    Org leadership & dev teams	    Lessons learned, preventive roadmap