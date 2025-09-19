# devsecops-assessment-siphesihle-mahlangu
1 ## Blocks Completed
2 - [x] Block 1: Security Automation - Secret Detection Engine
3 - [x] Block 2: Pipeline Security
4 - [x] Block 3: Container Security
5 - [x] Block 5: B- CI/CD Pipeline Communication
6
7 ## Approach Summary
8 Brief overview of your strategy and tool choices
  * DevSecOps mindset – embedded security throughout build, scan, containerize, and deploy.
  * Static & secret scanning – SonarQube for SAST/code quality; custom YAML rules and Trivy for secrets & misconfigurations.
  * Secure CI/CD – GitHub Actions pipeline with SonarQube, Trivy (FS, repo, image), quality gates, and SARIF reports.
  * Container hardening – multi-stage Dockerfile, minimal node:alpine, non-root user, dropped capabilities, read-only FS.
  * Dependency & image scanning – Trivy for OS/library CVEs and container images.
  * Incident response – documented playbook for CI/CD compromise and security failures.
  * Governance & communication – clear docs, quality gates, and alerts for security visibility.
10 ## Time Breakdown
11 - Block 1: X minutes
12 - Block 2: X minutes
13 - etc.
14
15 ## Assumptions Made
Success Criteria
We evaluate based on:
Security Integration: How naturally security fits into your solutions
Code Quality: Clean, maintainable, documented code
Problem Solving: Your approach to real-world challenges
Strategic Thinking: Understanding of broader DevSecOps impact
Communication: Clear explanations of technical decisions
Remember: This is about demonstrating core competencies in 3 hours, not building production-ready systems.
Final Notes
Work in 45-minute focused blocks - take breaks between blocks
Choose blocks that showcase your strengths - don't try to do everything
Document your choices - explain why you picked certain blocks/tools
Quality over coverage - better to excel in 4 areas than rush through more
Senior candidates: Block 6 
