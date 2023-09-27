FROM ghcr.io/zricethezav/gitleaks:latest

LABEL "com.github.actions.name"="Gitleaks Scanner"
LABEL "com.github.actions.description"="Runs Gitleaks in your CI/CD workflow"
LABEL "com.github.actions.icon"="shield"
LABEL "com.github.actions.color"="purple"
LABEL "repository"="https://github.com/sequring/github-action-gitleaks.git"

COPY .gitleaks/* /.gitleaks/
COPY entrypoint.sh /entrypoint.sh
USER root
ENTRYPOINT ["/entrypoint.sh"]