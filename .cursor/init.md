# CFS Initialization

This project uses CFS (Cursor File Structure) to manage instruction documents.

## Structure

- `.cursor/rules/` - Cursor rules documents (.mdc files)
- `.cursor/features/` - Feature request documents
- `.cursor/bugs/` - Bug report documents
- `.cursor/refactors/` - Refactoring task documents
- `.cursor/ui/` - UI/UX task documents
- `.cursor/docs/` - Documentation task documents
- `.cursor/research/` - Research task documents
- `.cursor/progress/` - Progress and handoff documents
- `.cursor/qa/` - QA task documents
- `.cursor/security/` - Security-related documents
- `.cursor/infrastructure-and-deployment/` - Infrastructure and deployment task documents
- `.cursor/tmp/` - Temporary documents

## Usage

```bash
cfs features create   # Create a feature request
cfs bugs create       # Create a bug report
cfs view              # View incomplete documents (--all for everything)
cfs gh sync           # Sync with GitHub issues
```
