# Publishing this clean-room repository

Recommended public repository name:

```text
Automotive-Diagnostic-Security-Analyzer
```

## GitHub web upload

1. Create a new public repository with the recommended name.
2. Do not initialize it with a README, license, or gitignore.
3. Extract this package locally.
4. Upload the extracted files and folders to the new repository.
5. Commit with the message `Initial clean-room release`.
6. Add the repository description and topics listed in `README.md`.
7. Verify the commit history contains only the new clean-room commits.
8. Delete the contaminated legacy repository after the replacement is verified.
9. Contact GitHub Support and request removal of cached views for the deleted legacy repository because sensitive data appeared in earlier commits.

## Git command alternative

```bash
git init
git add .
git commit -m "Initial clean-room release"
git branch -M main
git remote add origin https://github.com/LRTechpro/Automotive-Diagnostic-Security-Analyzer.git
git push -u origin main
```
