# Testing Guide

This document explains how to test the Privacy Toolkit script before pushing to GitHub.

## Local Testing

### Quick Test (Recommended)

Run the test script:

```bash
./test-script.sh
```

This will check:
- ✅ Syntax validation
- ✅ Required functions
- ✅ Error handling
- ✅ Logging
- ✅ User confirmation
- ✅ Safety checks

### Docker Testing

Test on different Linux distributions using Docker:

```bash
# Test on Ubuntu
docker build -t privacy-toolkit-test .
docker run --rm privacy-toolkit-test

# Or use docker-compose to test all distributions
docker-compose up
```

### Manual Syntax Check

```bash
bash -n privacy-toolkit.sh
```

## GitHub Actions Testing

When you push to GitHub, automated tests will run:

1. **Syntax Check** - Validates bash syntax
2. **Ubuntu Test** - Tests on Ubuntu latest
3. **Fedora Test** - Tests on Fedora latest
4. **Arch Test** - Tests on Arch Linux
5. **Function Validation** - Checks all required functions exist

View test results in the "Actions" tab on GitHub.

## What Gets Tested

- ✅ Bash syntax correctness
- ✅ All required functions present
- ✅ Error handling enabled
- ✅ No dangerous commands
- ✅ Proper shebang
- ✅ Version information
- ✅ Cross-distribution compatibility

## Before Pushing

1. Run local tests: `./test-script.sh`
2. Check syntax: `bash -n privacy-toolkit.sh`
3. Review changes: `git diff`
4. Commit: `git commit -m "Your message"`
5. Push: `git push`

GitHub Actions will automatically test on push.

