# Tasks: IA Shield Security Improvements

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 350-450 lines |
| 400-line budget risk | Medium |
| Chained PRs recommended | Yes |
| Suggested split | Security phase → Functionality phase → Testing phase |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: Medium

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | Security foundation (encryption, CORS, rate limiting, HTTPS) | PR 1 | Base branch; includes core security infrastructure |
| 2 | Extension functionality (homoglyphs, notifications, blocked UI) | PR 2 | Depends on PR 1; frontend/backend integration |
| 3 | Testing suite and verification | PR 3 | Independent; validates both phases |

## Phase 1: Foundation / Infrastructure

- [ ] 1.1 Create `backend/services/encryption.py` with AES-256-GCM encrypt/decrypt functions
- [ ] 1.2 Create `backend/middleware/rate_limiter.py` with rate limiting middleware using slowapi
- [ ] 1.3 Create `backend/middleware/cors_validation.py` with Extension ID validation middleware
- [ ] 1.4 Modify `backend/config.py` to add new environment variables for encryption keys and rate limits
- [ ] 1.5 Update `backend/requirements.txt` to add cryptography, slowapi, pytest dependencies
- [ ] 1.6 Modify `docker-compose.yml` to add HTTPS support with nginx configuration
- [ ] 1.7 Update `backend/main.py` to register new middlewares and configure HTTPS settings

## Phase 2: Core Implementation

- [ ] 2.1 Modify `extension/service-worker.js` to add homoglyph detection logic and user notifications
- [ ] 2.2 Modify `extension/blocked.html` to add report and proceed buttons with appropriate styling
- [ ] 2.3 Create `backend/tests/` directory structure for pytest test suite
- [ ] 2.4 Implement basic test files for encryption service, rate limiter, and CORS validation

## Phase 3: Integration / Wiring

- [ ] 3.1 Integrate encryption service with relevant backend endpoints for data protection
- [ ] 3.2 Connect rate limiter middleware to API routes in main.py
- [ ] 3.3 Wire CORS validation middleware to check extension origins
- [ ] 3.4 Test HTTPS configuration in docker-compose setup
- [ ] 3.5 Verify extension service worker communicates properly with secured backend

## Phase 4: Testing / Verification

- [ ] 4.1 Write comprehensive unit tests for encryption functionality (encrypt/decrypt edge cases)
- [ ] 4.2 Write integration tests for rate limiting middleware with various request patterns
- [ ] 4.3 Write tests for CORS validation with valid/invalid extension IDs
- [ ] 4.4 Create end-to-end test scenarios for blocked page functionality
- [ ] 4.5 Run full test suite to verify all components work together

## Phase 5: Cleanup / Documentation

- [ ] 5.1 Add docstrings and comments to all new security components
- [ ] 5.2 Verify all environment variables have appropriate defaults or error handling
- [ ] 5.3 Review and remove any temporary code or debug statements
- [ ] 5.4 Ensure README.md is updated with new security features information