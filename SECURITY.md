# Security Policy

We take security vulnerabilities seriously. If you discover a security vulnerability, please follow these steps:

1. Do NOT open a public GitHub issue
2. Do NOT discuss the vulnerability publicly until it has been addressed
3. Email security concerns to hayder@alumni.harvard.edu
   - Include a detailed description of the vulnerability
   - Include steps to reproduce (if applicable)
   - Include potential impact assessment
   - Include suggested fix (if available)

### Response Timeline

- Initial Response within 2 business days
- Status Update within 7 business days
- The resolution depends on severity and complexity

### Disclosure Policy

- We will acknowledge receipt of your report within 48 hours
- We will provide regular updates on the status of the vulnerability
- Once the vulnerability is fixed, we will:
  - Credit you (if desired) in the security advisory
  - Publish a security advisory with details
  - Update the changelog

## Security Best Practices

When using ceil-dlp:

- Keep ceil-dlp updated to the latest version
- Review and validate your `ceil-dlp.yaml` configuration file
- Use appropriate file permissions for configuration files
- Monitor audit logs for suspicious activity
- Use appropriate operational modes (observe, enforce) based on your environment
- Regularly review and update PII detection policies
- Ensure Tesseract OCR is kept up to date if using image detection

## Known Security Considerations

1. ceil-dlp uses pattern matching and ML models for PII detection. False positives and false negatives are possible. Always review audit logs and adjust policies as needed.
2. Image detection requires Tesseract OCR. Ensure Tesseract is from a trusted source and kept updated.
3. Configuration files may contain sensitive paths. Ensure appropriate file permissions and access controls.
4. Audit logs may contain hashed PII values. Secure audit log files appropriately and follow data retention policies.
5. Large images or high request volumes may impact performance. Monitor system resources and set appropriate timeouts.
6. Presidio and spaCy models may be updated. Review release notes for changes that might affect detection accuracy.

Thank you for helping keep ceil-dlp secure!
