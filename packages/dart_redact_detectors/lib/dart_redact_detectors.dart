library;
import 'package:dart_redact_core/dart_redact_core.dart';

class RegexDetector implements SecretDetector {
  RegexDetector(this.type, this.severity, this.pattern, this.placeholder);
  final SecretType type; final SecretSeverity severity; final RegExp pattern; final String placeholder;
  @override List<SecretMatch> scan(String content) => pattern.allMatches(content).map((m) => SecretMatch(type: type, severity: severity, start: m.start, end: m.end, placeholder: placeholder)).toList();
}

class UrlSecretDetector implements SecretDetector {
  @override
  List<SecretMatch> scan(String content) {
    final pattern = RegExp(r'(?:token|key|api_key|secret|password)=([^&\s]+)', caseSensitive: false);
    return pattern.allMatches(content).map((m) {
      final value = m.group(1)!;
      final start = m.start + m.group(0)!.length - value.length;
      return SecretMatch(type: SecretType.urlSecret, severity: SecretSeverity.high, start: start, end: m.end, placeholder: '[REDACTED_SECRET]');
    }).toList();
  }
}

List<SecretDetector> defaultDetectors() => [
  RegexDetector(SecretType.githubToken, SecretSeverity.critical, RegExp(r'\bgh[pousr]_[A-Za-z0-9_]{20,}\b'), '[REDACTED_GITHUB_TOKEN]'),
  RegexDetector(SecretType.awsAccessKey, SecretSeverity.critical, RegExp(r'\bAKIA[0-9A-Z]{16}\b'), '[REDACTED_AWS_ACCESS_KEY]'),
  RegexDetector(SecretType.jwt, SecretSeverity.high, RegExp(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'), '[REDACTED_JWT]'),
  RegexDetector(SecretType.privateKey, SecretSeverity.critical, RegExp(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'), '[REDACTED_PRIVATE_KEY]'),
  RegexDetector(SecretType.authorization, SecretSeverity.high, RegExp(r'(?:authorization|x-auth-token)\s*[:=]\s*(?:bearer\s+)?[^\s,;]+', caseSensitive: false), '[REDACTED_AUTHORIZATION]'),
  RegexDetector(SecretType.cookie, SecretSeverity.high, RegExp(r'(?:set-)?cookie\s*[:=]\s*[^\r\n]+', caseSensitive: false), '[REDACTED_COOKIE]'),
  UrlSecretDetector(),
  RegexDetector(SecretType.apiKey, SecretSeverity.high, RegExp(r'\b(?:api[_-]?key|secret|password)\s*[:=]\s*[A-Za-z0-9_-]{12,}', caseSensitive: false), '[REDACTED_SECRET]'),
  RegexDetector(SecretType.email, SecretSeverity.medium, RegExp(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b'), '[REDACTED_EMAIL]'),
  RegexDetector(SecretType.ipv4, SecretSeverity.low, RegExp(r'\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b'), '[REDACTED_IP]'),
  RegexDetector(SecretType.ipv6, SecretSeverity.low, RegExp(r'(?<![A-F0-9:])(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}(?![A-F0-9:])', caseSensitive: false), '[REDACTED_IP]'),
];
