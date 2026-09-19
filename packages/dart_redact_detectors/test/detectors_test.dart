import 'package:dart_redact_detectors/dart_redact_detectors.dart';
import 'package:dart_redact_core/dart_redact_core.dart';
import 'package:test/test.dart';
void main() {
  final redactor = Redactor(defaultDetectors());
  test('redacts fake GitHub token without retaining it', () { final value = 'ghp_abcdefghijklmnopqrstuvwxyz123456'; expect(redactor.sanitizeText(value), '[REDACTED_GITHUB_TOKEN]'); });
  test('does not classify ordinary text as a GitHub token', () { expect(redactor.scan('ghp_short and hello world').where((m) => m.type == SecretType.githubToken), isEmpty); });
  test('redacts email, IPv4 and URL parameter', () { final safe = redactor.sanitizeText('mail test@example.invalid ip 192.0.2.1 https://x.invalid?a=1&token=fake-token-value'); expect(safe, contains('[REDACTED_EMAIL]')); expect(safe, contains('[REDACTED_IP]')); expect(safe, contains('token=[REDACTED_SECRET]')); });
}
