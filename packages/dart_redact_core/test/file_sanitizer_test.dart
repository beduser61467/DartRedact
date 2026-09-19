import 'dart:convert';
import 'dart:io';
import 'package:dart_redact_core/dart_redact_core.dart';
import 'package:test/test.dart';
void main() {
  late Directory temp; late FileSanitizer sanitizer;
  setUp(() { temp = Directory.systemTemp.createTempSync('dart_redact_test_'); sanitizer = FileSanitizer(Redactor([_FakeAuthorizationDetector()])); });
  tearDown(() => temp.deleteSync(recursive: true));
  test('writes nested safe copies and preserves originals', () {
    final source = File('${temp.path}${Platform.pathSeparator}input${Platform.pathSeparator}nested${Platform.pathSeparator}app.log')..parent.createSync(recursive: true);
    const original = 'Authorization: Bearer fake-secret-value-123'; source.writeAsStringSync(original);
    sanitizer.sanitizePath(source.parent.parent.path, '${temp.path}${Platform.pathSeparator}out');
    expect(source.readAsStringSync(), original);
    expect(File('${temp.path}${Platform.pathSeparator}out${Platform.pathSeparator}nested${Platform.pathSeparator}app.log').readAsStringSync(), contains('[REDACTED_AUTHORIZATION]'));
  });
  test('HAR remains valid JSON and masks sensitive header', () {
    final source = File('${temp.path}${Platform.pathSeparator}request.har'); source.writeAsStringSync('{"log":{"entries":[{"request":{"headers":[{"name":"Authorization","value":"Bearer fake-value"}]}}]}}');
    sanitizer.sanitizePath(source.path, '${temp.path}${Platform.pathSeparator}out');
    final output = File('${temp.path}${Platform.pathSeparator}out${Platform.pathSeparator}request.har').readAsStringSync();
    expect(jsonDecode(output), isA<Map>()); expect(output, contains('[REDACTED_AUTHORIZATION]'));
  });
}

class _FakeAuthorizationDetector implements SecretDetector {
  @override
  List<SecretMatch> scan(String content) {
    const prefix = 'Authorization: Bearer ';
    final start = content.indexOf(prefix);
    if (start < 0) return [];
    return [SecretMatch(type: SecretType.authorization, severity: SecretSeverity.high, start: start, end: content.length, placeholder: '[REDACTED_AUTHORIZATION]')];
  }
}
