import 'dart:convert';
import 'dart:io';
import 'package:dart_redact_core/dart_redact_core.dart';
import 'package:test/test.dart';
void main() {
  late Directory temp; late FileSanitizer sanitizer;
  setUp(() { temp = Directory.systemTemp.createTempSync('dart_redact_test_'); sanitizer = FileSanitizer(Redactor([_FakeAuthorizationDetector(), _FakeUrlSecretDetector()])); });
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
  test('HAR redacts headers, cookies, query strings, URL and post data', () {
    final source = File('${temp.path}${Platform.pathSeparator}request.har');
    source.writeAsStringSync('''{"log":{"entries":[{"request":{"headers":[{"name":"Authorization","value":"Bearer fake-header"}],"cookies":[{"name":"session","value":"fake-cookie"}],"queryString":[{"name":"token","value":"fake-query"}],"url":"https://example.invalid/path?api_key=fake-url-value","postData":{"text":"password=fake-post-value"}}}]}}''');
    sanitizer.sanitizePath(source.path, '${temp.path}${Platform.pathSeparator}out');
    final output = File('${temp.path}${Platform.pathSeparator}out${Platform.pathSeparator}request.har').readAsStringSync();
    final request = (jsonDecode(output) as Map)['log']['entries'][0]['request'] as Map;
    expect(request['headers'][0]['value'], '[REDACTED_AUTHORIZATION]');
    expect(request['cookies'][0]['value'], '[REDACTED_COOKIE]');
    expect(request['queryString'][0]['value'], '[REDACTED_AUTHORIZATION]');
    expect(request['url'], contains('api_key=[REDACTED_SECRET]'));
    expect(request['postData']['text'], contains('[REDACTED_SECRET]'));
    expect(source.readAsStringSync(), contains('fake-header'));
  });
  test('malformed HAR fails instead of writing an output file', () {
    final source = File('${temp.path}${Platform.pathSeparator}broken.har')..writeAsStringSync('{not json');
    expect(() => sanitizer.sanitizePath(source.path, '${temp.path}${Platform.pathSeparator}out'), throwsFormatException);
    expect(File('${temp.path}${Platform.pathSeparator}out${Platform.pathSeparator}broken.har').existsSync(), isFalse);
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

class _FakeUrlSecretDetector implements SecretDetector {
  @override
  List<SecretMatch> scan(String content) {
    final pattern = RegExp(r'(?:api_key|password)=([^&\s]+)');
    return pattern.allMatches(content).map((match) {
      final value = match.group(1)!;
      return SecretMatch(
        type: SecretType.urlSecret,
        severity: SecretSeverity.high,
        start: match.end - value.length,
        end: match.end,
        placeholder: '[REDACTED_SECRET]',
      );
    }).toList();
  }
}
