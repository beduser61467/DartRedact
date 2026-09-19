import 'dart:io';

import 'package:dart_redact_cli/dart_redact_cli.dart';
import 'package:test/test.dart';

void main() {
  late Directory temp;

  setUp(() => temp = Directory.systemTemp.createTempSync('dart_redact_cli_test_'));
  tearDown(() => temp.deleteSync(recursive: true));

  test('dry run reports findings without creating output', () {
    final source = File('${temp.path}${Platform.pathSeparator}report.log')
      ..writeAsStringSync('token=fake-token-value');
    final output = '${temp.path}${Platform.pathSeparator}safe';
    final messages = <String>[];

    final code = runCli(['sanitize', source.path, '--output', output, '--dry-run'], writeOut: messages.add);

    expect(code, 1);
    expect(Directory(output).existsSync(), isFalse);
    expect(messages.join('\n'), contains('Dry run: no files were written.'));
  });

  test('verbose output includes documented finding exit code', () {
    final source = File('${temp.path}${Platform.pathSeparator}clean.log')..writeAsStringSync('normal text');
    final messages = <String>[];

    expect(runCli(['scan', source.path, '--verbose'], writeOut: messages.add), 0);
    expect(messages.join('\n'), contains('Exit code: 0'));
  });

  test('invalid usage has documented exit code', () {
    expect(runCli([], writeOut: (_) {}), usageExitCode);
  });
}
