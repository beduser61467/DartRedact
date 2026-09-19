import 'dart:convert';
import 'dart:io';
import 'package:dart_redact_core/dart_redact_core.dart';
import 'package:dart_redact_detectors/dart_redact_detectors.dart';

void main(List<String> args) {
  if (args.length < 2 || !{'scan', 'sanitize'}.contains(args.first)) return _usage(64);
  final command = args.first; final input = args[1]; final json = args.contains('--json'); final report = args.contains('--report');
  String output = 'dartredact-output';
  final outputIndex = args.indexOf('--output');
  if (outputIndex >= 0 && outputIndex + 1 < args.length) output = args[outputIndex + 1];
  try {
    final sanitizer = FileSanitizer(Redactor(defaultDetectors()));
    final result = command == 'scan' ? sanitizer.scanPath(input) : sanitizer.sanitizePath(input, output);
    if (json) { stdout.writeln(const JsonEncoder.withIndent('  ').convert(result.toJson())); }
    else _printResult(command, result, output);
    if (report && command == 'sanitize') _writeReport(output, result);
    exitCode = result.findings.isEmpty ? 0 : 1;
  } catch (error) { stderr.writeln('DartRedact could not process the requested path.'); exitCode = 2; }
}
void _printResult(String command, ScanResult result, String output) {
  stdout.writeln('DartRedact\n'); stdout.writeln('${result.filesScanned} files scanned'); stdout.writeln('${result.findings.length} sensitive values detected');
  for (final severity in SecretSeverity.values) { stdout.writeln('${severity.name.toUpperCase()} ${result.findings.where((f) => f.severity == severity).length}'); }
  if (command == 'sanitize') stdout.writeln('Safe copies written to $output; originals untouched.');
}
void _writeReport(String output, ScanResult result) {
  final counts = <SecretType, int>{for (final t in SecretType.values) t: result.findings.where((f) => f.type == t).length};
  File('$output${Platform.pathSeparator}SECURITY_REPORT.md').writeAsStringSync('# DartRedact Sanitization Report\n\nFiles scanned: ${result.filesScanned}\n\nSensitive values detected: ${result.findings.length}\n\nSensitive values redacted: ${result.findings.length}\n\n## Findings\n\n${counts.entries.where((e) => e.value > 0).map((e) => '* ${e.value} ${e.key.name}').join('\n')}\n');
}
void _usage(int code) { stdout.writeln('Usage: dartredact <scan|sanitize> <path> [--output <directory>] [--report] [--json] [--verbose] [--dry-run]'); exitCode = code; }
