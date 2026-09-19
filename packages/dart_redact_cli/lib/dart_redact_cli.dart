library;

import 'dart:convert';
import 'dart:io';

import 'package:dart_redact_core/dart_redact_core.dart';
import 'package:dart_redact_detectors/dart_redact_detectors.dart';

const usageExitCode = 64;
const processingErrorExitCode = 2;

int runCli(
  List<String> args, {
  void Function(String message)? writeOut,
  void Function(String message)? writeError,
}) {
  final out = writeOut ?? stdout.writeln;
  final errorOut = writeError ?? stderr.writeln;
  if (args.length < 2 || !{'scan', 'sanitize'}.contains(args.first)) {
    _usage(out);
    return usageExitCode;
  }
  final command = args.first;
  final input = args[1];
  final json = args.contains('--json');
  final report = args.contains('--report');
  final dryRun = args.contains('--dry-run');
  final verbose = args.contains('--verbose');
  var output = 'dartredact-output';
  final outputIndex = args.indexOf('--output');
  if (outputIndex >= 0 && outputIndex + 1 < args.length) {
    output = args[outputIndex + 1];
  } else if (outputIndex >= 0) {
    _usage(out);
    return usageExitCode;
  }
  try {
    final sanitizer = FileSanitizer(Redactor(defaultDetectors()));
    final result = command == 'scan' || dryRun
        ? sanitizer.scanPath(input)
        : sanitizer.sanitizePath(input, output);
    if (json) {
      out(const JsonEncoder.withIndent('  ').convert(result.toJson()));
    } else {
      _printResult(command, result, output, dryRun, out);
    }
    if (verbose) out('Exit code: ${result.findings.isEmpty ? 0 : 1}');
    if (report && command == 'sanitize' && !dryRun) _writeReport(output, result);
    return result.findings.isEmpty ? 0 : 1;
  } catch (_) {
    errorOut('DartRedact could not process the requested path.');
    return processingErrorExitCode;
  }
}

void _printResult(String command, ScanResult result, String output, bool dryRun,
    void Function(String message) out) {
  out('DartRedact\n');
  out('${result.filesScanned} files scanned');
  out('${result.findings.length} sensitive values detected');
  for (final severity in SecretSeverity.values) {
    out('${severity.name.toUpperCase()} ${result.findings.where((f) => f.severity == severity).length}');
  }
  if (command == 'sanitize' && dryRun) out('Dry run: no files were written.');
  if (command == 'sanitize' && !dryRun) out('Safe copies written to $output; originals untouched.');
}

void _writeReport(String output, ScanResult result) {
  final counts = <SecretType, int>{
    for (final type in SecretType.values)
      type: result.findings.where((finding) => finding.type == type).length,
  };
  File('$output${Platform.pathSeparator}SECURITY_REPORT.md').writeAsStringSync(
    '# DartRedact Sanitization Report\n\nFiles scanned: ${result.filesScanned}\n\nSensitive values detected: ${result.findings.length}\n\nSensitive values redacted: ${result.findings.length}\n\n## Findings\n\n${counts.entries.where((entry) => entry.value > 0).map((entry) => '* ${entry.value} ${entry.key.name}').join('\n')}\n',
  );
}

void _usage(void Function(String message) out) => out(
  'Usage: dartredact <scan|sanitize> <path> [--output <directory>] [--report] [--json] [--verbose] [--dry-run]\n'
  'Exit codes: 0 no findings, 1 findings, 2 processing error, 64 invalid usage.',
);
