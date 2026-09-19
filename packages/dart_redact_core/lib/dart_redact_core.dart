library;

import 'dart:convert';
import 'dart:io';

enum SecretSeverity { critical, high, medium, low }

enum SecretType { githubToken, awsAccessKey, jwt, email, ipv4, ipv6, authorization, cookie, privateKey, apiKey, urlSecret }

class SecretMatch {
  const SecretMatch({required this.type, required this.severity, required this.start, required this.end, required this.placeholder, this.confidence = 1.0, this.file, this.line});
  final SecretType type;
  final SecretSeverity severity;
  final int start;
  final int end;
  final String placeholder;
  final double confidence;
  final String? file;
  final int? line;
  SecretMatch located(String path, String content) => SecretMatch(type: type, severity: severity, start: start, end: end, placeholder: placeholder, confidence: confidence, file: path, line: '\n'.allMatches(content.substring(0, start)).length + 1);
}

abstract class SecretDetector { List<SecretMatch> scan(String content); }

class Redactor {
  const Redactor(this.detectors);
  final List<SecretDetector> detectors;
  List<SecretMatch> scan(String content) {
    final matches = detectors.expand((d) => d.scan(content)).toList()..sort((a, b) => a.start.compareTo(b.start));
    final kept = <SecretMatch>[];
    for (final match in matches) { if (kept.isEmpty || match.start >= kept.last.end) kept.add(match); }
    return kept;
  }
  String sanitizeText(String content) {
    final matches = scan(content);
    var result = content;
    for (final m in matches.reversed) { result = result.replaceRange(m.start, m.end, m.placeholder); }
    return result;
  }
}

class ScanResult {
  const ScanResult(this.filesScanned, this.findings);
  final int filesScanned;
  final List<SecretMatch> findings;
  Map<String, Object> toJson() => {'filesScanned': filesScanned, 'findings': findings.length, 'severity': {for (final s in SecretSeverity.values) s.name: findings.where((f) => f.severity == s).length}, 'matches': findings.map((f) => {'type': f.type.name, 'severity': f.severity.name, 'file': f.file, 'line': f.line, 'confidence': f.confidence}).toList()};
}

class FileSanitizer {
  FileSanitizer(this.redactor);
  final Redactor redactor;
  static const supportedExtensions = {'.txt', '.log', '.json', '.har', '.env', '.yaml', '.yml'};
  Iterable<File> files(String path) sync* {
    final entity = FileSystemEntity.typeSync(path);
    if (entity == FileSystemEntityType.file) { yield File(path); return; }
    if (entity != FileSystemEntityType.directory) throw ArgumentError('Path does not exist or is not readable.');
    yield* Directory(path).listSync(recursive: true).whereType<File>().where((f) => supportedExtensions.contains(_extension(f.path)));
  }
  ScanResult scanPath(String path) {
    final all = files(path).toList(); final found = <SecretMatch>[];
    for (final file in all) { final content = file.readAsStringSync(); found.addAll(redactor.scan(content).map((m) => m.located(file.path, content))); }
    return ScanResult(all.length, found);
  }
  ScanResult sanitizePath(String input, String output) {
    final root = FileSystemEntity.typeSync(input) == FileSystemEntityType.directory ? Directory(input).absolute.path : File(input).parent.absolute.path;
    final all = files(input).toList(); final found = <SecretMatch>[];
    for (final file in all) {
      final content = file.readAsStringSync(); found.addAll(redactor.scan(content).map((m) => m.located(file.path, content)));
      final relative = _relative(root, file.absolute.path); final destination = File('$output${Platform.pathSeparator}$relative')..parent.createSync(recursive: true);
      destination.writeAsStringSync(_extension(file.path) == '.har' ? _sanitizeHar(content) : redactor.sanitizeText(content));
    }
    return ScanResult(all.length, found);
  }
  String _sanitizeHar(String input) {
    final decoded = jsonDecode(input);
    Object? walk(Object? value, [String? key]) {
      if (value is Map) {
        final name = value['name']?.toString().toLowerCase();
        const sensitive = {'authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token'};
        if (name != null && sensitive.contains(name) && value.containsKey('value')) {
          return {for (final e in value.entries) e.key: e.key == 'value' ? (name.contains('cookie') ? '[REDACTED_COOKIE]' : '[REDACTED_AUTHORIZATION]') : walk(e.value, e.key.toString())};
        }
        return {for (final e in value.entries) e.key: walk(e.value, e.key.toString())};
      }
      if (value is List) return value.map((e) => walk(e, key)).toList();
      if (value is String) {
        const sensitive = {'authorization', 'cookie', 'set-cookie', 'x-api-key', 'x-auth-token'};
        if (key != null && sensitive.contains(key.toLowerCase())) return key.toLowerCase().contains('cookie') ? '[REDACTED_COOKIE]' : '[REDACTED_AUTHORIZATION]';
        return redactor.sanitizeText(value);
      }
      return value;
    }
    return const JsonEncoder.withIndent('  ').convert(walk(decoded));
  }
  String _extension(String path) => path.contains('.') ? '.${path.split('.').last.toLowerCase()}' : '';
  String _relative(String root, String path) => path.startsWith(root) ? path.substring(root.length).replaceFirst(RegExp(r'^[\\/]'), '') : path.split(Platform.pathSeparator).last;
}
