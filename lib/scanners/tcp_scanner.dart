import 'dart:io';
import 'dart:async';
import 'base_scanner.dart';

/// TCP端口扫描器
class TcpScanner extends BaseScanner {
  static const List<int> commonPorts = [
    22, // SSH
    23, // Telnet
    25, // SMTP
    53, // DNS
    80, // HTTP
    110, // POP3
    143, // IMAP
    443, // HTTPS
    993, // IMAPS
    995, // POP3S
    1433, // SQL Server
    3306, // MySQL
    3389, // RDP
    5432, // PostgreSQL
    8080, // HTTP Alt
    8443, // HTTPS Alt
    9000, // 常用开发端口
    3000, // Node.js开发端口
    5000, // Flask默认端口
    8000, // Django开发端口
  ];

  TcpScanner({ScannerConfig? config})
    : super(
        name: 'TCP端口扫描器',
        scanType: ScanResultType.tcpPort,
        config: config ?? const ScannerConfig(),
      );

  @override
  String get description => '扫描常用TCP端口，检测Web服务、SSH、数据库等服务';

  @override
  int get priority => 2; // 中高优先级

  @override
  Future<bool> isAvailable() async {
    try {
      // 测试是否能创建TCP连接
      final socket = await Socket.connect(
        '127.0.0.1',
        80,
        timeout: const Duration(milliseconds: 100),
      );
      socket.destroy();
      return true;
    } catch (e) {
      // 即使连接失败也表示TCP功能可用
      return true;
    }
  }

  @override
  Future<ScanResult?> scanSingle(
    String ip,
    String networkSegment, {
    ScanProgressCallback? onProgress,
  }) async {
    try {
      final stopwatch = Stopwatch()..start();
      final openPorts = <int>[];
      final serviceInfo = <String, dynamic>{};

      // 并行扫描所有端口以提高效率
      final futures = <Future<int?>>[];

      for (final port in commonPorts) {
        futures.add(_scanPort(ip, port));
      }

      // 等待所有端口扫描完成
      final results = await Future.wait(futures);

      for (int i = 0; i < results.length; i++) {
        final port = results[i];
        if (port != null) {
          openPorts.add(port);

          // 识别服务类型
          final service = _identifyService(port);
          if (service != null) {
            serviceInfo[port.toString()] = service;
          }
        }

        // 更新进度
        onProgress?.call(ip, (i + 1) / results.length);
      }

      // 如果找到HTTP/HTTPS服务，并行获取Web信息
      final webPorts = openPorts
          .where((port) => port == 80 || port == 443)
          .toList();
      if (webPorts.isNotEmpty) {
        final webFutures = webPorts
            .map((port) => _detectWebService(ip, port))
            .toList();
        final webResults = await Future.wait(webFutures);

        for (int i = 0; i < webResults.length; i++) {
          final webInfo = webResults[i];
          if (webInfo != null) {
            serviceInfo['web_info_${webPorts[i]}'] = webInfo;
          }
        }
      }

      stopwatch.stop();

      if (openPorts.isNotEmpty) {
        return ScanResult(
          ip: ip,
          isActive: true,
          responseTime: stopwatch.elapsedMilliseconds,
          networkSegment: networkSegment,
          detectionMethod: ScanResultType.tcpPort,
          openPorts: openPorts,
          additionalInfo: {
            'services': serviceInfo,
            'open_port_count': openPorts.length,
            'website_available':
                openPorts.contains(80) || openPorts.contains(443),
            'ssh_available': openPorts.contains(22),
            'database_available': openPorts.any(
              (p) => [1433, 3306, 5432].contains(p),
            ),
          },
        );
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// 扫描单个端口
  Future<int?> _scanPort(String ip, int port) async {
    try {
      final socket = await Socket.connect(
        ip,
        port,
        timeout: const Duration(milliseconds: 800),
      );
      socket.destroy();
      return port;
    } catch (e) {
      return null;
    }
  }

  /// 识别端口对应的服务
  String? _identifyService(int port) {
    switch (port) {
      case 22:
        return 'SSH';
      case 23:
        return 'Telnet';
      case 25:
        return 'SMTP';
      case 53:
        return 'DNS';
      case 80:
        return 'HTTP';
      case 110:
        return 'POP3';
      case 143:
        return 'IMAP';
      case 443:
        return 'HTTPS';
      case 993:
        return 'IMAPS';
      case 995:
        return 'POP3S';
      case 1433:
        return 'SQL Server';
      case 3306:
        return 'MySQL';
      case 3389:
        return 'RDP';
      case 5432:
        return 'PostgreSQL';
      case 8080:
        return 'HTTP (Alt)';
      case 8443:
        return 'HTTPS (Alt)';
      case 9000:
        return 'Development';
      case 3000:
        return 'Node.js';
      case 5000:
        return 'Flask';
      case 8000:
        return 'Django';
      default:
        return null;
    }
  }

  /// 检测Web服务信息
  Future<Map<String, dynamic>?> _detectWebService(String ip, int port) async {
    try {
      final client = HttpClient();
      client.connectionTimeout = const Duration(milliseconds: 1000);

      if (port == 443) {
        client.badCertificateCallback = (cert, host, port) => true;
      }

      final uri = Uri.parse('${port == 443 ? 'https' : 'http'}://$ip:$port');
      final request = await client.getUrl(uri);
      final response = await request.close().timeout(
        const Duration(milliseconds: 2000),
      );

      final headers = <String, String>{};
      response.headers.forEach((name, values) {
        headers[name] = values.join(', ');
      });

      client.close();

      return {
        'status_code': response.statusCode,
        'server': headers['server'] ?? 'Unknown',
        'content_type': headers['content-type'] ?? 'Unknown',
        'headers': headers,
      };
    } catch (e) {
      return null;
    }
  }
}
