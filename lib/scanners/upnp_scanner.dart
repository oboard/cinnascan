import 'dart:io';
import 'dart:async';
import 'dart:convert';
import 'base_scanner.dart';

/// UPnP SSDP扫描器
class UpnpScanner extends BaseScanner {
  static const String _ssdpAddress = '239.255.255.250';
  static const int _ssdpPort = 1900;

  UpnpScanner({ScannerConfig? config})
    : super(
        name: 'UPnP SSDP扫描器',
        scanType: ScanResultType.upnp,
        config: config ?? const ScannerConfig(),
      );

  @override
  String get description => '发现支持UPnP的网络设备和服务';

  @override
  int get priority => 3; // 中等优先级

  @override
  Future<bool> isAvailable() async {
    try {
      // 检查是否能创建UDP socket
      final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      socket.close();
      return true;
    } catch (e) {
      return false;
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

      // 检查UPnP服务
      final upnpInfo = await _checkUpnpDevice(ip);

      stopwatch.stop();

      if (upnpInfo != null) {
        return ScanResult(
          ip: ip,
          isActive: true,
          responseTime: stopwatch.elapsedMilliseconds,
          networkSegment: networkSegment,
          detectionMethod: ScanResultType.upnp,
          hostname: upnpInfo['friendlyName'],
          additionalInfo: {
            'upnp_available': true,
            'device_type': upnpInfo['deviceType'],
            'manufacturer': upnpInfo['manufacturer'],
            'model': upnpInfo['modelName'],
            'services': upnpInfo['services'] ?? [],
          },
        );
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// 检查UPnP设备
  Future<Map<String, dynamic>?> _checkUpnpDevice(String ip) async {
    try {
      // 首先尝试连接常见的UPnP端口
      final upnpPorts = [1900, 49152, 49153, 49154];

      for (final port in upnpPorts) {
        try {
          final socket = await Socket.connect(
            ip,
            port,
            timeout: const Duration(seconds: 1),
          );
          socket.destroy();

          // 如果能连接，尝试获取设备描述
          final deviceInfo = await _getDeviceDescription(ip, port);
          if (deviceInfo != null) {
            return deviceInfo;
          }
        } catch (e) {
          // 端口不可达，继续检查下一个
        }
      }

      // 尝试HTTP端口获取UPnP描述
      final httpInfo = await _checkHttpUpnp(ip);
      if (httpInfo != null) {
        return httpInfo;
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// 获取设备描述
  Future<Map<String, dynamic>?> _getDeviceDescription(
    String ip,
    int port,
  ) async {
    try {
      // 发送M-SEARCH请求
      final searchRequest = _buildMSearchRequest();

      final socket = await RawDatagramSocket.bind(InternetAddress.anyIPv4, 0);
      socket.send(searchRequest.codeUnits, InternetAddress(ip), port);

      // 等待响应
      final completer = Completer<Map<String, dynamic>?>();
      Timer(const Duration(seconds: 2), () {
        if (!completer.isCompleted) {
          completer.complete(null);
        }
      });

      late StreamSubscription subscription;
      subscription = socket.listen((RawSocketEvent event) {
        if (event == RawSocketEvent.read) {
          final datagram = socket.receive();
          if (datagram != null) {
            final response = String.fromCharCodes(datagram.data);
            final deviceInfo = _parseUpnpResponse(response, ip);
            if (deviceInfo != null && !completer.isCompleted) {
              completer.complete(deviceInfo);
            }
          }
        }
      });

      final result = await completer.future;
      await subscription.cancel();
      socket.close();

      return result;
    } catch (e) {
      return null;
    }
  }

  /// 构建M-SEARCH请求
  String _buildMSearchRequest() {
    return 'M-SEARCH * HTTP/1.1\r\n'
        'HOST: $_ssdpAddress:$_ssdpPort\r\n'
        'MAN: "ssdp:discover"\r\n'
        'ST: upnp:rootdevice\r\n'
        'MX: 3\r\n\r\n';
  }

  /// 解析UPnP响应
  Map<String, dynamic>? _parseUpnpResponse(String response, String ip) {
    try {
      final lines = response.split('\r\n');
      String? location;
      String? server;
      String? usn;

      for (final line in lines) {
        final parts = line.split(':');
        if (parts.length >= 2) {
          final key = parts[0].trim().toLowerCase();
          final value = parts.sublist(1).join(':').trim();

          switch (key) {
            case 'location':
              location = value;
              break;
            case 'server':
              server = value;
              break;
            case 'usn':
              usn = value;
              break;
          }
        }
      }

      if (location != null) {
        return {
          'friendlyName': _extractDeviceName(server, usn),
          'deviceType': _identifyDeviceType(server, usn),
          'manufacturer': _extractManufacturer(server),
          'modelName': _extractModel(server),
          'location': location,
          'server': server,
          'services': ['UPnP'],
        };
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// 提取设备名称
  String _extractDeviceName(String? server, String? usn) {
    if (server != null) {
      // 从Server字段提取设备名称
      final patterns = [
        RegExp(r'([A-Za-z]+)\s*[/\s]', caseSensitive: false),
        RegExp(r'^([A-Za-z0-9\-]+)', caseSensitive: false),
      ];

      for (final pattern in patterns) {
        final match = pattern.firstMatch(server);
        if (match != null) {
          return match.group(1)!;
        }
      }
    }

    if (usn != null) {
      // 从USN字段提取
      if (usn.contains('::')) {
        final parts = usn.split('::');
        if (parts.isNotEmpty) {
          return parts.first.replaceAll('uuid:', '').substring(0, 8);
        }
      }
    }

    return 'UPnP Device';
  }

  /// 识别设备类型
  String _identifyDeviceType(String? server, String? usn) {
    if (server != null) {
      final serverLower = server.toLowerCase();

      if (serverLower.contains('router') || serverLower.contains('gateway')) {
        return 'Router/Gateway';
      } else if (serverLower.contains('printer')) {
        return 'Printer';
      } else if (serverLower.contains('media') ||
          serverLower.contains('dlna')) {
        return 'Media Server';
      } else if (serverLower.contains('nas') ||
          serverLower.contains('storage')) {
        return 'NAS/Storage';
      } else if (serverLower.contains('camera') ||
          serverLower.contains('webcam')) {
        return 'IP Camera';
      } else if (serverLower.contains('tv') || serverLower.contains('smart')) {
        return 'Smart TV';
      }
    }

    return 'UPnP Device';
  }

  /// 提取制造商
  String _extractManufacturer(String? server) {
    if (server == null) return 'Unknown';

    final manufacturers = {
      'linux': 'Linux',
      'windows': 'Microsoft',
      'upnp': 'Generic UPnP',
      'miniupnpd': 'MiniUPnP',
      'igd': 'Internet Gateway Device',
      'fritz': 'AVM Fritz',
      'netgear': 'Netgear',
      'linksys': 'Linksys',
      'dlink': 'D-Link',
      'tplink': 'TP-Link',
      'asus': 'ASUS',
    };

    final serverLower = server.toLowerCase();
    for (final entry in manufacturers.entries) {
      if (serverLower.contains(entry.key)) {
        return entry.value;
      }
    }

    return 'Unknown';
  }

  /// 提取型号
  String _extractModel(String? server) {
    if (server == null) return 'Unknown';

    // 尝试提取版本号或型号
    final versionMatch = RegExp(r'(\d+\.\d+(?:\.\d+)?)').firstMatch(server);
    if (versionMatch != null) {
      return 'v${versionMatch.group(1)}';
    }

    return 'Unknown';
  }

  /// 通过HTTP检查UPnP
  Future<Map<String, dynamic>?> _checkHttpUpnp(String ip) async {
    try {
      // 尝试常见的UPnP描述路径
      final paths = [
        '/rootDesc.xml',
        '/description.xml',
        '/device.xml',
        '/upnp/desc.xml',
      ];

      for (final path in paths) {
        try {
          final client = HttpClient();
          client.connectionTimeout = const Duration(seconds: 2);

          final request = await client.get(ip, 80, path);
          final response = await request.close();

          if (response.statusCode == 200) {
            final content = await response.transform(utf8.decoder).join();
            final deviceInfo = _parseXmlDescription(content);
            client.close();

            if (deviceInfo != null) {
              return deviceInfo;
            }
          }

          client.close();
        } catch (e) {
          // 继续尝试下一个路径
        }
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// 解析XML设备描述
  Map<String, dynamic>? _parseXmlDescription(String xml) {
    try {
      // 简单的XML解析（提取关键信息）
      final friendlyNameMatch = RegExp(
        r'<friendlyName>(.*?)</friendlyName>',
      ).firstMatch(xml);
      final deviceTypeMatch = RegExp(
        r'<deviceType>(.*?)</deviceType>',
      ).firstMatch(xml);
      final manufacturerMatch = RegExp(
        r'<manufacturer>(.*?)</manufacturer>',
      ).firstMatch(xml);
      final modelNameMatch = RegExp(
        r'<modelName>(.*?)</modelName>',
      ).firstMatch(xml);

      if (friendlyNameMatch != null || deviceTypeMatch != null) {
        return {
          'friendlyName': friendlyNameMatch?.group(1) ?? 'UPnP Device',
          'deviceType': _simplifyDeviceType(deviceTypeMatch?.group(1)),
          'manufacturer': manufacturerMatch?.group(1) ?? 'Unknown',
          'modelName': modelNameMatch?.group(1) ?? 'Unknown',
          'services': ['UPnP', 'HTTP'],
        };
      }

      return null;
    } catch (e) {
      return null;
    }
  }

  /// 简化设备类型
  String _simplifyDeviceType(String? deviceType) {
    if (deviceType == null) return 'UPnP Device';

    if (deviceType.contains('InternetGatewayDevice')) {
      return 'Router/Gateway';
    } else if (deviceType.contains('MediaServer')) {
      return 'Media Server';
    } else if (deviceType.contains('MediaRenderer')) {
      return 'Media Renderer';
    } else if (deviceType.contains('Printer')) {
      return 'Printer';
    }

    return 'UPnP Device';
  }

  /// 批量扫描
  @override
  Future<List<ScanResult>> scanBatch(
    List<String> ips,
    String networkSegment, {
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
  }) async {
    if (!config.enabled || !await isAvailable()) {
      return [];
    }

    final results = <ScanResult>[];
    final semaphore = Semaphore(config.maxConcurrency);

    final futures = ips.asMap().entries.map((entry) async {
      final index = entry.key;
      final ip = entry.value;

      await semaphore.acquire();
      try {
        onProgress?.call(ip, index / ips.length);

        final result = await scanSingle(ip, networkSegment);
        if (result != null) {
          results.add(result);
          onResult?.call(result);
        }
      } finally {
        semaphore.release();
      }
    });

    await Future.wait(futures);
    return results;
  }
}
