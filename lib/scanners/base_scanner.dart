import 'dart:async';
import 'dart:collection';

/// 扫描结果类型
enum ScanResultType {
  icmpPing,
  tcpPort,
  arpTable,
  bonjour,
  upnp,
  dnsReverse,
  ipv6,
  mdns,
  ssdp,
}

/// 扫描结果数据类
class ScanResult {
  final String ip;
  final String? hostname;
  final String? macAddress;
  final List<int> openPorts;
  final Map<String, dynamic> additionalInfo;
  final ScanResultType detectionMethod;
  final int responseTime;
  final bool isActive;
  final String networkSegment;

  ScanResult({
    required this.ip,
    this.hostname,
    this.macAddress,
    this.openPorts = const [],
    this.additionalInfo = const {},
    required this.detectionMethod,
    required this.responseTime,
    required this.isActive,
    required this.networkSegment,
  });

  /// 获取检测方法的显示名称
  String get detectionMethodName {
    switch (detectionMethod) {
      case ScanResultType.icmpPing:
        return 'ICMP Ping';
      case ScanResultType.arpTable:
        return 'ARP表';
      case ScanResultType.bonjour:
        return 'Bonjour/mDNS';
      case ScanResultType.upnp:
        return 'UPnP SSDP';
      case ScanResultType.tcpPort:
        return 'TCP端口';
      case ScanResultType.dnsReverse:
        return 'DNS反向解析';
      case ScanResultType.ipv6:
        return 'IPv6探测';
      case ScanResultType.mdns:
        return 'mDNS';
      case ScanResultType.ssdp:
        return 'SSDP';
    }
  }

  /// 获取设备类型图标
  String get deviceIcon {
    if (additionalInfo.containsKey('deviceType')) {
      switch (additionalInfo['deviceType']) {
        case 'router':
          return '🌐';
        case 'computer':
          return '💻';
        case 'phone':
          return '📱';
        case 'printer':
          return '🖨️';
        case 'tv':
          return '📺';
        case 'camera':
          return '📷';
        default:
          return '📱';
      }
    }
    return '📱';
  }
}

/// 扫描器配置类
class ScannerConfig {
  final Duration timeout;
  final int maxConcurrency;
  final bool enabled;
  final Map<String, dynamic> customParams;
  final bool enableParallelScanning; // 新增：是否启用并行扫描
  final Duration delayBetweenRequests; // 新增：请求间延迟

  const ScannerConfig({
    this.timeout = const Duration(seconds: 3),
    this.maxConcurrency = 20, // 增加默认并发数
    this.enabled = true,
    this.customParams = const {},
    this.enableParallelScanning = true,
    this.delayBetweenRequests = Duration.zero,
  });
}

/// 扫描进度回调
typedef ScanProgressCallback = void Function(String ip, double progress);

/// 扫描结果回调
typedef ScanResultCallback = void Function(ScanResult result);

/// 抽象扫描器基类
abstract class BaseScanner {
  final String name;
  final ScanResultType scanType;
  final ScannerConfig config;

  BaseScanner({
    required this.name,
    required this.scanType,
    required this.config,
  });

  /// 检查扫描器是否可用（检查权限、依赖等）
  Future<bool> isAvailable();

  /// 扫描单个IP地址
  Future<ScanResult?> scanSingle(
    String ip,
    String networkSegment, {
    ScanProgressCallback? onProgress,
  });

  /// 批量扫描IP地址列表
  Future<List<ScanResult>> scanBatch(
    List<String> ips,
    String networkSegment, {
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
  }) async {
    if (!config.enabled || !await isAvailable()) {
      return [];
    }

    if (config.enableParallelScanning) {
      return await _scanBatchParallel(
        ips,
        networkSegment,
        onProgress,
        onResult,
      );
    } else {
      return await _scanBatchSequential(
        ips,
        networkSegment,
        onProgress,
        onResult,
      );
    }
  }

  /// 并行批量扫描
  Future<List<ScanResult>> _scanBatchParallel(
    List<String> ips,
    String networkSegment,
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
  ) async {
    final results = <ScanResult>[];
    final semaphore = Semaphore(config.maxConcurrency);
    final completedCount = <int>[0]; // 使用列表以便在闭包中修改

    // 创建所有扫描任务
    final futures = ips.map((ip) async {
      await semaphore.acquire();
      try {
        // 添加延迟以避免网络拥塞
        if (config.delayBetweenRequests > Duration.zero) {
          await Future.delayed(config.delayBetweenRequests);
        }

        final result = await scanSingle(ip, networkSegment);

        // 更新进度
        completedCount[0]++;
        onProgress?.call(ip, completedCount[0] / ips.length);

        if (result != null) {
          results.add(result);
          onResult?.call(result);
        }

        return result;
      } finally {
        semaphore.release();
      }
    }).toList();

    // 等待所有任务完成
    await Future.wait(futures);
    return results;
  }

  /// 顺序批量扫描（用于需要严格控制的场景）
  Future<List<ScanResult>> _scanBatchSequential(
    List<String> ips,
    String networkSegment,
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
  ) async {
    final results = <ScanResult>[];

    for (int i = 0; i < ips.length; i++) {
      final ip = ips[i];
      onProgress?.call(ip, i / ips.length);

      if (config.delayBetweenRequests > Duration.zero) {
        await Future.delayed(config.delayBetweenRequests);
      }

      try {
        final result = await scanSingle(ip, networkSegment);
        if (result != null) {
          results.add(result);
          onResult?.call(result);
        }
      } catch (e) {
        // 记录错误但继续扫描
        print('Error scanning $ip with ${this.runtimeType}: $e');
      }
    }

    return results;
  }

  /// 获取扫描器描述
  String get description;

  /// 获取扫描器优先级（数字越小优先级越高）
  int get priority;
}

/// 信号量实现，用于控制并发数
class Semaphore {
  final int maxCount;
  int _currentCount;
  final Queue<Completer<void>> _waitQueue = Queue<Completer<void>>();

  Semaphore(this.maxCount) : _currentCount = maxCount;

  Future<void> acquire() async {
    if (_currentCount > 0) {
      _currentCount--;
      return;
    }

    final completer = Completer<void>();
    _waitQueue.add(completer);
    return completer.future;
  }

  void release() {
    if (_waitQueue.isNotEmpty) {
      final completer = _waitQueue.removeFirst();
      completer.complete();
    } else {
      _currentCount++;
    }
  }
}
