import 'dart:async';

import 'base_scanner.dart';
import 'icmp_scanner.dart';
import 'tcp_scanner.dart';
import 'arp_scanner.dart';
import 'mdns_scanner.dart';
import 'upnp_scanner.dart';
import 'dns_scanner.dart';
import 'ipv6_scanner.dart';

/// 扫描任务优先级
enum ScanPriority {
  immediate, // 立即扫描（常见IP）
  high, // 高优先级（邻近IP）
  normal, // 普通优先级（其他IP）
}

/// 扫描任务
class ScanTask implements Comparable<ScanTask> {
  final String ip;
  final String networkSegment;
  final ScanPriority priority;
  final DateTime createdAt;

  ScanTask({
    required this.ip,
    required this.networkSegment,
    required this.priority,
  }) : createdAt = DateTime.now();

  /// 比较函数，用于优先级队列排序
  @override
  int compareTo(ScanTask other) {
    // 首先按优先级排序
    final priorityComparison = priority.index.compareTo(other.priority.index);
    if (priorityComparison != 0) return priorityComparison;

    // 相同优先级按创建时间排序
    return createdAt.compareTo(other.createdAt);
  }
}

/// 简单的优先级队列实现
class PriorityQueue<T extends Comparable<T>> {
  final List<T> _items = [];

  PriorityQueue();

  void add(T item) {
    _items.add(item);
    _bubbleUp(_items.length - 1);
  }

  T removeFirst() {
    if (_items.isEmpty) throw StateError('Queue is empty');

    final result = _items[0];
    final last = _items.removeLast();

    if (_items.isNotEmpty) {
      _items[0] = last;
      _bubbleDown(0);
    }

    return result;
  }

  bool get isNotEmpty => _items.isNotEmpty;
  bool get isEmpty => _items.isEmpty;
  int get length => _items.length;

  void _bubbleUp(int index) {
    while (index > 0) {
      final parentIndex = (index - 1) ~/ 2;
      if (_items[index].compareTo(_items[parentIndex]) >= 0) break;

      _swap(index, parentIndex);
      index = parentIndex;
    }
  }

  void _bubbleDown(int index) {
    while (true) {
      final leftChild = 2 * index + 1;
      final rightChild = 2 * index + 2;
      int smallest = index;

      if (leftChild < _items.length &&
          _items[leftChild].compareTo(_items[smallest]) < 0) {
        smallest = leftChild;
      }

      if (rightChild < _items.length &&
          _items[rightChild].compareTo(_items[smallest]) < 0) {
        smallest = rightChild;
      }

      if (smallest == index) break;

      _swap(index, smallest);
      index = smallest;
    }
  }

  void _swap(int i, int j) {
    final temp = _items[i];
    _items[i] = _items[j];
    _items[j] = temp;
  }
}

/// 扫描管理器
class ScanManager {
  final List<BaseScanner> _scanners = [];
  final Map<ScanResultType, bool> _enabledScanners = {};

  ScanManager() {
    _initializeScanners();
  }

  /// 初始化所有扫描器
  void _initializeScanners() {
    // 使用极致优化的配置创建扫描器
    final icmpTurboConfig = ScannerConfig(
      timeout: const Duration(milliseconds: 500), // 更短的超时时间
      maxConcurrency: 200, // 极高并发，ICMP可以承受
      enableParallelScanning: true,
      delayBetweenRequests: Duration.zero, // 无延迟
    );

    final tcpTurboConfig = ScannerConfig(
      timeout: const Duration(milliseconds: 800), // 更短的TCP超时
      maxConcurrency: 100, // 高并发TCP连接
      enableParallelScanning: true,
      delayBetweenRequests: Duration.zero, // 无延迟
    );

    final highPerformanceConfig = ScannerConfig(
      timeout: const Duration(seconds: 1), // 减少超时时间
      maxConcurrency: 80, // 增加并发数
      enableParallelScanning: true,
      delayBetweenRequests: const Duration(milliseconds: 5), // 最小延迟
    );

    final standardConfig = ScannerConfig(
      timeout: const Duration(seconds: 2), // 减少超时时间
      maxConcurrency: 50, // 增加并发数
      enableParallelScanning: true,
      delayBetweenRequests: const Duration(milliseconds: 10),
    );

    final conservativeConfig = ScannerConfig(
      timeout: const Duration(seconds: 3), // 减少超时时间
      maxConcurrency: 30, // 增加并发数
      enableParallelScanning: true,
      delayBetweenRequests: const Duration(milliseconds: 20),
    );

    _scanners.addAll([
      IcmpScanner(config: icmpTurboConfig), // 极致优化的ICMP配置
      TcpScanner(config: tcpTurboConfig), // 极致优化的TCP配置
      ArpScanner(config: highPerformanceConfig), // 高性能ARP配置
      MdnsScanner(config: conservativeConfig), // mDNS保持保守配置
      UpnpScanner(config: standardConfig), // 标准UPnP配置
      DnsScanner(config: highPerformanceConfig), // 高性能DNS配置
      Ipv6Scanner(config: standardConfig), // 标准IPv6配置
    ]);

    // 默认启用最快的扫描器
    _enabledScanners[ScanResultType.icmpPing] = true;
    _enabledScanners[ScanResultType.tcpPort] = true;
    _enabledScanners[ScanResultType.arpTable] = true;
    _enabledScanners[ScanResultType.dnsReverse] = true;
    // 默认禁用较慢的扫描器
    _enabledScanners[ScanResultType.mdns] = false;
    _enabledScanners[ScanResultType.upnp] = false;
    _enabledScanners[ScanResultType.ipv6] = false;
  }

  /// 获取所有可用的扫描器
  List<BaseScanner> get availableScanners => List.unmodifiable(_scanners);

  /// 获取已启用的扫描器
  List<BaseScanner> get enabledScanners => _scanners
      .where((scanner) => _enabledScanners[scanner.scanType] == true)
      .toList();

  /// 性能监控数据
  final Map<ScanResultType, List<int>> _responseTimes = {};
  final Map<ScanResultType, List<bool>> _scanResults = {};

  /// 记录扫描性能数据
  void recordScanPerformance(
    ScanResultType scanType,
    int responseTime,
    bool success,
  ) {
    _responseTimes.putIfAbsent(scanType, () => <int>[]);
    _scanResults.putIfAbsent(scanType, () => <bool>[]);

    _responseTimes[scanType]!.add(responseTime);
    _scanResults[scanType]!.add(success);

    // 保持最近100次记录
    if (_responseTimes[scanType]!.length > 100) {
      _responseTimes[scanType]!.removeAt(0);
      _scanResults[scanType]!.removeAt(0);
    }
  }

  /// 获取扫描器性能建议
  Map<String, dynamic> getPerformanceRecommendations() {
    final recommendations = <String, dynamic>{};

    for (final scanType in _responseTimes.keys) {
      final responseTimes = _responseTimes[scanType]!;
      final results = _scanResults[scanType]!;

      if (responseTimes.isNotEmpty && results.isNotEmpty) {
        final avgResponseTime =
            responseTimes.reduce((a, b) => a + b) / responseTimes.length;
        final successRate = results.where((r) => r).length / results.length;

        String recommendation = '';
        if (successRate > 0.9 && avgResponseTime < 300) {
          recommendation = '性能优秀，可以考虑增加并发数';
        } else if (successRate < 0.5 || avgResponseTime > 2000) {
          recommendation = '性能较差，建议减少并发数或增加超时时间';
        } else {
          recommendation = '性能正常';
        }

        recommendations[scanType.toString()] = {
          'avgResponseTime': avgResponseTime.round(),
          'successRate': (successRate * 100).round(),
          'recommendation': recommendation,
          'sampleSize': responseTimes.length,
        };
      }
    }

    return recommendations;
  }

  /// 获取网络性能统计
  Map<String, dynamic> getNetworkStats() {
    final stats = <String, dynamic>{};
    for (final scanner in _scanners) {
      stats[scanner.scanType.toString()] = {
        'maxConcurrency': scanner.config.maxConcurrency,
        'timeout': scanner.config.timeout.inMilliseconds,
        'delayBetweenRequests':
            scanner.config.delayBetweenRequests.inMilliseconds,
      };
    }
    return stats;
  }

  /// 智能扫描策略 - 根据网络环境自动选择最优扫描器
  Map<ScanResultType, bool> getSmartScanConfig({
    bool prioritizeSpeed = true,
    bool includeAdvanced = false,
  }) {
    final config = <ScanResultType, bool>{};

    if (prioritizeSpeed) {
      // 速度优先模式 - 只启用最快的扫描器
      config[ScanResultType.icmpPing] = true; // 最快的连通性检测
      config[ScanResultType.tcpPort] = true; // 快速服务检测
      config[ScanResultType.arpTable] = true; // 快速MAC地址获取
      config[ScanResultType.dnsReverse] = false; // 可能较慢
      config[ScanResultType.bonjour] = false; // 较慢
      config[ScanResultType.upnp] = false; // 较慢
      config[ScanResultType.ipv6] = false; // 较慢
      config[ScanResultType.mdns] = false; // 较慢
      config[ScanResultType.ssdp] = false; // 较慢
    } else {
      // 全面扫描模式
      config[ScanResultType.icmpPing] = true;
      config[ScanResultType.tcpPort] = true;
      config[ScanResultType.arpTable] = true;
      config[ScanResultType.dnsReverse] = true;
      config[ScanResultType.bonjour] = includeAdvanced;
      config[ScanResultType.upnp] = includeAdvanced;
      config[ScanResultType.ipv6] = includeAdvanced;
      config[ScanResultType.mdns] = includeAdvanced;
      config[ScanResultType.ssdp] = includeAdvanced;
    }

    return config;
  }

  /// 应用智能扫描配置
  void applySmartScanConfig({
    bool prioritizeSpeed = true,
    bool includeAdvanced = false,
  }) {
    final config = getSmartScanConfig(
      prioritizeSpeed: prioritizeSpeed,
      includeAdvanced: includeAdvanced,
    );
    setScannerConfig(config);
  }

  /// 获取当前网络环境评估
  Map<String, dynamic> assessNetworkEnvironment() {
    final recommendations = getPerformanceRecommendations();

    // 计算整体网络性能
    double avgResponseTime = 0;
    double avgSuccessRate = 0;
    int totalSamples = 0;

    for (final data in recommendations.values) {
      if (data is Map<String, dynamic>) {
        final responseTime = (data['avgResponseTime'] ?? 0) as int;
        final successRate = (data['successRate'] ?? 0) as int;
        final sampleSize = (data['sampleSize'] ?? 0) as int;

        avgResponseTime += responseTime * sampleSize;
        avgSuccessRate += successRate * sampleSize;
        totalSamples += sampleSize;
      }
    }

    if (totalSamples > 0) {
      avgResponseTime /= totalSamples;
      avgSuccessRate /= totalSamples;
    }

    // 网络环境评级
    String networkQuality = 'unknown';
    if (avgSuccessRate > 90 && avgResponseTime < 200) {
      networkQuality = 'excellent';
    } else if (avgSuccessRate > 80 && avgResponseTime < 500) {
      networkQuality = 'good';
    } else if (avgSuccessRate > 60 && avgResponseTime < 1000) {
      networkQuality = 'fair';
    } else {
      networkQuality = 'poor';
    }

    return {
      'networkQuality': networkQuality,
      'avgResponseTime': avgResponseTime.round(),
      'avgSuccessRate': avgSuccessRate.round(),
      'totalSamples': totalSamples,
      'recommendations': recommendations,
    };
  }

  /// 启用/禁用扫描器
  void setScannerEnabled(ScanResultType scanType, bool enabled) {
    _enabledScanners[scanType] = enabled;
  }

  /// 检查扫描器是否启用
  bool isScannerEnabled(ScanResultType scanType) {
    return _enabledScanners[scanType] ?? false;
  }

  /// 获取扫描器配置
  Map<ScanResultType, bool> get scannerConfig =>
      Map.unmodifiable(_enabledScanners);

  /// 设置扫描器配置
  void setScannerConfig(Map<ScanResultType, bool> config) {
    _enabledScanners.clear();
    _enabledScanners.addAll(config);
  }

  /// 检查所有扫描器的可用性
  Future<Map<ScanResultType, bool>> checkScannersAvailability() async {
    final availability = <ScanResultType, bool>{};

    for (final scanner in _scanners) {
      try {
        availability[scanner.scanType] = await scanner.isAvailable();
      } catch (e) {
        availability[scanner.scanType] = false;
      }
    }

    return availability;
  }

  /// 扫描单个IP地址
  Future<List<ScanResult>> scanSingleIp(
    String ip,
    String networkSegment, {
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
  }) async {
    final results = <ScanResult>[];
    final enabledScannersList = enabledScanners;

    // 按优先级排序
    enabledScannersList.sort((a, b) => b.priority.compareTo(a.priority));

    for (int i = 0; i < enabledScannersList.length; i++) {
      final scanner = enabledScannersList[i];

      try {
        onProgress?.call(ip, i / enabledScannersList.length);

        final result = await scanner.scanSingle(ip, networkSegment);
        if (result != null) {
          results.add(result);
          onResult?.call(result);
        }
      } catch (e) {
        // 扫描器出错，继续下一个
        print('Scanner ${scanner.name} failed for IP $ip: $e');
      }
    }

    return results;
  }

  /// 批量扫描IP地址
  Future<List<ScanResult>> scanBatch(
    List<String> ips,
    String networkSegment, {
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
    int? maxConcurrency,
    bool parallelScanners = true, // 新增：是否并行执行扫描器
  }) async {
    final enabledScannersList = enabledScanners;

    if (enabledScannersList.isEmpty) {
      return [];
    }

    if (parallelScanners) {
      return await _scanBatchParallel(
        ips,
        networkSegment,
        enabledScannersList,
        onProgress,
        onResult,
      );
    } else {
      return await _scanBatchSequential(
        ips,
        networkSegment,
        enabledScannersList,
        onProgress,
        onResult,
      );
    }
  }

  /// 并行执行所有扫描器
  Future<List<ScanResult>> _scanBatchParallel(
    List<String> ips,
    String networkSegment,
    List<BaseScanner> scanners,
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
  ) async {
    final allResults = <ScanResult>[];
    final progressMap = <String, double>{}; // 跟踪每个扫描器的进度

    // 并行执行所有扫描器
    final futures = scanners.map((scanner) async {
      try {
        final scannerResults = await scanner.scanBatch(
          ips,
          networkSegment,
          onProgress: (ip, progress) {
            // 更新该扫描器的进度
            progressMap[scanner.name] = progress;

            // 计算总体进度
            final totalProgress = progressMap.values.isEmpty
                ? 0.0
                : progressMap.values.reduce((a, b) => a + b) / scanners.length;
            onProgress?.call(ip, totalProgress);
          },
          onResult: onResult,
        );

        return scannerResults;
      } catch (e) {
        print('Scanner ${scanner.name} parallel scan failed: $e');
        return <ScanResult>[];
      }
    }).toList();

    // 等待所有扫描器完成
    final results = await Future.wait(futures);

    // 合并所有结果
    for (final scannerResults in results) {
      allResults.addAll(scannerResults);
    }

    return allResults;
  }

  /// 顺序执行扫描器（原有逻辑）
  Future<List<ScanResult>> _scanBatchSequential(
    List<String> ips,
    String networkSegment,
    List<BaseScanner> scanners,
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
  ) async {
    final allResults = <ScanResult>[];

    // 按优先级排序
    scanners.sort((a, b) => b.priority.compareTo(a.priority));

    // 为每个扫描器执行批量扫描
    for (int scannerIndex = 0; scannerIndex < scanners.length; scannerIndex++) {
      final scanner = scanners[scannerIndex];

      try {
        final scannerResults = await scanner.scanBatch(
          ips,
          networkSegment,
          onProgress: (ip, progress) {
            final totalProgress = (scannerIndex + progress) / scanners.length;
            onProgress?.call(ip, totalProgress);
          },
          onResult: onResult,
        );

        allResults.addAll(scannerResults);
      } catch (e) {
        print('Scanner ${scanner.name} batch scan failed: $e');
      }
    }

    return allResults;
  }

  /// 智能扫描：根据网络环境自动选择最佳扫描策略
  Future<List<ScanResult>> smartScan(
    List<String> ips,
    String networkSegment, {
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
  }) async {
    // 第一阶段：快速并行扫描（ICMP + TCP）
    final quickScanners = enabledScanners
        .where(
          (scanner) =>
              scanner.scanType == ScanResultType.icmpPing ||
              scanner.scanType == ScanResultType.tcpPort,
        )
        .toList();

    final quickResults = <ScanResult>[];

    if (quickScanners.isNotEmpty) {
      // 并行执行快速扫描器
      final quickFutures = quickScanners.map((scanner) async {
        try {
          return await scanner.scanBatch(
            ips,
            networkSegment,
            onProgress: (ip, progress) => onProgress?.call(ip, progress * 0.3),
            onResult: onResult,
          );
        } catch (e) {
          print('Quick scan failed for ${scanner.name}: $e');
          return <ScanResult>[];
        }
      }).toList();

      final quickResultsList = await Future.wait(quickFutures);
      for (final results in quickResultsList) {
        quickResults.addAll(results);
      }
    }

    // 获取活跃的IP地址
    final activeIps = quickResults.map((result) => result.ip).toSet().toList();

    if (activeIps.isEmpty) {
      return quickResults;
    }

    // 第二阶段：并行详细扫描活跃的IP
    final detailedScanners = enabledScanners
        .where(
          (scanner) =>
              scanner.scanType != ScanResultType.icmpPing &&
              scanner.scanType != ScanResultType.tcpPort,
        )
        .toList();

    final detailedResults = <ScanResult>[];

    if (detailedScanners.isNotEmpty) {
      // 并行执行详细扫描器
      final detailedFutures = detailedScanners.map((scanner) async {
        try {
          return await scanner.scanBatch(
            activeIps,
            networkSegment,
            onProgress: (ip, progress) {
              final totalProgress = 0.3 + progress * 0.7;
              onProgress?.call(ip, totalProgress);
            },
            onResult: onResult,
          );
        } catch (e) {
          print('Detailed scan failed for ${scanner.name}: $e');
          return <ScanResult>[];
        }
      }).toList();

      final detailedResultsList = await Future.wait(detailedFutures);
      for (final results in detailedResultsList) {
        detailedResults.addAll(results);
      }
    }

    return [...quickResults, ...detailedResults];
  }

  /// 获取扫描器统计信息
  Map<String, dynamic> getScannerStats() {
    final stats = <String, dynamic>{};

    for (final scanner in _scanners) {
      stats[scanner.name] = {
        'enabled': _enabledScanners[scanner.scanType] ?? false,
        'priority': scanner.priority,
        'description': scanner.description,
        'scan_type': scanner.scanType.toString(),
      };
    }

    return stats;
  }

  /// 重置所有扫描器配置
  void resetScannerConfig() {
    for (final scanner in _scanners) {
      _enabledScanners[scanner.scanType] = true;
    }
  }

  /// 获取推荐的扫描器配置
  Map<ScanResultType, bool> getRecommendedConfig() {
    return {
      ScanResultType.icmpPing: true, // 基础连通性检测
      ScanResultType.tcpPort: true, // 服务检测
      ScanResultType.arpTable: true, // MAC地址获取
      ScanResultType.bonjour: true, // Apple设备发现
      ScanResultType.upnp: false, // 可选，可能较慢
      ScanResultType.dnsReverse: true, // 主机名解析
      ScanResultType.ipv6: false, // 可选，IPv6环境
    };
  }

  /// 获取快速扫描配置
  Map<ScanResultType, bool> getQuickScanConfig() {
    return {
      ScanResultType.icmpPing: true,
      ScanResultType.tcpPort: true,
      ScanResultType.arpTable: false,
      ScanResultType.bonjour: false,
      ScanResultType.upnp: false,
      ScanResultType.dnsReverse: false,
      ScanResultType.ipv6: false,
    };
  }

  /// 获取完整扫描配置
  Map<ScanResultType, bool> getFullScanConfig() {
    return {
      ScanResultType.icmpPing: true,
      ScanResultType.tcpPort: true,
      ScanResultType.arpTable: true,
      ScanResultType.bonjour: true,
      ScanResultType.upnp: true,
      ScanResultType.dnsReverse: true,
      ScanResultType.ipv6: true,
    };
  }

  /// 高性能并行扫描：所有扫描器同时运行以获得最快速度
  Future<List<ScanResult>> turboScan(
    List<String> ips,
    String networkSegment, {
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
  }) async {
    final enabledScannersList = enabledScanners;

    if (enabledScannersList.isEmpty) {
      return [];
    }

    final allResults = <ScanResult>[];
    final progressMap = <String, double>{}; // 跟踪每个扫描器的进度

    // 所有扫描器完全并行执行，不分阶段
    final futures = enabledScannersList.map((scanner) async {
      try {
        final scannerResults = await scanner.scanBatch(
          ips,
          networkSegment,
          onProgress: (ip, progress) {
            // 更新该扫描器的进度
            progressMap[scanner.name] = progress;

            // 计算总体进度
            final totalProgress = progressMap.values.isEmpty
                ? 0.0
                : progressMap.values.reduce((a, b) => a + b) /
                      enabledScannersList.length;
            onProgress?.call(ip, totalProgress);
          },
          onResult: onResult,
        );

        return scannerResults;
      } catch (e) {
        print('Turbo scan failed for ${scanner.name}: $e');
        return <ScanResult>[];
      }
    }).toList();

    // 等待所有扫描器完成
    final results = await Future.wait(futures);

    // 合并所有结果
    for (final scannerResults in results) {
      allResults.addAll(scannerResults);
    }

    return allResults;
  }

  /// 广度优先搜索扫描 - 以最快速度发现最多设备
  Future<List<ScanResult>> breadthFirstScan(
    List<String> ips,
    String networkSegment, {
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
  }) async {
    final enabledScannersList = enabledScanners;
    if (enabledScannersList.isEmpty) return [];

    // 创建优先级队列
    final taskQueue = PriorityQueue<ScanTask>();
    final allResults = <ScanResult>[];
    final discoveredIps = <String>{};
    final completedIps = <String>{};

    // 按优先级添加扫描任务
    _addTasksWithPriority(ips, networkSegment, taskQueue);

    // 创建多个并发扫描流
    final maxConcurrentStreams = 8; // 增加并发流数量
    final activeStreams = <Future<void>>[];

    // 进度跟踪
    final totalTasks = taskQueue.length;
    var completedTasks = 0;

    // 启动多个并发扫描流
    for (int i = 0; i < maxConcurrentStreams; i++) {
      final streamFuture = _runScanStream(
        taskQueue,
        enabledScannersList,
        allResults,
        discoveredIps,
        completedIps,
        (ip, localProgress) {
          completedTasks++;
          final globalProgress = completedTasks / totalTasks;
          onProgress?.call(ip, globalProgress);
        },
        onResult,
      );
      activeStreams.add(streamFuture);
    }

    // 等待所有扫描流完成
    await Future.wait(activeStreams);

    return allResults;
  }

  /// 添加带优先级的扫描任务
  void _addTasksWithPriority(
    List<String> ips,
    String networkSegment,
    PriorityQueue<ScanTask> taskQueue,
  ) {
    for (final ip in ips) {
      final priority = _calculateIpPriority(ip, networkSegment);
      taskQueue.add(
        ScanTask(ip: ip, networkSegment: networkSegment, priority: priority),
      );
    }
  }

  /// 计算IP的扫描优先级
  ScanPriority _calculateIpPriority(String ip, String networkSegment) {
    final parts = ip.split('.');
    if (parts.length != 4) return ScanPriority.normal;

    final lastOctet = int.tryParse(parts[3]) ?? 0;

    // 立即优先级：常见的网关和服务器IP
    if ([1, 254, 253, 252].contains(lastOctet)) {
      return ScanPriority.immediate;
    }

    // 高优先级：常见的设备IP范围
    if ((lastOctet >= 2 && lastOctet <= 20) || // 网络设备
        (lastOctet >= 100 && lastOctet <= 120) || // DHCP常见范围
        (lastOctet >= 200 && lastOctet <= 220)) {
      // 静态IP常见范围
      return ScanPriority.high;
    }

    return ScanPriority.normal;
  }

  /// 运行单个扫描流
  Future<void> _runScanStream(
    PriorityQueue<ScanTask> taskQueue,
    List<BaseScanner> scanners,
    List<ScanResult> allResults,
    Set<String> discoveredIps,
    Set<String> completedIps,
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
  ) async {
    while (taskQueue.isNotEmpty) {
      final task = taskQueue.removeFirst();

      // 跳过已完成的IP
      if (completedIps.contains(task.ip)) continue;
      completedIps.add(task.ip);

      // 并行执行所有启用的扫描器
      final scanFutures = scanners.map((scanner) async {
        try {
          final result = await scanner.scanSingle(task.ip, task.networkSegment);
          return result;
        } catch (e) {
          // 忽略单个扫描器的错误，继续其他扫描器
          return null;
        }
      }).toList();

      // 等待所有扫描器完成，但使用超时避免卡住
      try {
        final results = await Future.wait(
          scanFutures,
        ).timeout(const Duration(seconds: 2)); // 减少超时时间

        // 处理结果
        for (final result in results) {
          if (result != null && result.isActive) {
            allResults.add(result);
            discoveredIps.add(result.ip);
            onResult?.call(result);

            // 发现新设备时，立即添加邻近IP到高优先级队列
            _addNeighborIpsToQueue(
              result.ip,
              task.networkSegment,
              taskQueue,
              completedIps,
            );
          }
        }
      } catch (e) {
        // 超时或其他错误，继续下一个任务
        print('Scan timeout for ${task.ip}: $e');
      }

      onProgress?.call(task.ip, 0.0);
    }
  }

  /// 添加邻近IP到队列（发现设备时动态扩展搜索范围）
  void _addNeighborIpsToQueue(
    String discoveredIp,
    String networkSegment,
    PriorityQueue<ScanTask> taskQueue,
    Set<String> completedIps,
  ) {
    final parts = discoveredIp.split('.');
    if (parts.length != 4) return;

    final lastOctet = int.tryParse(parts[3]) ?? 0;
    final networkBase = '${parts[0]}.${parts[1]}.${parts[2]}';

    // 添加邻近的IP地址（±3范围，减少范围以提高速度）
    for (int offset = -3; offset <= 3; offset++) {
      final neighborOctet = lastOctet + offset;
      if (neighborOctet >= 1 && neighborOctet <= 254) {
        final neighborIp = '$networkBase.$neighborOctet';

        // 只添加未完成的IP
        if (!completedIps.contains(neighborIp)) {
          taskQueue.add(
            ScanTask(
              ip: neighborIp,
              networkSegment: networkSegment,
              priority: ScanPriority.high,
            ),
          );
        }
      }
    }
  }

  /// 超快速扫描 - 只使用最快的扫描器
  Future<List<ScanResult>> ultraFastScan(
    List<String> ips,
    String networkSegment, {
    ScanProgressCallback? onProgress,
    ScanResultCallback? onResult,
  }) async {
    // 只使用ICMP和TCP扫描器，它们是最快的
    final fastScanners = _scanners
        .where(
          (scanner) =>
              scanner.scanType == ScanResultType.icmpPing ||
              scanner.scanType == ScanResultType.tcpPort,
        )
        .toList();

    if (fastScanners.isEmpty) return [];

    final allResults = <ScanResult>[];
    final maxConcurrency = 200; // 极高并发
    final semaphore = Semaphore(maxConcurrency);
    final completedCount = <int>[0];

    // 创建所有扫描任务
    final futures = ips.map((ip) async {
      await semaphore.acquire();
      try {
        // 并行执行快速扫描器
        final scanFutures = fastScanners.map((scanner) async {
          try {
            return await scanner.scanSingle(ip, networkSegment);
          } catch (e) {
            return null;
          }
        }).toList();

        final results = await Future.wait(
          scanFutures,
        ).timeout(const Duration(milliseconds: 500)); // 极短超时

        // 更新进度
        completedCount[0]++;
        onProgress?.call(ip, completedCount[0] / ips.length);

        // 处理结果
        for (final result in results) {
          if (result != null && result.isActive) {
            allResults.add(result);
            onResult?.call(result);
          }
        }
      } catch (e) {
        // 忽略超时和错误
      } finally {
        semaphore.release();
      }
    }).toList();

    await Future.wait(futures);
    return allResults;
  }

  /// 释放资源
  void dispose() {
    _scanners.clear();
    _enabledScanners.clear();
  }
}
