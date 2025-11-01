import 'dart:io';
import 'dart:async';

import 'package:flutter/material.dart';
import 'package:connectivity_plus/connectivity_plus.dart';
import 'package:cinnascan/scanners/scan_manager.dart';
import 'package:cinnascan/scanners/base_scanner.dart';
import 'package:cinnascan/widgets/scanner_selection_dialog.dart';

class LocalNetworkInterface {
  final String name;
  final String address;
  final String type;

  LocalNetworkInterface({
    required this.name,
    required this.address,
    required this.type,
  });
}

class ScanPage extends StatefulWidget {
  const ScanPage({super.key});

  @override
  State<ScanPage> createState() => _ScanPageState();
}

class _ScanPageState extends State<ScanPage> {
  final ScanManager _scanManager = ScanManager();
  List<LocalNetworkInterface> _networkInterfaces = [];
  final List<ScanResult> _discoveredDevices = [];
  bool _isScanning = false;
  double _scanProgress = 0.0;
  String _currentScanIP = '';
  final List<String> _debugMessages = [];
  bool _showDebugInfo = false;
  Timer? _quickScanTimer;
  StreamSubscription? _scanSubscription;

  // 网络连接监听相关
  final Connectivity _connectivity = Connectivity();
  StreamSubscription<List<ConnectivityResult>>? _connectivitySubscription;
  List<ConnectivityResult> _connectionStatus = [ConnectivityResult.none];

  @override
  void initState() {
    super.initState();
    _initConnectivityListener();
    _loadNetworkInterfaces();
    _startQuickScan();
  }

  @override
  void dispose() {
    _quickScanTimer?.cancel();
    _scanSubscription?.cancel();
    _connectivitySubscription?.cancel();
    super.dispose();
  }

  void _addDebugMessage(String message) {
    final timestamp = DateTime.now().toString().substring(11, 19);
    setState(() {
      _debugMessages.add('[$timestamp] $message');
      // 保持最新的50条消息
      if (_debugMessages.length > 50) {
        _debugMessages.removeAt(0);
      }
    });
    print(message); // 同时输出到控制台
  }

  // 启动快速ping扫描，每30秒执行一次
  void _startQuickScan() {
    _quickScanTimer = Timer.periodic(const Duration(seconds: 30), (timer) {
      if (!_isScanning) {
        _performQuickScan();
      }
    });
    // 立即执行一次
    _performQuickScan();
  }

  // 执行快速ping扫描
  Future<void> _performQuickScan() async {
    if (_networkInterfaces.isEmpty) return;

    _addDebugMessage('开始快速ping扫描...');

    // 使用快速扫描配置（只启用ICMP和TCP）
    final quickConfig = _scanManager.getQuickScanConfig();
    _scanManager.setScannerConfig(quickConfig);

    final allTargetIPs = <String>[];
    final networkBases = <String>[];

    for (final interface in _networkInterfaces) {
      final ipParts = interface.address.split('.');
      final networkBase = '${ipParts[0]}.${ipParts[1]}.${ipParts[2]}';

      if (!networkBases.contains(networkBase)) {
        networkBases.add(networkBase);
        // 快速扫描只扫描常见的IP范围
        for (int i = 1; i <= 254; i++) {
          allTargetIPs.add('$networkBase.$i');
        }
      }
    }

    // 执行快速扫描
    final results = await _scanManager.scanBatch(
      allTargetIPs,
      networkBases.first,
    );

    // 更新设备列表
    setState(() {
      for (final result in results) {
        // 检查是否是新设备
        final existingIndex = _discoveredDevices.indexWhere(
          (d) => d.ip == result.ip,
        );
        if (existingIndex >= 0) {
          // 更新现有设备
          _discoveredDevices[existingIndex] = result;
        } else {
          // 添加新设备
          _discoveredDevices.add(result);
          _addDebugMessage(
            '发现新设备: ${result.ip} (${result.detectionMethodName})',
          );
        }
      }
    });

    _addDebugMessage('快速扫描完成，发现 ${results.length} 个活跃设备');
  }

  Widget _buildDeviceListBySegment() {
    // 按网段分组活跃设备
    final activeDevices = _discoveredDevices.where((d) => d.isActive).toList();
    final devicesBySegment = <String, List<ScanResult>>{};

    for (final device in activeDevices) {
      var devices = devicesBySegment[device.networkSegment] ?? [];
      devices.add(device);
      devicesBySegment[device.networkSegment] = devices;
    }

    if (devicesBySegment.isEmpty) {
      return const Center(
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.search, size: 64, color: Colors.grey),
            SizedBox(height: 16),
            Text('正在搜索设备...', style: TextStyle(color: Colors.grey)),
          ],
        ),
      );
    }

    return ListView.builder(
      itemCount: devicesBySegment.length,
      itemBuilder: (context, segmentIndex) {
        final entry = devicesBySegment.entries.elementAt(segmentIndex);
        final segment = entry.key;
        final devices = entry.value;

        return ExpansionTile(
          title: Text(
            '网段 $segment.x (${devices.length} 个设备)',
            style: const TextStyle(fontWeight: FontWeight.bold),
          ),
          initiallyExpanded: true,
          children: devices.map((device) {
            return ListTile(
              leading: Icon(_getDeviceIcon(device), color: Colors.green),
              title: Text(
                device.ip,
                style: const TextStyle(fontFamily: 'monospace'),
              ),
              subtitle: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    '${device.detectionMethodName} • 响应时间: ${device.responseTime}ms',
                  ),
                  if (device.hostname != null)
                    Text(
                      '主机名: ${device.hostname}',
                      style: const TextStyle(fontSize: 12),
                    ),
                  if (device.additionalInfo.isNotEmpty)
                    Text(
                      '详情: ${device.additionalInfo.entries.map((e) => '${e.key}: ${e.value}').join(', ')}',
                      style: const TextStyle(fontSize: 12, color: Colors.grey),
                    ),
                ],
              ),
              trailing: const Icon(Icons.check_circle, color: Colors.green),
              onTap: () => _showDeviceDetails(device),
            );
          }).toList(),
        );
      },
    );
  }

  IconData _getDeviceIcon(ScanResult device) {
    switch (device.detectionMethod) {
      case ScanResultType.bonjour:
        return Icons.apple;
      case ScanResultType.upnp:
        return Icons.router;
      case ScanResultType.dnsReverse:
        return Icons.dns;
      case ScanResultType.ipv6:
        return Icons.language;
      default:
        return Icons.computer;
    }
  }

  void _showDeviceDetails(ScanResult device) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text('设备详情 - ${device.ip}'),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text('IP地址: ${device.ip}'),
            Text('检测方法: ${device.detectionMethodName}'),
            Text('响应时间: ${device.responseTime}ms'),
            Text('网段: ${device.networkSegment}'),
            if (device.hostname != null) Text('主机名: ${device.hostname}'),
            if (device.additionalInfo.isNotEmpty) ...[
              const SizedBox(height: 8),
              const Text(
                '附加信息:',
                style: TextStyle(fontWeight: FontWeight.bold),
              ),
              ...device.additionalInfo.entries.map(
                (e) => Text('${e.key}: ${e.value}'),
              ),
            ],
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('关闭'),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // 本机网络接口信息
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      '本机网络接口',
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 8),
                    if (_networkInterfaces.isEmpty)
                      const Text('正在获取网络接口信息...')
                    else
                      ..._networkInterfaces.map(
                        (interface) => Padding(
                          padding: const EdgeInsets.symmetric(vertical: 4.0),
                          child: Row(
                            children: [
                              Icon(
                                interface.type == 'wifi'
                                    ? Icons.wifi
                                    : Icons.cable,
                                size: 16,
                              ),
                              const SizedBox(width: 8),
                              Expanded(
                                child: Text(
                                  '${interface.name}: ${interface.address}',
                                  style: const TextStyle(
                                    fontFamily: 'monospace',
                                  ),
                                ),
                              ),
                            ],
                          ),
                        ),
                      ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            // 扫描控制
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        const Text(
                          '局域网扫描',
                          style: TextStyle(
                            fontSize: 18,
                            fontWeight: FontWeight.bold,
                          ),
                        ),
                        // 第一行扫描按钮
                        Row(
                          children: [
                            ElevatedButton.icon(
                              onPressed: _isScanning ? null : _startBfsScan,
                              icon: const Icon(Icons.speed),
                              label: Text(_isScanning ? '扫描中...' : 'BFS快速扫描'),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: Colors.green,
                                foregroundColor: Colors.white,
                              ),
                            ),
                            const SizedBox(width: 8),
                            ElevatedButton.icon(
                              onPressed: _isScanning
                                  ? null
                                  : _startUltraFastScan,
                              icon: const Icon(Icons.flash_on),
                              label: Text(_isScanning ? '扫描中...' : '超快速扫描'),
                              style: ElevatedButton.styleFrom(
                                backgroundColor: Colors.orange,
                                foregroundColor: Colors.white,
                              ),
                            ),
                          ],
                        ),
                        const SizedBox(height: 8),
                        // 第二行扫描按钮
                        Row(
                          children: [
                            ElevatedButton.icon(
                              onPressed: _isScanning ? null : _startFullScan,
                              icon: const Icon(Icons.search),
                              label: Text(_isScanning ? '扫描中...' : '完整扫描'),
                            ),
                            const SizedBox(width: 8),
                            ElevatedButton.icon(
                              onPressed: _showScannerSelection,
                              icon: const Icon(Icons.settings),
                              label: const Text('扫描设置'),
                            ),
                            const SizedBox(width: 8),
                            ElevatedButton.icon(
                              onPressed: () {
                                setState(() {
                                  _showDebugInfo = !_showDebugInfo;
                                });
                              },
                              icon: Icon(
                                _showDebugInfo
                                    ? Icons.visibility_off
                                    : Icons.visibility,
                              ),
                              label: const Text('调试'),
                            ),
                          ],
                        ),
                      ],
                    ),
                    if (_isScanning) ...[
                      const SizedBox(height: 16),
                      LinearProgressIndicator(value: _scanProgress),
                      const SizedBox(height: 8),
                      Text('正在扫描: $_currentScanIP'),
                    ],
                    const SizedBox(height: 8),
                    Text(
                      '已发现 ${_discoveredDevices.where((d) => d.isActive).length} 个活跃设备',
                      style: const TextStyle(color: Colors.grey),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(height: 16),

            // 调试信息
            if (_showDebugInfo) ...[
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        '调试信息',
                        style: TextStyle(
                          fontSize: 16,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 8),
                      Container(
                        height: 150,
                        width: double.infinity,
                        decoration: BoxDecoration(
                          color: Colors.black87,
                          borderRadius: BorderRadius.circular(4),
                        ),
                        child: SingleChildScrollView(
                          padding: const EdgeInsets.all(8),
                          child: Text(
                            _debugMessages.join('\n'),
                            style: const TextStyle(
                              color: Colors.green,
                              fontFamily: 'monospace',
                              fontSize: 12,
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
            ],

            // 设备列表
            Expanded(
              child: Card(
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        '发现的设备',
                        style: TextStyle(
                          fontSize: 18,
                          fontWeight: FontWeight.bold,
                        ),
                      ),
                      const SizedBox(height: 16),
                      Expanded(child: _buildDeviceListBySegment()),
                    ],
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  /// 初始化网络连接状态监听器
  Future<void> _initConnectivityListener() async {
    try {
      // 获取初始连接状态
      _connectionStatus = await _connectivity.checkConnectivity();
      _addDebugMessage(
        '初始网络状态: ${_getConnectivityStatusText(_connectionStatus)}',
      );

      // 监听网络连接状态变化
      _connectivitySubscription = _connectivity.onConnectivityChanged.listen(
        _onConnectivityChanged,
        onError: (error) {
          _addDebugMessage('网络状态监听错误: $error');
        },
      );
    } catch (e) {
      _addDebugMessage('初始化网络监听失败: $e');
    }
  }

  /// 处理网络连接状态变化
  void _onConnectivityChanged(List<ConnectivityResult> result) {
    setState(() {
      _connectionStatus = result;
    });

    final statusText = _getConnectivityStatusText(result);
    _addDebugMessage('网络状态变化: $statusText');

    // 当网络状态发生变化时，重新加载网络接口
    if (result.any((status) => status != ConnectivityResult.none)) {
      _addDebugMessage('检测到网络连接，正在重新加载网络接口...');
      // 延迟一秒后重新加载，给系统时间来稳定网络配置
      Future.delayed(const Duration(seconds: 1), () {
        _loadNetworkInterfaces();
      });
    } else {
      _addDebugMessage('网络连接断开');
      // 清空网络接口列表
      setState(() {
        _networkInterfaces.clear();
      });
    }
  }

  /// 获取网络连接状态的文本描述
  String _getConnectivityStatusText(List<ConnectivityResult> results) {
    if (results.isEmpty || results.contains(ConnectivityResult.none)) {
      return '无网络连接';
    }

    final statusTexts = results.map((result) {
      switch (result) {
        case ConnectivityResult.wifi:
          return 'WiFi';
        case ConnectivityResult.ethernet:
          return '以太网';
        case ConnectivityResult.mobile:
          return '移动网络';
        case ConnectivityResult.bluetooth:
          return '蓝牙';
        case ConnectivityResult.vpn:
          return 'VPN';
        case ConnectivityResult.other:
          return '其他';
        case ConnectivityResult.none:
          return '无连接';
      }
    }).toList();

    return statusTexts.join(', ');
  }

  Future<void> _loadNetworkInterfaces() async {
    try {
      final interfaces = await NetworkInterface.list();
      final networkInterfaces = <LocalNetworkInterface>[];

      for (final interface in interfaces) {
        // 过滤掉虚拟网络接口和不常用的接口
        if (_shouldSkipInterface(interface.name)) {
          continue;
        }

        for (final addr in interface.addresses) {
          if (addr.type == InternetAddressType.IPv4 && !addr.isLoopback) {
            // 过滤掉不常见的网段
            if (_isCommonNetworkSegment(addr.address)) {
              networkInterfaces.add(
                LocalNetworkInterface(
                  name: interface.name,
                  address: addr.address,
                  type: interface.name.toLowerCase().contains('wi')
                      ? 'wifi'
                      : 'ethernet',
                ),
              );
            }
          }
        }
      }

      setState(() {
        _networkInterfaces = networkInterfaces;
      });

      _addDebugMessage('发现 ${networkInterfaces.length} 个有效网络接口');
    } catch (e) {
      _addDebugMessage('获取网络接口失败: $e');
    }
  }

  /// 判断是否应该跳过某个网络接口
  bool _shouldSkipInterface(String interfaceName) {
    final name = interfaceName.toLowerCase();

    // 跳过虚拟网络接口
    final skipPatterns = [
      'utun', // VPN隧道接口
      'bridge', // 虚拟网桥
      'vmnet', // VMware虚拟网络
      'vboxnet', // VirtualBox虚拟网络
      'docker', // Docker网络
      'lo', // 回环接口
      'awdl', // Apple Wireless Direct Link
      'llw', // 低延迟无线
    ];

    return skipPatterns.any((pattern) => name.contains(pattern));
  }

  /// 判断是否是常见的网络段
  bool _isCommonNetworkSegment(String ip) {
    final parts = ip.split('.');
    if (parts.length != 4) return false;

    final firstOctet = int.tryParse(parts[0]) ?? 0;
    final secondOctet = int.tryParse(parts[1]) ?? 0;

    // 常见的私有网络段
    if (firstOctet == 192 && secondOctet == 168) return true; // 192.168.x.x
    if (firstOctet == 10) return true; // 10.x.x.x
    if (firstOctet == 172 && secondOctet >= 16 && secondOctet <= 31)
      return true; // 172.16-31.x.x

    // 过滤掉一些特殊用途的网段
    if (firstOctet == 169 && secondOctet == 254) return false; // 链路本地地址
    if (firstOctet == 198 && secondOctet == 18) return false; // 基准测试网段

    return false;
  }

  /// 生成智能扫描目标，避免扫描整个网段
  List<String> _generateSmartScanTargets(String networkBase, String currentIP) {
    final targets = <String>[];
    final currentParts = currentIP.split('.');
    final currentLastOctet = int.tryParse(currentParts[3]) ?? 1;

    // 1. 添加当前设备IP（自己）
    targets.add(currentIP);

    // 2. 添加常见的网关和DNS服务器IP
    final commonIPs = [1, 254, 253, 252]; // 网关通常是1或254
    for (final ip in commonIPs) {
      targets.add('$networkBase.$ip');
    }

    // 3. 添加当前IP附近的范围（±10）
    final rangeStart = (currentLastOctet - 10).clamp(1, 254);
    final rangeEnd = (currentLastOctet + 10).clamp(1, 254);
    for (int i = rangeStart; i <= rangeEnd; i++) {
      targets.add('$networkBase.$i');
    }

    // 4. 添加一些常见的设备IP范围
    final commonRanges = [
      [2, 20], // 路由器、交换机等网络设备
      [100, 120], // DHCP常见分配范围
      [200, 220], // 静态IP常见范围
    ];

    for (final range in commonRanges) {
      for (int i = range[0]; i <= range[1]; i++) {
        targets.add('$networkBase.$i');
      }
    }

    // 去重并排序
    final uniqueTargets = targets.toSet().toList();
    uniqueTargets.sort((a, b) {
      final aLast = int.parse(a.split('.')[3]);
      final bLast = int.parse(b.split('.')[3]);
      return aLast.compareTo(bLast);
    });

    return uniqueTargets;
  }

  // 广度优先搜索扫描 - 快速发现设备
  Future<void> _startBfsScan() async {
    if (_networkInterfaces.isEmpty) {
      _addDebugMessage('错误: 没有找到可用的网络接口');
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('没有找到可用的网络接口')));
      return;
    }

    setState(() {
      _isScanning = true;
      _scanProgress = 0.0;
      _discoveredDevices.clear();
      _debugMessages.clear();
    });

    _addDebugMessage('开始广度优先搜索扫描...');

    final allTargetIPs = <String>[];
    final networkBases = <String>[];

    for (final interface in _networkInterfaces) {
      final ipParts = interface.address.split('.');
      final networkBase = '${ipParts[0]}.${ipParts[1]}.${ipParts[2]}';

      if (!networkBases.contains(networkBase)) {
        networkBases.add(networkBase);

        // 智能扫描策略：优先扫描常见的IP范围
        final smartTargets = _generateSmartScanTargets(
          networkBase,
          interface.address,
        );
        allTargetIPs.addAll(smartTargets);

        _addDebugMessage(
          '发现网段: $networkBase.x，BFS扫描 ${smartTargets.length} 个目标 (${interface.name})',
        );
      }
    }

    _addDebugMessage(
      '开始BFS扫描 ${networkBases.length} 个网段，共 ${allTargetIPs.length} 个IP地址',
    );

    try {
      // 使用广度优先搜索扫描
      final results = await _scanManager.breadthFirstScan(
        allTargetIPs,
        networkBases.first,
        onProgress: (ip, progress) {
          setState(() {
            _currentScanIP = ip;
            _scanProgress = progress;
          });
        },
        onResult: (result) {
          setState(() {
            _discoveredDevices.add(result);
          });
          _addDebugMessage(
            '✓ 发现设备 ${result.ip} (${result.detectionMethodName})',
          );
        },
      );

      _addDebugMessage(
        'BFS扫描完成，发现 ${results.where((d) => d.isActive).length} 个活跃设备',
      );

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            'BFS扫描完成，发现 ${results.where((d) => d.isActive).length} 个设备',
          ),
          backgroundColor: Colors.green,
        ),
      );
    } catch (e) {
      _addDebugMessage('BFS扫描出错: $e');
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('BFS扫描出错: $e')));
    } finally {
      setState(() {
        _isScanning = false;
        _currentScanIP = '';
      });
    }
  }

  // 超快速扫描 - 只使用最快的扫描器
  Future<void> _startUltraFastScan() async {
    if (_networkInterfaces.isEmpty) {
      _addDebugMessage('错误: 没有找到可用的网络接口');
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('没有找到可用的网络接口')));
      return;
    }

    setState(() {
      _isScanning = true;
      _scanProgress = 0.0;
      _discoveredDevices.clear();
      _debugMessages.clear();
    });

    _addDebugMessage('开始超快速扫描...');

    final allTargetIPs = <String>[];
    final networkBases = <String>[];

    for (final interface in _networkInterfaces) {
      final ipParts = interface.address.split('.');
      final networkBase = '${ipParts[0]}.${ipParts[1]}.${ipParts[2]}';

      if (!networkBases.contains(networkBase)) {
        networkBases.add(networkBase);

        // 只扫描最常见的IP范围以提高速度
        final commonIPs = <String>[];
        // 网关和常见服务器
        for (final lastOctet in [1, 254, 253, 252]) {
          commonIPs.add('$networkBase.$lastOctet');
        }
        // 常见设备范围
        for (int i = 2; i <= 20; i++) {
          commonIPs.add('$networkBase.$i');
        }
        for (int i = 100; i <= 120; i++) {
          commonIPs.add('$networkBase.$i');
        }

        allTargetIPs.addAll(commonIPs);
        _addDebugMessage(
          '发现网段: $networkBase.x，超快速扫描 ${commonIPs.length} 个目标 (${interface.name})',
        );
      }
    }

    _addDebugMessage(
      '开始超快速扫描 ${networkBases.length} 个网段，共 ${allTargetIPs.length} 个IP地址',
    );

    try {
      // 使用超快速扫描
      final results = await _scanManager.ultraFastScan(
        allTargetIPs,
        networkBases.first,
        onProgress: (ip, progress) {
          setState(() {
            _currentScanIP = ip;
            _scanProgress = progress;
          });
        },
        onResult: (result) {
          setState(() {
            _discoveredDevices.add(result);
          });
          _addDebugMessage(
            '✓ 发现设备 ${result.ip} (${result.detectionMethodName})',
          );
        },
      );

      _addDebugMessage(
        '超快速扫描完成，发现 ${results.where((d) => d.isActive).length} 个活跃设备',
      );

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            '超快速扫描完成，发现 ${results.where((d) => d.isActive).length} 个设备',
          ),
          backgroundColor: Colors.green,
        ),
      );
    } catch (e) {
      _addDebugMessage('超快速扫描出错: $e');
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('超快速扫描出错: $e')));
    } finally {
      setState(() {
        _isScanning = false;
        _currentScanIP = '';
      });
    }
  }

  Future<void> _startFullScan() async {
    if (_networkInterfaces.isEmpty) {
      _addDebugMessage('错误: 没有找到可用的网络接口');
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(const SnackBar(content: Text('没有找到可用的网络接口')));
      return;
    }

    setState(() {
      _isScanning = true;
      _scanProgress = 0.0;
      _discoveredDevices.clear();
      _debugMessages.clear();
    });

    _addDebugMessage('开始扫描...');

    final allTargetIPs = <String>[];
    final networkBases = <String>[];

    for (final interface in _networkInterfaces) {
      final ipParts = interface.address.split('.');
      final networkBase = '${ipParts[0]}.${ipParts[1]}.${ipParts[2]}';

      if (!networkBases.contains(networkBase)) {
        networkBases.add(networkBase);

        // 智能扫描策略：优先扫描常见的IP范围
        final smartTargets = _generateSmartScanTargets(
          networkBase,
          interface.address,
        );
        allTargetIPs.addAll(smartTargets);

        _addDebugMessage(
          '发现网段: $networkBase.x，智能扫描 ${smartTargets.length} 个目标 (${interface.name})',
        );
      }
    }

    _addDebugMessage(
      '开始扫描 ${networkBases.length} 个网段，共 ${allTargetIPs.length} 个IP地址',
    );

    try {
      final totalHosts = allTargetIPs.length;
      var scannedHosts = 0;

      // 优化批量扫描：根据IP数量动态调整批量大小
      final batchSize = (allTargetIPs.length / 10).clamp(20, 50).round();
      _addDebugMessage('使用批量大小: $batchSize');

      for (int i = 0; i < allTargetIPs.length; i += batchSize) {
        final batch = allTargetIPs.skip(i).take(batchSize).toList();

        setState(() {
          _currentScanIP = '${batch.first} - ${batch.last}';
        });

        final results = await _scanManager.scanBatch(batch, networkBases.first);

        setState(() {
          _discoveredDevices.addAll(results);
          scannedHosts += batch.length;
          _scanProgress = scannedHosts / totalHosts;
        });

        // 为每个发现的设备添加调试信息
        for (final result in results) {
          _addDebugMessage(
            '✓ 发现设备 ${result.ip} (${result.detectionMethodName})',
          );
        }

        // 添加批量完成信息
        _addDebugMessage(
          '批量扫描完成: ${i + batch.length}/${allTargetIPs.length} (${((i + batch.length) / allTargetIPs.length * 100).toStringAsFixed(1)}%)',
        );
      }

      _addDebugMessage(
        '扫描完成，发现 ${_discoveredDevices.where((d) => d.isActive).length} 个活跃设备',
      );

      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          content: Text(
            '扫描完成！发现 ${_discoveredDevices.where((d) => d.isActive).length} 个活跃设备',
          ),
        ),
      );
    } catch (e) {
      _addDebugMessage('扫描过程中出错: $e');
      ScaffoldMessenger.of(
        context,
      ).showSnackBar(SnackBar(content: Text('扫描失败: $e')));
    } finally {
      setState(() {
        _isScanning = false;
        _scanProgress = 1.0;
        _currentScanIP = '';
      });
    }
  }

  void _showScannerSelection() {
    showDialog(
      context: context,
      builder: (context) => ScannerSelectionDialog(
        scanManager: _scanManager,
        onConfigChanged: (config) {
          // 应用新的扫描器配置
          _scanManager.setScannerConfig(config);

          // 统计启用的扫描器数量
          final enabledCount = config.values.where((enabled) => enabled).length;
          final totalCount = config.length;

          _addDebugMessage('扫描器配置已更新: $enabledCount/$totalCount 个扫描器已启用');

          // 显示配置详情
          final enabledScanners = <String>[];
          config.forEach((scanType, enabled) {
            if (enabled) {
              final scanner = _scanManager.availableScanners.firstWhere(
                (s) => s.scanType == scanType,
              );
              enabledScanners.add(scanner.name);
            }
          });

          if (enabledScanners.isNotEmpty) {
            _addDebugMessage('已启用的扫描器: ${enabledScanners.join(', ')}');
          }

          // 显示用户友好的提示
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Text('扫描器配置已更新，启用了 $enabledCount 个扫描器'),
              duration: const Duration(seconds: 2),
            ),
          );
        },
      ),
    );
  }
}
