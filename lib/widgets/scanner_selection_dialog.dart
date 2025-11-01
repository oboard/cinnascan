import 'package:flutter/material.dart';
import '../scanners/base_scanner.dart';
import '../scanners/scan_manager.dart';

/// 扫描器选择对话框
class ScannerSelectionDialog extends StatefulWidget {
  final ScanManager scanManager;
  final Function(Map<ScanResultType, bool>) onConfigChanged;

  const ScannerSelectionDialog({
    Key? key,
    required this.scanManager,
    required this.onConfigChanged,
  }) : super(key: key);

  @override
  State<ScannerSelectionDialog> createState() => _ScannerSelectionDialogState();
}

class _ScannerSelectionDialogState extends State<ScannerSelectionDialog> {
  late Map<ScanResultType, bool> _config;
  Map<ScanResultType, bool> _availability = {};

  @override
  void initState() {
    super.initState();
    _config = Map.from(widget.scanManager.scannerConfig);
    _checkAvailability();
  }

  Future<void> _checkAvailability() async {
    final availability = await widget.scanManager.checkScannersAvailability();
    if (mounted) {
      setState(() {
        _availability = availability;
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      title: const Text('选择扫描方式'),
      content: SizedBox(
        width: double.maxFinite,
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // 预设配置按钮
            Row(
              mainAxisAlignment: MainAxisAlignment.spaceEvenly,
              children: [
                _buildPresetButton(
                  '快速',
                  widget.scanManager.getQuickScanConfig(),
                ),
                _buildPresetButton(
                  '推荐',
                  widget.scanManager.getRecommendedConfig(),
                ),
                _buildPresetButton(
                  '完整',
                  widget.scanManager.getFullScanConfig(),
                ),
              ],
            ),
            const SizedBox(height: 16),

            // 当前配置状态
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: Theme.of(context).primaryColor.withOpacity(0.1),
                borderRadius: BorderRadius.circular(8),
              ),
              child: Row(
                children: [
                  Icon(
                    Icons.info_outline,
                    size: 16,
                    color: Theme.of(context).primaryColor,
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      '已启用 ${_config.values.where((enabled) => enabled).length} / ${_config.length} 个扫描器',
                      style: TextStyle(
                        fontSize: 12,
                        color: Theme.of(context).primaryColor,
                        fontWeight: FontWeight.w500,
                      ),
                    ),
                  ),
                ],
              ),
            ),

            const SizedBox(height: 16),
            const Divider(),
            const SizedBox(height: 8),

            // 扫描器列表
            Flexible(
              child: ListView.builder(
                shrinkWrap: true,
                itemCount: widget.scanManager.availableScanners.length,
                itemBuilder: (context, index) {
                  final scanner = widget.scanManager.availableScanners[index];
                  return _buildScannerTile(scanner);
                },
              ),
            ),
          ],
        ),
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.of(context).pop(),
          child: const Text('取消'),
        ),
        ElevatedButton(
          onPressed: () {
            // 检查是否至少启用了一个扫描器
            final enabledCount = _config.values
                .where((enabled) => enabled)
                .length;

            if (enabledCount == 0) {
              ScaffoldMessenger.of(context).showSnackBar(
                const SnackBar(
                  content: Text('请至少启用一个扫描器'),
                  backgroundColor: Colors.orange,
                ),
              );
              return;
            }

            widget.onConfigChanged(_config);
            Navigator.of(context).pop();
          },
          child: const Text('确定'),
        ),
      ],
    );
  }

  Widget _buildPresetButton(String label, Map<ScanResultType, bool> config) {
    return OutlinedButton(
      onPressed: () {
        setState(() {
          _config = Map.from(config);
        });
      },
      child: Text(label),
    );
  }

  Widget _buildScannerTile(BaseScanner scanner) {
    final isEnabled = _config[scanner.scanType] ?? false;
    final isAvailable = _availability[scanner.scanType] ?? true;

    return Card(
      margin: const EdgeInsets.symmetric(vertical: 4),
      child: ListTile(
        leading: _buildScannerIcon(scanner.scanType),
        title: Text(
          scanner.name,
          style: TextStyle(
            color: isAvailable ? null : Colors.grey,
            fontWeight: FontWeight.w500,
          ),
        ),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              scanner.description,
              style: TextStyle(
                color: isAvailable ? null : Colors.grey,
                fontSize: 12,
              ),
            ),
            const SizedBox(height: 4),
            Row(
              children: [
                _buildPriorityChip(scanner.priority),
                const SizedBox(width: 8),
                if (!isAvailable)
                  const Chip(
                    label: Text('不可用', style: TextStyle(fontSize: 10)),
                    backgroundColor: Colors.red,
                    labelStyle: TextStyle(color: Colors.white),
                  ),
              ],
            ),
          ],
        ),
        trailing: Switch(
          value: isEnabled && isAvailable,
          onChanged: isAvailable
              ? (value) {
                  setState(() {
                    _config[scanner.scanType] = value;
                  });
                }
              : null,
        ),
        isThreeLine: true,
      ),
    );
  }

  Widget _buildScannerIcon(ScanResultType scanType) {
    IconData iconData;
    Color color;

    switch (scanType) {
      case ScanResultType.icmpPing:
        iconData = Icons.network_ping;
        color = Colors.blue;
        break;
      case ScanResultType.tcpPort:
        iconData = Icons.router;
        color = Colors.green;
        break;
      case ScanResultType.arpTable:
        iconData = Icons.device_hub;
        color = Colors.orange;
        break;
      case ScanResultType.bonjour:
        iconData = Icons.apple;
        color = Colors.grey;
        break;
      case ScanResultType.upnp:
        iconData = Icons.cast;
        color = Colors.purple;
        break;
      case ScanResultType.dnsReverse:
        iconData = Icons.dns;
        color = Colors.teal;
        break;
      case ScanResultType.ipv6:
        iconData = Icons.language;
        color = Colors.indigo;
        break;
      case ScanResultType.mdns:
        iconData = Icons.apple;
        color = Colors.grey;
        break;
      case ScanResultType.ssdp:
        iconData = Icons.cast;
        color = Colors.purple;
        break;
    }

    return CircleAvatar(
      backgroundColor: color.withOpacity(0.1),
      child: Icon(iconData, color: color, size: 20),
    );
  }

  Widget _buildPriorityChip(int priority) {
    String label;
    Color color;

    if (priority >= 90) {
      label = '高优先级';
      color = Colors.red;
    } else if (priority >= 70) {
      label = '中优先级';
      color = Colors.orange;
    } else {
      label = '低优先级';
      color = Colors.grey;
    }

    return Chip(
      label: Text(label, style: const TextStyle(fontSize: 10)),
      backgroundColor: color.withOpacity(0.1),
      labelStyle: TextStyle(color: color),
    );
  }
}

/// 扫描器信息底部表单
class ScannerInfoBottomSheet extends StatelessWidget {
  final ScanManager scanManager;

  const ScannerInfoBottomSheet({Key? key, required this.scanManager})
    : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(16),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          const Text(
            '扫描器详细信息',
            style: TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
          ),
          const SizedBox(height: 16),
          Flexible(
            child: ListView.builder(
              shrinkWrap: true,
              itemCount: scanManager.availableScanners.length,
              itemBuilder: (context, index) {
                final scanner = scanManager.availableScanners[index];
                return _buildDetailCard(scanner);
              },
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDetailCard(BaseScanner scanner) {
    return Card(
      margin: const EdgeInsets.symmetric(vertical: 8),
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                _buildScannerIcon(scanner.scanType),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    scanner.name,
                    style: const TextStyle(
                      fontSize: 16,
                      fontWeight: FontWeight.bold,
                    ),
                  ),
                ),
                Text(
                  '优先级: ${scanner.priority}',
                  style: const TextStyle(fontSize: 12, color: Colors.grey),
                ),
              ],
            ),
            const SizedBox(height: 8),
            Text(scanner.description, style: const TextStyle(fontSize: 14)),
            const SizedBox(height: 8),
            _buildTechnicalDetails(scanner),
          ],
        ),
      ),
    );
  }

  Widget _buildScannerIcon(ScanResultType scanType) {
    // 复用上面的图标逻辑
    IconData iconData;
    Color color;

    switch (scanType) {
      case ScanResultType.icmpPing:
        iconData = Icons.network_ping;
        color = Colors.blue;
        break;
      case ScanResultType.tcpPort:
        iconData = Icons.router;
        color = Colors.green;
        break;
      case ScanResultType.arpTable:
        iconData = Icons.device_hub;
        color = Colors.orange;
        break;
      case ScanResultType.bonjour:
        iconData = Icons.apple;
        color = Colors.grey;
        break;
      case ScanResultType.upnp:
        iconData = Icons.cast;
        color = Colors.purple;
        break;
      case ScanResultType.dnsReverse:
        iconData = Icons.dns;
        color = Colors.teal;
        break;
      case ScanResultType.ipv6:
        iconData = Icons.language;
        color = Colors.indigo;
        break;
      case ScanResultType.mdns:
        iconData = Icons.apple;
        color = Colors.grey;
        break;
      case ScanResultType.ssdp:
        iconData = Icons.cast;
        color = Colors.purple;
        break;
    }

    return Icon(iconData, color: color, size: 24);
  }

  Widget _buildTechnicalDetails(BaseScanner scanner) {
    Map<String, String> details = {};

    switch (scanner.scanType) {
      case ScanResultType.icmpPing:
        details = {
          '协议': 'ICMP Echo Request/Reply',
          '端口': 'N/A',
          '检测内容': '设备在线状态、响应时间',
          '适用场景': '基础连通性检测',
        };
        break;
      case ScanResultType.tcpPort:
        details = {
          '协议': 'TCP',
          '端口': '22, 80, 443, 8080等常用端口',
          '检测内容': '开放服务、Web服务器信息',
          '适用场景': '服务发现、Web应用检测',
        };
        break;
      case ScanResultType.arpTable:
        details = {
          '协议': 'ARP (Address Resolution Protocol)',
          '端口': 'N/A',
          '检测内容': 'MAC地址、厂商信息',
          '适用场景': '设备硬件识别',
        };
        break;
      case ScanResultType.bonjour:
        details = {
          '协议': 'mDNS (Multicast DNS)',
          '端口': '5353 (UDP)',
          '检测内容': 'Apple设备、Bonjour服务',
          '适用场景': 'Apple生态设备发现',
        };
        break;
      case ScanResultType.upnp:
        details = {
          '协议': 'UPnP SSDP',
          '端口': '1900 (UDP)',
          '检测内容': 'UPnP设备、媒体服务器',
          '适用场景': '智能家居设备发现',
        };
        break;
      case ScanResultType.dnsReverse:
        details = {
          '协议': 'DNS PTR查询',
          '端口': '53 (UDP/TCP)',
          '检测内容': '主机名、域名信息',
          '适用场景': '设备名称识别',
        };
        break;
      case ScanResultType.ipv6:
        details = {
          '协议': 'IPv6 NDP, DNS AAAA',
          '端口': 'N/A',
          '检测内容': 'IPv6地址、IPv6服务',
          '适用场景': 'IPv6网络环境',
        };
        break;
      case ScanResultType.mdns:
        details = {
          '协议': 'mDNS (Multicast DNS)',
          '端口': '5353 (UDP)',
          '检测内容': 'mDNS服务、设备名称',
          '适用场景': '本地网络服务发现',
        };
        break;
      case ScanResultType.ssdp:
        details = {
          '协议': 'SSDP (Simple Service Discovery Protocol)',
          '端口': '1900 (UDP)',
          '检测内容': 'UPnP设备、DLNA服务',
          '适用场景': '媒体设备发现',
        };
        break;
    }

    return Column(
      children: details.entries
          .map(
            (entry) => Padding(
              padding: const EdgeInsets.symmetric(vertical: 2),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  SizedBox(
                    width: 80,
                    child: Text(
                      '${entry.key}:',
                      style: const TextStyle(
                        fontSize: 12,
                        fontWeight: FontWeight.w500,
                        color: Colors.grey,
                      ),
                    ),
                  ),
                  Expanded(
                    child: Text(
                      entry.value,
                      style: const TextStyle(fontSize: 12),
                    ),
                  ),
                ],
              ),
            ),
          )
          .toList(),
    );
  }
}
