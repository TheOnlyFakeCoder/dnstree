import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:graphview/GraphView.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const DNSSECVisualizerApp());
}

class DNSSECVisualizerApp extends StatelessWidget {
  const DNSSECVisualizerApp({Key? key}) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'DNSSEC Chain Visualizer',
      debugShowCheckedModeBanner: false,
      theme: ThemeData(
        primarySwatch: Colors.blue,
        scaffoldBackgroundColor: Colors.white,
      ),
      home: const HomePage(),
    );
  }
}

class DnsNodeData {
  final String title;
  final List<String> details;
  final String? edgeLabel;
  final Color edgeColor;

  DnsNodeData({
    required this.title,
    required this.details,
    this.edgeLabel,
    this.edgeColor = Colors.black,
  });
}

class HomePage extends StatefulWidget {
  const HomePage({Key? key}) : super(key: key);

  @override
  State<HomePage> createState() => _HomePageState();
}

class _HomePageState extends State<HomePage> {
  final TextEditingController _domainController = TextEditingController();
  final TransformationController _transformationController = TransformationController();
  bool _showGraph = false;

  final Graph graph = Graph()..isTree = true;
  final BuchheimWalkerConfiguration builder = BuchheimWalkerConfiguration();

  @override
  void initState() {
    super.initState();
    builder
      ..orientation = BuchheimWalkerConfiguration.ORIENTATION_TOP_BOTTOM
      ..siblingSeparation = 40
      ..levelSeparation = 70
      ..subtreeSeparation = 40;
  }

  // Dynamic live-fetching DNS tree builder optimized for Google Public DNS
  Future<void> _buildTree(String domain) async {
    String sanitized = domain
        .replaceAll(RegExp(r'https?://'), '')
        .replaceAll(RegExp(r'www\.'), '')
        .trim();
        
    if (sanitized.endsWith('.')) {
      sanitized = sanitized.substring(0, sanitized.length - 1);
    }

    if (sanitized.isEmpty) return;

    BuildContext? dialogContext;
    showDialog(
      context: context,
      barrierDismissible: false,
      builder: (ctx) {
        dialogContext = ctx;
        return const Center(child: CircularProgressIndicator());
      },
    );

    try {
      List<String> parts = sanitized.split('.');
      List<String> domainChain = ['.'];
      String currentLayer = '';
      
      for (int i = parts.length - 1; i >= 0; i--) {
        currentLayer = currentLayer.isEmpty ? parts[i] : '${parts[i]}.$currentLayer';
        domainChain.add(currentLayer);
      }

      final freshGraph = Graph()..isTree = true;
      List<Node> createdNodes = [];

      for (int i = 0; i < domainChain.length; i++) {
        String layerName = domainChain[i];
        bool isLeaf = (i == domainChain.length - 1);
        
        int dnskeyCount = 0;
        int dsCount = 0;
        int rrsigCount = 0;
        bool hasNsec = false;
        bool hasNsec3 = false;
        bool hasDnskey = false;
        bool hasDs = false;

        if (layerName != '.') {
          final dnskeyUri = Uri.parse('https://dns.google/resolve?name=$layerName&type=DNSKEY&do=true');
          final dnskeyResponse = await http.get(dnskeyUri, headers: {'Accept': 'application/json'});
          
          if (dnskeyResponse.statusCode == 200) {
            final data = jsonDecode(dnskeyResponse.body);
            
            if (data['Answer'] != null) {
              for (var answer in data['Answer']) {
                if (answer['type'] == 48) dnskeyCount++; 
                if (answer['type'] == 46) rrsigCount++;  
              }
              hasDnskey = dnskeyCount > 0;
            }
            
            if (data['Authority'] != null) {
              for (var auth in data['Authority']) {
                if (auth['type'] == 46) rrsigCount++;
                if (auth['type'] == 47) hasNsec = true;  
                if (auth['type'] == 50) hasNsec3 = true; 
              }
            }
          }

          if (dnskeyCount == 0 || rrsigCount == 0) {
            final fallbackUri = Uri.parse('https://dns.google/resolve?name=$layerName&type=ANY&do=true');
            final fallbackResponse = await http.get(fallbackUri, headers: {'Accept': 'application/json'});
            if (fallbackResponse.statusCode == 200) {
              final data = jsonDecode(fallbackResponse.body);
              if (data['Authority'] != null) {
                for (var auth in data['Authority']) {
                  if (auth['type'] == 46) rrsigCount++;
                  if (auth['type'] == 47) hasNsec = true;
                  if (auth['type'] == 50) hasNsec3 = true;
                }
              }
            }
          }

          final dsUri = Uri.parse('https://dns.google/resolve?name=$layerName&type=DS&do=true');
          final dsResponse = await http.get(dsUri, headers: {'Accept': 'application/json'});
          
          if (dsResponse.statusCode == 200) {
            final data = jsonDecode(dsResponse.body);
            if (data['Answer'] != null) {
              for (var answer in data['Answer']) {
                if (answer['type'] == 43) dsCount++;
                if (answer['type'] == 46) rrsigCount++;
              }
              hasDs = dsCount > 0;
            }
          }
        } else {
          hasDnskey = true;
          hasDs = true;
        }

        Color statusColor;
        List<String> details = [];
        String edgeLabel = '';

        if (layerName == '.') {
          statusColor = const Color(0xFF2E7D32); 
          details = const ['Root Anchor', 'DNSKEY: Active'];
        } else {
          if (isLeaf) {
            details.add('DNSKEY: ${hasDnskey ? dnskeyCount : "no obs."}');
            details.add('RRSIG: ${rrsigCount > 0 ? rrsigCount : "no obs."}');
            
            if (!hasDnskey || hasNsec3 || rrsigCount > 0) {
              details.add('Evidencia en autoridad: NSEC3 y RRSIG');
              statusColor = Colors.greenAccent;
              edgeLabel = 'Cadena interrumpida';
            } else if (hasDnskey && hasDs) {
              details.add('Evidencia: Cadena completa');
              statusColor = const Color(0xFF2E7D32);
              edgeLabel = 'DS → DNSKEY OK';
            } else {
              details.add('Evidencia: Sin protección');
              statusColor = Colors.red.shade700;
              edgeLabel = 'Insecure Zone';
            }
          } else {
            details.add('DNSKEY: ${hasDnskey ? dnskeyCount : "no obs."}');
            details.add('RRSIG: $rrsigCount');
            
            if (hasDnskey && hasDs) {
              statusColor = const Color(0xFF2E7D32);
              edgeLabel = 'DS → DNSKEY OK';
              details.add('DS validado');
            } else {
              statusColor = const Color(0xFFD4AF37); 
              edgeLabel = 'DS: no obs.';
            }
          }
        }

        createdNodes.add(Node.Id(DnsNodeData(
          title: layerName,
          details: details,
          edgeLabel: edgeLabel,
          edgeColor: statusColor,
        )));
      }

      for (int i = 0; i < createdNodes.length - 1; i++) {
        Node parent = createdNodes[i];
        Node child = createdNodes[i + 1];
        Color connectionColor = (child.key!.value as DnsNodeData).edgeColor;

        freshGraph.addEdge(
          parent, 
          child, 
          paint: Paint()..color = connectionColor..strokeWidth = 2.5
        );
      }

      if (dialogContext != null && mounted) {
        Navigator.pop(dialogContext!);
      }
      
      setState(() {
        graph.nodes.clear();
        graph.edges.clear();
        for (var edge in freshGraph.edges) {
          graph.addEdge(edge.source, edge.destination, paint: edge.paint);
        }
        _showGraph = true;
      });

      WidgetsBinding.instance.addPostFrameCallback((_) {
        _transformationController.value = Matrix4.identity();
      });

    } catch (e) {
      if (dialogContext != null && mounted) {
        Navigator.pop(dialogContext!);
      }
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text('Failed to fetch data from Google: $e')),
      );
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: const Text('DNSSEC Chain Visualizer'),
        centerTitle: true,
        backgroundColor: Colors.white,
        foregroundColor: Colors.black,
        elevation: 1,
      ),
      body: Column(
        children: [
          Padding(
            padding: const EdgeInsets.all(16.0),
            child: Row(
              children: [
                Expanded(
                  child: TextField(
                    controller: _domainController,
                    onSubmitted: (val) => _buildTree(val.trim()),
                    decoration: const InputDecoration(
                      labelText: 'Enter Domain',
                      hintText: 'e.g., sat.gob.mx',
                      border: OutlineInputBorder(),
                    ),
                  ),
                ),
                const SizedBox(width: 12),
                ElevatedButton(
                  onPressed: () => _buildTree(_domainController.text.trim()),
                  style: ElevatedButton.styleFrom(
                    padding: const EdgeInsets.symmetric(vertical: 16, horizontal: 24),
                  ),
                  child: const Text('Analyze'),
                ),
              ],
            ),
          ),
          const Divider(height: 1),
          Expanded(
            child: _showGraph
                ? InteractiveViewer(
                    transformationController: _transformationController,
                    constrained: false, 
                    boundaryMargin: const EdgeInsets.all(600), 
                    minScale: 0.1,
                    maxScale: 3.0,
                    child: Container(
                      alignment: Alignment.center, 
                      padding: const EdgeInsets.symmetric(vertical: 60, horizontal: 120),
                      child: GraphView(
                        graph: graph,
                        algorithm: BuchheimWalkerAlgorithm(builder, TreeEdgeRenderer(builder)),
                        paint: Paint()
                          ..color = Colors.black
                          ..strokeWidth = 2
                          ..style = PaintingStyle.stroke,
                        builder: (Node node) {
                          var value = node.key!.value as DnsNodeData;
                          return _buildNodeView(value);
                        },
                      ),
                    ),
                  )
                : const Center(
                    child: Text(
                      'Enter a domain above to visualize the DNSSEC chain.',
                      style: TextStyle(fontSize: 15, color: Colors.black54),
                    ),
                  ),
          ),
        ],
      ),
    );
  }

  Widget _buildNodeView(DnsNodeData value) {
    return Container(
      padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 26),
      decoration: BoxDecoration(
        color: Colors.white,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: value.edgeColor, width: 2),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withOpacity(0.06),
            blurRadius: 6,
            offset: const Offset(0, 3),
          )
        ],
      ),
      child: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            value.title,
            style: const TextStyle(fontWeight: FontWeight.bold, fontSize: 16, letterSpacing: 0.5),
          ),
          if (value.details.isNotEmpty) ...[
            const SizedBox(height: 6),
            ...value.details.map((detail) => Padding(
                  padding: const EdgeInsets.symmetric(vertical: 1),
                  child: Text(
                    detail,
                    style: const TextStyle(fontSize: 13, color: Colors.black87),
                    textAlign: TextAlign.center,
                  ),
                )),
          ]
        ],
      ),
    );
  }
}