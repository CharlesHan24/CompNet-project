目录结构:

- clients/src/: clients & server

- switch/scripts/log_generator.py, routing_controller.py: 控制面逻辑

- switch/p4src_simple: 我们的p4代码, 其中p4app.json配置topology


## 1.6
- switch/scripts/packet_monitor.py: 控制面异常报文的处理, 目前为print logs

- switch/p4src_simple: 增加 stateful registers 去检测 malicious packets: 五元组(fingerprint)相同, 没有timeout, 并且pid不同
