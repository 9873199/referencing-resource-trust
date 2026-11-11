独立验收说明

冻结提交：https://github.com/9873199/referencing-resource-trust/commit/9a3a252a656e60e0f93cbaddcfd2265ad37f4213
实际解释器：3.14.3 (tags/v3.14.3:323c59a, Feb  3 2026, 16:04:56) [MSC v.1944 64 bit (AMD64)]

使用同一冻结提交和environment-reviewed.json中的真实解释器及依赖。回归需declared-suite-dependency.json所列官方suite固定版本，并设置REFERENCING_SUITE指向解压目录；此依赖不是模型源码。执行regression-r1、acceptance-r1与dynamic-r1中的真实命令，support中的schema_adapter.py只映射公开API，不补安全逻辑。回归有效数字取test-results-corrected.json和原始stdout：JUnit子测试父行的skipped不能替代终端统计。normalization-r1/reproduce-schema-alias.py打印同一冻结实现对别名和规范URI的不同选择，退出0表示复现脚本执行完，不表示安全要求通过。所有临时输出映射到自己的缓存；无需容器、外部Schema服务或账号。

每组目录内的 *-command.json 保留真实参数、工作目录、PYTHONPATH、退出码和原始日志位置；test-results.json 与 JUnit XML 保留完整成绩。跨机器运行时把这些绝对路径映射到同一冻结 checkout 和自己的缓存目录，所有 --basetemp、XML 和构建输出均放在缓存里。依赖版本见 environment-reviewed.json。
这些材料在模型单轮结束后生成，与原轨内测试分开，不代表项目方质检通过。原轨和视频只放各自的飞书附件。


冻结产物提交：https://github.com/9873199/referencing-resource-trust/commit/9a3a252a656e60e0f93cbaddcfd2265ad37f4213
这些独立验收文件在模型首轮结束后生成，不是模型原轨中的测试。
