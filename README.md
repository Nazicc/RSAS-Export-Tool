### 工具介绍
绿盟远程安全评估系统漏洞数据导出工具，只支持6.0的RSAS。

这个工具也是我写的第一个工具，没留有太多的结构空间，所以这一坨代码已经到极限了，没法修改了。

工具涉及：读取目录下的文件、ZIP文件读取、正则表达式、Excel表格写入、文件读写、TKinter、PyQt5

GitHub：
https://github.com/webingio/RSAS-Export-Tool

这是测试的原始报告：
http://p68yfqejc.bkt.clouddn.com/192.168.1.2.zip

源代码可以到我的博客笔记看，有点长，就不贴了：
https://webing.io/article/tool-rsas-tool.html

### 功能
- [x] 支持导出的数据：IP地址、漏洞名称、风险等级、整改建议、漏洞描述、漏洞CVE编号、漏洞对应端口、漏洞对应协议、漏洞对应服务等。
- [x] 导出不同端口的同一个漏洞，也就是一个端口对应一个漏洞，保证导出漏洞的完整性。
- [x] 导出端口和导出网站为单独的功能，导出网站的功能是采用正则去匹配http、www这两个服务。

### 须知
- [x] 当一个漏洞存在两个或者两个以上CVE编号，则只取第一个CVE漏洞编号。
- [x] 当一个漏洞不存在CVE编号时，则替换为 漏洞暂无CVE编号 。
- [x] 当一个漏洞整改建议为空时（个别低危漏洞），导出留空。
- [x] 使用之前请务必看使用说明。

### 工具下载
### PyQt界面：
下载链接：
http://p4nyd2zat.bkt.clouddn.com/RSAS漏洞数据导出工具1.5.zip

如图：
![](http://p4nyd2zat.bkt.clouddn.com/pyqt_rsas_15.png)

### Tkinter界面
下载链接：
已经不开放下载了，界面太丑懒得上传。

如图：
![](http://p4nyd2zat.bkt.clouddn.com/tkinter_rsas_15.png)
