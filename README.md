# add_qufirewall_rules
Add the IP allow list to the QNAP firewall. Particularly suitable for Edge one.

在用Edge one给家里的威联通做公网域名访问时会遇到edgeone世界各地的节点无法访问威联通的情况，实际是因为威联通的防火墙，对世界各地的edge one加速节点因为地理位置而Ban了，要解决这个问题，就要在威联通的防火墙列表里对edgeone的回源ip网段允许访问，但是因为威联通无法批量添加ip地址列表（非常愚蠢），所以有了这个批量添加ip地址段的脚本。

使用方法：把威联通服务器导出的csv、py、txt放在同一个目录下，配置好ip列表txt后，运行py文件，拖入csv文件，按提示操作。
<img width="1734" height="927" alt="image" src="https://github.com/user-attachments/assets/1b27a407-80d8-4fa3-84a7-59fb30f0e663" />

我这个小白写不来这个脚本，所以本脚本完全由cursor写，如有问题请提issue！

*当前防火墙的威联通自带规则会加在中间，但是最主要的规则允许地区和拒绝所有已经处于最下方，请大家一起来优化这个脚本！
