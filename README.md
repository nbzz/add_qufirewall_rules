# add_qufirewall_rules
Add the IP allow list to the QNAP firewall. Particularly suitable for Edge one.
在用Edge one给家里的威联通做公网域名访问时会遇到edgeone世界各地的节点无法访问威联通的情况，实际是因为威联通的防火墙，对世界各地的edge one加速节点因为地理位置而Ban了，要解决这个问题，就要在威联通的防火墙列表里对edgeone的回源ip网段允许访问，但是因为威联通无法批量添加ip地址列表（非常愚蠢），所以有了这个批量添加ip地址段的脚本。

我这个小白写不来这个脚本，所以本脚本完全由cursor写，如有问题请提issue！
