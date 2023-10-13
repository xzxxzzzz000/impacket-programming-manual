impacket编程手册
author:鲁平

个人公众号：Security丨Art，欢迎大佬前来批评指教

impacket包是一个常用的“域渗透工具包”,在他的example文件夹下有很多利用该工具包对域控进行操作的脚本，基本满足域渗透需求 也是因为这个原因导致网上的文章全是介绍他的示例文件的使用的文章，而基本没有介绍如何利用他对域渗透遇到的场景进行脚本开发的文章，然而正相反的是，在后续的很多域漏洞的利用脚本中都直接使用了impacket模块进行开发，如sam-the-admin、CVE-2022-33679等 ，所以在这里补充一下，方便日后出现漏洞时及时利用impacket改自己的poc
![2](https://github.com/xzxxzzzz000/impacket-programming-manual/assets/24671887/2c9fd1fb-98f8-46c3-ad70-8d083e0a082b)

