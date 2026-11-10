# System Mamager

一个只使用 Python 标准库和 Linux 系统自带命令的 root 终端系统管理器。

## 启动

```bash
./system_mamager
```

启动器会自动调用 `sudo` 并提示输入当前用户密码。也可以显式执行：

```bash
sudo /home/tony/.applications/system_mamager/system_mamager
```

## 功能

- 系统总览：主机、内核、负载、CPU、内存、Swap、磁盘、温度、进程和服务状态
- 进程管理：全部、运行中、守护进程、僵尸、睡眠进程；支持搜索、详情和信号操作
- 网络状态：接口、当前套接字、路由、DNS、防火墙、代理、安全概览
- 服务管理：systemd 服务列表、详情、日志、启动/停止/重启/启用/禁用
- 系统信息：CPU、内存、内核启动参数、登录用户、虚拟化与 DMI
- 磁盘与硬件：文件系统、块设备、温度/风扇、PCI/GPU
- 日志与告警：本次启动的 warning 及以上 journal 日志

## 按键

- `↑` / `↓`：移动或滚动
- `←` / `→`：切换进程/网络分类
- `Enter`：进入功能或查看详情
- `Esc` / `q`：返回上一级；在总览退出
- `r`：刷新
- `/`：过滤进程或服务
- 进程列表按 `k`：直接对光标所在进程发送 SIGKILL，操作前会确认
- `?`：帮助

危险操作（发送进程信号、启停服务）都会要求确认。

网络页会读取 UFW、firewalld、nftables、iptables、GNOME/KDE 代理设置、进程代理变量、对外监听端口、VPN 接口和默认路由。某些项目在系统未安装对应工具时会显示“未检测到”。

## 自检

```bash
sudo /home/tony/.applications/system_mamager/system_mamager --self-test
```

## 说明

不依赖第三方 Python 包。风扇转速只有在主板/EC 通过 hwmon 暴露时才可读取。
