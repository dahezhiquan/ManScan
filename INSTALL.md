# ManScan 安装流程（本地化部署方式）

## 环境准备

### Go语言交叉编译环境准备

#### 本地打包机器环境准备

MacOS先安装 FiloSottile/musl-cross/musl-cross:

`brew install FiloSottile/musl-cross/musl-cross`

如果要部署到 linux amd64 系统， cd 到 `server/cmd/server` 下，执行：

`CGO_ENABLED=1 GOOS=linux GOARCH=amd64 CC=x86_64-linux-musl-gcc CXX=x86_64-linux-musl-g++ go build -trimpath -o manscan`

如果要部署到 MacOS arm64 系统， cd 到 `server/cmd/server` 下，执行：

`CGO_ENABLED=1 GOOS=darwin GOARCH=arm64 CC=clang CXX=clang++ go build -trimpath -o manscan`

#### 部署机器环境准备

1、根据机器类型执行下面的命令，安装交叉编译环境

CentOS:
- mkdir -p /etc/yum.repos.d/
- wget https://copr.fedorainfracloud.org/coprs/ngompa/musl-libc/repo/epel-7/ngompa-musl-libc-epel-7.repo -O /etc/yum.repos.d/ngompa-musl-libc-epel-7.repo
- yum install -y musl-libc-static

Ubuntu:
- apt update
- apt install musl-tools

2、安装 nginx，用于部署前端项目

```bash
cat > /etc/yum.repos.d/nginx.repo <<'EOF'
[nginx-stable]
name=nginx stable repo
baseurl=http://nginx.org/packages/centos/7/$basearch/
    gpgcheck=0
    enabled=1
    EOF
    
yum install -y nginx
```


### 模版部署

将模版仓库上传位置 ： /root/manscan-templates 目录

### manscan-fe 前端部署

1、构建前端静态文件

```bash
npm ci
npm run build
```

2、上传构建好的 dist 目录到 /work/manscan-fe


3、配置 Nginx

新建 `/etc/nginx/conf.d/manscan-fe.conf`

```text
server {
    listen 6080;
    server_name manscan-fe;

    root /work/manscan-fe;
    index index.html;

    # 前端静态资源
    location / {
        try_files $uri $uri/ /index.html;
    }

    # 后端接口代理
    location /api/ {
        proxy_pass http://127.0.0.1:8686;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```
4、重载 nginx

```bash
nginx -t
systemctl enable --now nginx
systemctl reload nginx
```

### 新建 ManScan 服务

1、创建 /work/manscan 目录，将打包好的二进制文件传到目录中 /work/manscan/manscan

2、将配置文件 config.yaml 和 prompt.yaml 上传到 /work/manscan 目录

3、将 data 目录打包进 /work/manscan 目录

4、新建 manscan 日志目录

`mkdir -p /var/log/manscan`

4、系统服务创建

`vi /etc/systemd/system/manscan.service`

```
[Unit]
Description=Manscan Service

[Service]
User=root
WorkingDirectory=/work/manscan
ExecStart=/bin/bash -c 'exec /work/manscan/manscan >> /var/log/manscan/manscan.log 2>&1'
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

5、配置日志分片

创建 `/etc/logrotate.d/manscan`，写入：

```text
/var/log/manscan/manscan.log {
    daily
    maxsize 100M
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```


6、服务启动

`systemctl start manscan`