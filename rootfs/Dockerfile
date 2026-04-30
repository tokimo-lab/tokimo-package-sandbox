# syntax=docker/dockerfile:1
# TokimoOS rootfs — minimal Debian 13 sandbox filesystem
#
# Build:
#   docker build -f rootfs/Dockerfile -o type=local,dest=rootfs-amd64 .
#
# Multi-arch:
#   docker build -f rootfs/Dockerfile -o type=local,dest=rootfs-arm64 --platform linux/arm64 .
#
# Layer strategy (ordered by change frequency, least frequent first):
#   1. ca-certificates + mirrors    (almost never changes)
#   2. apt heavy packages           (rarely changes)
#   3. python + node global pkgs    (changes occasionally)
#   4. user + config files          (changes sometimes)
#   5. cleanup / slim               (changes most often)

FROM debian:13 AS builder

# BuildKit auto-sets TARGETARCH (amd64 / arm64)
ARG TARGETARCH

# ── Layer 1: HTTPS base + mirror configuration ──────────────────────────
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    ca-certificates curl

RUN rm -f /etc/apt/sources.list.d/debian.sources && \
    printf '%s\n' \
    'deb https://mirrors.tuna.tsinghua.edu.cn/debian/ trixie main contrib non-free non-free-firmware' \
    'deb https://mirrors.tuna.tsinghua.edu.cn/debian/ trixie-updates main contrib non-free non-free-firmware' \
    'deb https://mirrors.tuna.tsinghua.edu.cn/debian-security trixie-security main contrib non-free non-free-firmware' \
    > /etc/apt/sources.list

# ── Layer 2: Heavy apt packages ─────────────────────────────────────────
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update -qq && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    gnupg vim nano less procps \
    wget git jq unzip zip bzip2 xz-utils zstd \
    iputils-ping rsync \
    dnsutils ffmpeg \
    python3 python3-pip python3-venv \
    bash-completion \
    pandoc poppler-utils qpdf tesseract-ocr \
    libreoffice-writer libreoffice-impress libreoffice-calc \
    lua5.4 \
    && \
    curl -fsSL https://deb.nodesource.com/setup_24.x | bash - && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y nodejs && \
    corepack enable

# ── Layer 3: pip + npm global packages ──────────────────────────────────

RUN npm config set --global registry https://registry.npmmirror.com

RUN cat > /etc/pip.conf << 'EOF' && \
    npm install -g pnpm docx pptxgenjs
[global]
index-url = https://pypi.tuna.tsinghua.edu.cn/simple
trusted-host = pypi.tuna.tsinghua.edu.cn
EOF

RUN mkdir -p /home/tokimo/python_packages && \
    pip3 install --break-system-packages --target=/home/tokimo/python_packages \
    requests ipython rich \
    pypdf pdfplumber reportlab pytesseract pdf2image \
    pandas openpyxl "markitdown[pptx]" Pillow

# ── Layer 4: User + system config ───────────────────────────────────────

RUN groupadd -g 1000 tokimo && \
    useradd -m -u 1000 -g 1000 -s /bin/bash -d /home/tokimo tokimo && \
    ln -sf ../../bin/python3 /usr/local/bin/python && \
    ln -sf ../../bin/lua5.4 /usr/local/bin/lua && \
    echo "TokimoOS" > /etc/hostname

RUN cat > /etc/os-release << 'EOF'
PRETTY_NAME="TokimoOS 1.0"
NAME="TokimoOS"
ID=tokimoos
ID_LIKE=debian
VERSION_ID="1.0"
HOME_URL="https://tokimo.io"
EOF

RUN cat > /etc/profile.d/tokimo_env.sh << 'EOF'
export HOME=/home/tokimo
export USER=tokimo
export LOGNAME=tokimo
export NPM_CONFIG_PREFIX=/home/tokimo
export NODE_PATH=/home/tokimo/lib/node_modules
export PATH=/home/tokimo/bin:/usr/local/bin:/usr/bin:/bin
export PYTHONPATH=/home/tokimo/python_packages${PYTHONPATH:+:$PYTHONPATH}
export PIP_TARGET=/home/tokimo/python_packages
export npm_config_registry=https://registry.npmmirror.com
EOF
RUN chmod +x /etc/profile.d/tokimo_env.sh

RUN cat > /etc/bash.bashrc << 'EOF'
for f in /etc/profile.d/*.sh; do [ -r "$f" ] && . "$f"; done
unset f
[ -f ~/.bashrc ] && . ~/.bashrc
EOF

RUN cat > /home/tokimo/.bashrc << 'EOF'
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTCONTROL=ignoredups:erasedups
shopt -s histappend

PS1='[\[\033[35;1m\]\u\[\033[0m\]@\[\033[31;1m\]TokimoOS\[\033[0m\]:\[\033[32;1m\]$PWD\[\033[0m\]]\$ '

alias ls='ls --color=auto'
alias ll='ls -lah --color=auto'
alias la='ls -A --color=auto'
alias grep='grep --color=auto'

if [ -f /usr/share/bash-completion/bash_completion ]; then
    . /usr/share/bash-completion/bash_completion 2>/dev/null || true
fi
EOF

RUN cat > /home/tokimo/.bash_profile << 'EOF'
[ -f ~/.bashrc ] && . ~/.bashrc
EOF

RUN cat > /home/tokimo/.inputrc << 'EOF'
set completion-ignore-case on
set show-all-if-ambiguous on
set show-all-if-unmodified on
set colored-stats on
set mark-symlinked-directories on
set visible-stats on
EOF

# ldconfig for non-standard lib paths
RUN case "${TARGETARCH}" in \
      amd64) MULTIARCH="x86_64-linux-gnu" ;; \
      arm64) MULTIARCH="aarch64-linux-gnu" ;; \
      *) echo "unsupported arch"; exit 1 ;; \
    esac && \
    echo "/usr/lib/${MULTIARCH}/pulseaudio" > /etc/ld.so.conf.d/pulseaudio.conf && \
    echo "/usr/lib/libreoffice/program" > /etc/ld.so.conf.d/libreoffice.conf && \
    ldconfig

# ── Layer 5: Slim down ──────────────────────────────────────────────────

# Node.js C++ headers (only needed for native addon compilation)
RUN rm -rf /usr/include/node

# Perl data (perl-base is Essential, keep the binary)
RUN rm -rf /usr/share/perl /usr/share/perl5 /etc/perl

# Scalar
RUN rm -rf /usr/bin/scalar /usr/share/man/man1/scalar* 2>/dev/null || true

# GPG aux (keep gpg itself)
RUN apt-get remove -y dirmngr gpgsm 2>/dev/null || true

# Vim docs/tutor, keep only useful syntax files
RUN rm -rf /usr/share/vim/vim*/doc /usr/share/vim/vim*/tutor && \
    find /usr/share/vim/vim*/syntax -type f \
    ! -name 'markdown.vim' ! -name 'text.vim' ! -name 'help.vim' ! -name 'vim.vim' \
    ! -name 'viminfo.vim' ! -name 'sh.vim' ! -name 'bash.vim' ! -name 'python.vim' \
    ! -name 'json.vim' ! -name 'yaml.vim' ! -name 'xml.vim' ! -name 'html.vim' \
    ! -name 'css.vim' ! -name 'javascript.vim' ! -name 'conf.vim' \
    ! -name 'gitcommit.vim' ! -name 'gitconfig.vim' ! -name 'diff.vim' \
    ! -name 'csv.vim' ! -name 'toml.vim' ! -name 'sql.vim' ! -name 'log.vim' \
    ! -name 'dosini.vim' ! -name 'cmake.vim' ! -name 'make.vim' \
    ! -name 'lua.vim' \
    -delete 2>/dev/null || true

# systemd / init / udev (no init system in bwrap)
RUN rm -rf /usr/lib/systemd /usr/lib/init /etc/systemd /etc/init.d \
    /var/lib/systemd /usr/lib/tmpfiles.d /usr/lib/sysctl.d \
    /usr/lib/udev /etc/udev 2>/dev/null || true

# Desktop stuff
RUN rm -rf /usr/share/icons /usr/share/pixmaps /usr/share/applications \
    /usr/share/menu /usr/share/polkit-1

# Other shells (keep bash only)
RUN rm -rf /usr/share/fish /usr/share/zsh

# Misc share
RUN rm -rf /usr/share/keyrings /usr/share/gcc /usr/share/libgcrypt20 \
    /usr/share/cmake /usr/share/pkgconfig /usr/share/binfmts \
    /usr/share/libc-bin /usr/share/readline /usr/share/misc \
    /usr/share/bug /usr/share/doc-base /usr/share/debconf \
    /usr/share/debianutils /usr/share/base-files /usr/share/base-passwd \
    /usr/share/gdb /usr/share/gitweb /usr/share/tabset \
    /usr/share/python-wheels

# PAM (single-user, no login)
RUN rm -rf /etc/pam.d /etc/pam.conf /etc/security /usr/share/pam* /var/lib/pam

# etc misc
RUN rm -rf /etc/cron* /etc/logrotate.d /etc/logcheck /etc/default /etc/skel

# usr/lib misc
RUN rm -rf /usr/lib/lsb /usr/lib/valgrind /usr/lib/mime

# /usr/sbin: keep only what the sandbox needs
RUN find /usr/sbin -type f \
    ! -name 'ldconfig' ! -name 'update-ca-certificates' \
    ! -name 'zic' ! -name 'sysctl' ! -name 'iconvconfig' \
    -delete 2>/dev/null || true

# terminfo: xterm only
RUN find /usr/share/terminfo -type f ! -path '*/xterm*' -delete 2>/dev/null || true && \
    find /usr/share/terminfo -type d -empty -delete 2>/dev/null || true

# zoneinfo: Asia + UTC + PRC only
RUN find /usr/share/zoneinfo -type f \
    ! -path '*/Asia/*' ! -name 'UTC' ! -name 'PRC' ! -name 'posixrules' \
    -delete 2>/dev/null || true && \
    find /usr/share/zoneinfo -type d -empty -delete 2>/dev/null || true

# Bulk share removal
RUN rm -rf /usr/share/man /usr/share/doc /usr/share/locale \
    /usr/share/info /usr/share/lintian /usr/share/common-licenses

# Apt cache + temp cleanup
RUN apt-get clean && \
    rm -rf /var/lib/apt/lists/* /var/cache/apt /var/log/apt /var/log/*.log \
    /root/.npm /root/.cache /home/tokimo/.cache /tmp/* /var/tmp/*

# Python cache
RUN find / -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true && \
    find / -name '*.pyc' -delete 2>/dev/null || true

# Fix ownership
RUN chown -R tokimo:tokimo /home/tokimo

# ── Export: flattened rootfs ────────────────────────────────────────────
FROM scratch
COPY --from=builder / /
