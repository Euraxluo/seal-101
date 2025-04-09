# 使用Rust官方镜像作为构建环境
FROM rust:1.81-bullseye AS builder

ARG PROFILE=release

WORKDIR /app

# 复制项目文件
COPY . .

# 构建key-server
RUN cargo build --bin key-server --profile $PROFILE --config net.git-fetch-with-cli=true

# 使用精简版Debian作为运行环境
FROM debian:bullseye-slim AS runtime

ARG master_key
ARG key_server_object_id
ARG network

EXPOSE 2024

RUN apt-get update && apt-get install -y cmake clang libpq5 ca-certificates libpq-dev postgresql

# 从构建阶段复制编译好的可执行文件
COPY --from=builder /app/target/release/key-server /opt/key-server/bin/

# 设置环境变量
ENV MASTER_KEY=$master_key
ENV KEY_SERVER_OBJECT_ID=$key_server_object_id
ENV NETWORK=$network

# 设置入口点
ENTRYPOINT ["/opt/key-server/bin/key-server"]
