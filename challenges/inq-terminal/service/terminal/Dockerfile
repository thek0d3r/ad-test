# Multi-stage: compile the C service, then ship a slim runtime with only the
# shared library it needs. glibc version is irrelevant to the exploits (the
# service uses an offset-based allocator, not libc internals), but pinning the
# base image keeps builds reproducible.
FROM debian:bookworm AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libc6-dev libseccomp-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /build
COPY terminal.c .
# Full RELRO + PIE + stack protector + FORTIFY. No system()/"/bin/sh" anywhere,
# and the service installs a seccomp filter at startup that kills execve/fork/
# clone -- so none of the memory bugs can become code execution.
RUN gcc -O1 -fstack-protector-all -D_FORTIFY_SOURCE=2 \
    -Wl,-z,relro,-z,now -pie -fPIE -o terminal terminal.c -lseccomp

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
    libseccomp2 && rm -rf /var/lib/apt/lists/*
RUN useradd -r -s /usr/sbin/nologin terminal
COPY --from=build /build/terminal /usr/local/bin/terminal
USER terminal
EXPOSE 9423
CMD ["/usr/local/bin/terminal"]
