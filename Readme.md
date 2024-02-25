# Cilium ebpf

To run this code, run the below command

1. Generate `vmlinux.h` file

    ```bash
    bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
    ```

It will generate the `vmlinux.h` file, which is needed by our `hello.bpf.c` code

2. we need to initialize the go module
    ```bash
    go mod init <name of the module>
    go mod tidy
    ```

3. run `go generate` command
    ```bash
    go generate main.go
    ```

4. Now, we will build our go code to get the executable
    ```bash
    CGO_ENABLED=0 go build -o hello *.go
    ```

5. Finally, run our compiled code to get trace output
    ```bash
    sudo ./hello
    ```


