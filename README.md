# sgx-detect

This is a program to test whether the TCB of your current platform is safe. It requires Ubuntu kernel to be greater than 5.11. The usage method is as follows:

1. Compile the sgx-detect app program, which is responsible for generating remote authentication reports.

* Download the baiduxlab/sgx-rust container and compile using the environment with sgxsdk installed.

```shell
#install complie docker
docker pull baiduxlab/sgx-rust

#run
docker run -v <Your project path>:/root/sgx-detect --device /dev/sgx_enclave:/dev/sgx/enclave --device /dev/sgx_provision -ti baiduxlab/sgx-rust:latest
```

* Compile the sgx-detect program

```shell
cd /root/sgx-detect

#change your rust toolchain
rustup toolchain install nightly-2020-10-25

#export your IAS_API_KEY and IAS_SPID
export IAS_API_KEY="xxxxxxxxxx"
export IAS_SPID="xxxxxxxxxx"

#build the project
make
```

* Exit the container and build the docker image

```shell
exit
sudo docker build -f dockerfile/sgx_detect.Dockerfile -t sgx-detect:latest .
```

# sgx-detect

This is a program to test whether the TCB of your current platform is safe. It requires Ubuntu kernel to be greater than 5.11. The usage method is as follows:

1. Compile the sgx-detect app program, which is responsible for generating remote authentication reports.

* Download the baiduxlab/sgx-rust container and compile using the environment with sgxsdk installed.

```shell
#install complie docker
docker pull baiduxlab/sgx-rust

#run
docker run -v <Your project path>:/root/sgx-detect --device /dev/sgx_enclave:/dev/sgx/enclave --device /dev/sgx_provision -ti baiduxlab/sgx-rust:latest
```

* Compile the sgx-detect program

```shell
cd /root/sgx-detect

#change your rust toolchain
rustup toolchain install nightly-2020-10-25

#export your IAS_API_KEY and IAS_SPID
export IAS_API_KEY="xxxxxxxxxx"
export IAS_SPID="xxxxxxxxxx"

#build the project
make
```

* Exit the container and build the docker image

```shell
exit
sudo docker build -f dockerfile/sgx_detect.Dockerfile -t sgx-detect:latest .
```

