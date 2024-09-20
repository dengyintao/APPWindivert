#include <winsock2.h>
#include <ws2tcpip.h>  // 添加此行以包含 inet_pton
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include "windivert.h"
#include <tlhelp32.h>
#include <iphlpapi.h>
#include <process.h>
#include <queue>
#include <mutex>
#include <condition_variable>
#include <thread>
#include <vector>
#include <memory>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "Ws2_32.lib")

#define MAX_PACKET_SIZE 65535
constexpr const char* PROXY_ADDRESS = "127.0.0.1";
constexpr int PROXY_PORT = 7890;

std::queue<std::pair<std::vector<char>, UINT>> packet_queue;
std::mutex queue_mutex;
std::condition_variable queue_cond;
DWORD target_pid = 0;
int ports[50];
int port_count = 0;
WINDIVERT_ADDRESS global_addr;

void modify_packet_and_redirect(char* packet, UINT packet_len, WINDIVERT_ADDRESS addr);
DWORD GetProcessIdByName(const wchar_t* process_name);
void GetTcpConnections(DWORD target_pid, int* ports, int* port_count);
void AsyncGetPidAndPorts(const wchar_t* process_name);
void PacketProcessingThread();

int main() {
    const wchar_t* target_process_name = L"chrome.exe";

    // 启动异步获取 PID 和端口的线程
    std::thread pid_thread(AsyncGetPidAndPorts, target_process_name);

    // 启动数据包处理线程
    std::thread packet_thread(PacketProcessingThread);

    HANDLE handle;
    handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0); // 使用 "true" 作为过滤器
    if (handle == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "Error: Failed to open WinDivert handle (%d)\n", GetLastError());
        return EXIT_FAILURE;
    }

    while (TRUE) {
        std::vector<char> packet(MAX_PACKET_SIZE);
        UINT packet_len;

        if (!WinDivertRecv(handle, packet.data(), packet.size(), &packet_len, &global_addr)) {
            fprintf(stderr, "Warning: Failed to receive packet (%d)\n", GetLastError());
            continue;
        }

        // 缓存数据包
        {
            std::lock_guard<std::mutex> lock(queue_mutex);
            packet_queue.push(std::make_pair(std::move(packet), packet_len));
        }
        queue_cond.notify_one();
    }

    WinDivertClose(handle);
    pid_thread.detach();
    packet_thread.detach();
    return 0;
}

void modify_packet_and_redirect(char* packet, UINT packet_len, WINDIVERT_ADDRESS addr) {
    PWINDIVERT_IPHDR ip_header = nullptr;
    PWINDIVERT_IPV6HDR ipv6_header = nullptr;
    UINT8 protocol;
    PWINDIVERT_ICMPHDR icmp_header = nullptr;
    PWINDIVERT_ICMPV6HDR icmpv6_header = nullptr;
    PWINDIVERT_TCPHDR tcp_header = nullptr;
    PWINDIVERT_UDPHDR udp_header = nullptr;
    PVOID payload = nullptr;
    UINT payload_len = 0;
    PVOID next_header = nullptr;
    UINT next_header_len = 0;

    // 解析 IP 和 TCP 头部
    WinDivertHelperParsePacket(
        packet,
        packet_len,
        &ip_header,
        &ipv6_header,
        &protocol,
        &icmp_header,
        &icmpv6_header,
        &tcp_header,
        &udp_header,
        &payload,
        &payload_len,
        &next_header,
        &next_header_len
    );

    if (ip_header == nullptr || tcp_header == nullptr) {
        return;  // 如果解析失败，直接返回
    }

    // 修改目标 IP 地址和端口
    struct in_addr proxy_addr;
    if (inet_pton(AF_INET, PROXY_ADDRESS, &proxy_addr) == 1) {
        ip_header->DstAddr = proxy_addr.S_un.S_addr;
        tcp_header->DstPort = htons(PROXY_PORT);

        // 重新计算校验和
        WinDivertHelperCalcChecksums(packet, packet_len, &addr, 0); // flags 参数传递为 0
    }
    else {
        fprintf(stderr, "Error: Invalid proxy address\n");
    }
}

DWORD GetProcessIdByName(const wchar_t* process_name) {
    PROCESSENTRY32 process_entry;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        fwprintf(stderr, L"Error: Failed to create process snapshot (%d)\n", GetLastError());
        return 0;
    }

    process_entry.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(snapshot, &process_entry) == TRUE) {
        while (Process32Next(snapshot, &process_entry) == TRUE) {
            if (_wcsicmp(process_entry.szExeFile, process_name) == 0) {
                CloseHandle(snapshot);
                return process_entry.th32ProcessID;
            }
        }
    }
    else {
        fwprintf(stderr, L"Error: Failed to iterate process list (%d)\n", GetLastError());
    }

    CloseHandle(snapshot);
    return 0;
}

void GetTcpConnections(DWORD target_pid, int* ports, int* port_count) {
    DWORD size = 0;
    GetExtendedTcpTable(NULL, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    std::unique_ptr<char[]> tcp_table_raw(new char[size]);
    PMIB_TCPTABLE_OWNER_PID tcp_table = (PMIB_TCPTABLE_OWNER_PID)tcp_table_raw.get();

    DWORD result = GetExtendedTcpTable(tcp_table, &size, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    if (result == NO_ERROR) {
        *port_count = 0;
        for (int i = 0; i < (int)tcp_table->dwNumEntries; i++) {
            if (tcp_table->table[i].dwOwningPid == target_pid) {
                ports[*port_count] = ntohs((u_short)tcp_table->table[i].dwLocalPort);
                (*port_count)++;
            }
        }
    }
}

void AsyncGetPidAndPorts(const wchar_t* process_name) {
    while (TRUE) {
        DWORD pid = GetProcessIdByName(process_name);
        if (pid != 0 && pid != target_pid) {
            target_pid = pid;
            GetTcpConnections(target_pid, ports, &port_count);
        }
        Sleep(5000);  // 定期刷新 PID 和端口信息
    }
}

void PacketProcessingThread() {
    while (TRUE) {
        std::unique_lock<std::mutex> lock(queue_mutex);
        queue_cond.wait(lock, [] { return !packet_queue.empty(); });

        while (!packet_queue.empty()) {
            auto packet_info = std::move(packet_queue.front());
            packet_queue.pop();
            lock.unlock();

            // 处理捕获的数据包
            modify_packet_and_redirect(packet_info.first.data(), packet_info.second, global_addr);

            lock.lock();
        }
    }
}
