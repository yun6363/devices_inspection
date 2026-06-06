#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""
devices_inspection.py —— 网络设备自动化巡检脚本

功能简介：
    本脚本通过读取 Excel 格式的 info 配置文件，自动批量登录网络设备并执行预设
    的巡检命令，将巡检结果保存为本地日志文件，适用于日常网络运维的自动化巡检场景。

主要功能：
    - 支持读取加密/未加密的 Excel 配置文件（info.xlsx），获取设备登录信息与巡检命令；
    - 通过 Netmiko 库以 SSH/Telnet 方式登录设备，支持多种设备类型；
    - 采用多线程并发巡检，最大并发线程数为 200（可配置），显著提升巡检效率；
    - 自动按当天日期创建结果目录，每台设备生成独立的子目录，其中：
        * {host}.log          : 常规巡检命令输出
        * {host}.log.log      : 设备类型对应的额外命令输出（Cisco: show logging alarm, Huawei: display logbuffer）
    - 对登录失败（超时、认证失败、协议错误等）的设备统一记录至 01log.log 文件；
    - 认证失败自动重试3次，提高巡检容错性；
    - 巡检完成后 CLI 输出汇总信息，包含巡检设备总数、异常数及总耗时。

依赖库：
    netmiko, pandas, msoffcrypto, openpyxl

使用方式：
    1. 在脚本同目录下准备 info.xlsx（Sheet1：设备登录信息，Sheet2：巡检命令）；
    2. 直接运行脚本：python devices_inspection.py；
    3. 按提示输入 info 文件名（默认为 info.xlsx）；
    4. 巡检结果将保存至当天日期命名的文件夹中。

         Author: Robin (modified)
  Creation Date: 2023.12.25
        Version: v2026.03.24 (enhanced)
"""

import os
import sys
import time
import getpass
import threading
import shutil
import msoffcrypto
import pandas as pd
from io import BytesIO
from netmiko import ConnectHandler
from netmiko import exceptions
from contextlib import contextmanager

FILENAME = input(f"\n请输入info文件名（默认为 info.xlsx）：") or "info.xlsx"  # 指定info文件名称
INFO_PATH = os.path.join(os.getcwd(), FILENAME)  # 读取info文件路径
LOCAL_TIME = time.strftime('%Y.%m.%d', time.localtime())  # 读取当前日期
LOCK = threading.Lock()  # 线程锁实例化
POOL = threading.BoundedSemaphore(200)  # 最大线程控制


# 自定义异常类，用于处理输入密码为None情况
class PasswordRequiredError(Exception):
    """文件受密码保护，必须提供密码"""
    pass


@contextmanager
def suppress_stderr():
    """
    临时屏蔽 stderr 输出（仅用于抑制 Paramiko 在 SSH 连接失败时
    输出的 'Error reading SSH protocol banner' 等底层 traceback）。
    """
    with open(os.devnull, 'w') as devnull:
        old_stderr = sys.stderr
        sys.stderr = devnull
        try:
            yield
        finally:
            sys.stderr = old_stderr


# 判断info文件是否被加密，使用不同的读取方式
def read_info():
    if is_encrypted(INFO_PATH):
        return read_encrypted_file(INFO_PATH)
    else:
        return read_unencrypted_file(INFO_PATH)


# 检测info文件是否被加密
def is_encrypted(info_file: str) -> bool:
    try:
        with open(info_file, "rb") as f:
            return msoffcrypto.OfficeFile(f).is_encrypted()
    except Exception:
        return False


# 读取被加密info文件
def read_encrypted_file(info_file: str, max_retry: int = 3):
    retry_count = 0
    while retry_count < max_retry:
        try:
            password = getpass.getpass("\ninfo文件被加密，请输入密码：") or None
            if not password:
                raise PasswordRequiredError("文件受密码保护，必须提供密码！")

            decrypted_data = BytesIO()
            with open(info_file, "rb") as f:
                office_file = msoffcrypto.OfficeFile(f)
                office_file.load_key(password=password)
                office_file.decrypt(decrypted_data)
            decrypted_data.seek(0)

            devices_dataframe = pd.read_excel(decrypted_data, sheet_name=0, dtype=str, keep_default_na=False)
            cmds_dataframe = pd.read_excel(decrypted_data, sheet_name=1, dtype=str)

        except FileNotFoundError:
            print(f'\n没有找到info文件！\n')
            input('输入Enter退出！')
            sys.exit(1)
        except ValueError:
            print(f'\ninfo文件缺失子表格信息！\n')
            input('输入Enter退出！')
            sys.exit(1)
        except (msoffcrypto.exceptions.InvalidKeyError, PasswordRequiredError):
            retry_count += 1
            if retry_count < max_retry:
                print(f"\n密码错误，请重新输入！（剩余尝试次数：{max_retry - retry_count}）")
            else:
                input("\n超过最大尝试次数，输入Enter退出！")
                sys.exit(1)
        except Exception as e:
            print(f"\n解密失败：{str(e)}")
            sys.exit(1)
        else:
            devices_dict = devices_dataframe.to_dict('records')
            cmds_dict = cmds_dataframe.to_dict('list')
            return devices_dict, cmds_dict


# 读取未加密info文件
def read_unencrypted_file(info_file: str):
    try:
        devices_dataframe = pd.read_excel(info_file, sheet_name=0, dtype=str, keep_default_na=False)
        cmds_dataframe = pd.read_excel(info_file, sheet_name=1, dtype=str)
    except FileNotFoundError:
        print(f'\n没有找到info文件！\n')
        input('输入Enter退出！')
        sys.exit(1)
    except ValueError:
        print(f'\ninfo文件缺失子表格信息！\n')
        input('输入Enter退出！')
        sys.exit(1)
    else:
        devices_dict = devices_dataframe.to_dict('records')
        cmds_dict = cmds_dataframe.to_dict('list')
        return devices_dict, cmds_dict


# === 功能3：带重试的连接函数（仅认证异常重试）===
def connect_with_retry(login_info, max_retries=3, retry_delay=5):
    """
    尝试建立 SSH/Telnet 连接，若遇到认证异常则重试。
    返回 (connection, has_error, error_type, error_message)
    成功时 connection 有效，其余为 None；失败时 connection 为 None，返回错误信息。
    """
    last_exception = None
    for attempt in range(1, max_retries + 1):
        try:
            with suppress_stderr():
                conn = ConnectHandler(**login_info)
                return conn, False, None, None
        except Exception as e:
            last_exception = e
            if isinstance(e, exceptions.NetmikoAuthenticationException):
                if attempt < max_retries:
                    with LOCK:
                        print(f"设备 {login_info['host']} 认证失败，{retry_delay}秒后进行第{attempt+1}次重试...")
                    time.sleep(retry_delay)
                    continue
                else:
                    return None, True, 'NetmikoAuthenticationException', str(e)
            else:
                # 非认证异常，不重试
                return None, True, type(e).__name__, str(e)
    return None, True, 'UnknownError', str(last_exception)


# === 巡检主函数（已集成功能1、功能2）===
def inspection(login_info, cmds_dict):
    t11 = time.time()
    ssh = None

    ssh, has_error, error_type, error_msg = connect_with_retry(login_info, max_retries=3, retry_delay=5)

    if has_error:
        # 连接失败，记录到 01log.log
        with LOCK:
            match error_type:
                case 'AttributeError':
                    print(f'设备 {login_info["host"]} 缺少设备管理地址！')
                    with open(os.path.join(os.getcwd(), LOCAL_TIME, '01log.log'), 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} 缺少设备管理地址！\n')
                case 'NetmikoTimeoutException':
                    print(f'设备 {login_info["host"]} 管理地址或端口不可达！')
                    with open(os.path.join(os.getcwd(), LOCAL_TIME, '01log.log'), 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} 管理地址或端口不可达！\n')
                case 'NetmikoAuthenticationException':
                    print(f'设备 {login_info["host"]} 用户名或密码认证失败！')
                    with open(os.path.join(os.getcwd(), LOCAL_TIME, '01log.log'), 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} 用户名或密码认证失败！\n')
                case 'ValueError':
                    print(f'设备 {login_info["host"]} Enable密码认证失败！')
                    with open(os.path.join(os.getcwd(), LOCAL_TIME, '01log.log'), 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} Enable密码认证失败！\n')
                case 'TimeoutError':
                    print(f'设备 {login_info["host"]} Telnet连接超时！')
                    with open(os.path.join(os.getcwd(), LOCAL_TIME, '01log.log'), 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} Telnet连接超时！\n')
                case 'ReadTimeout':
                    print(f'设备 {login_info["host"]} Enable密码认证失败！')
                    with open(os.path.join(os.getcwd(), LOCAL_TIME, '01log.log'), 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} Enable密码认证失败！\n')
                case 'ConnectionRefusedError':
                    print(f'设备 {login_info["host"]} 远程登录协议错误！')
                    with open(os.path.join(os.getcwd(), LOCAL_TIME, '01log.log'), 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} 远程登录协议错误！\n')
                case _:
                    print(f'设备 {login_info["host"]} 未知错误！{error_type}: {error_msg}')
                    with open(os.path.join(os.getcwd(), LOCAL_TIME, '01log.log'), 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} 未知错误！{error_type}: {error_msg}\n')
        POOL.release()
        return

    # === 功能1：为每台设备创建独立子目录 ===
    host_subdir = os.path.join(os.getcwd(), LOCAL_TIME, login_info['host'])
    os.makedirs(host_subdir, exist_ok=True)
    main_log_path = os.path.join(host_subdir, f"{login_info['host']}.log")   # 常规命令输出 {host}.log

    with open(main_log_path, 'w', encoding='utf-8') as device_log_file:
        with LOCK:
            print(f'设备 {login_info["host"]} 正在巡检...')
        device_log_file.write('=' * 10 + ' ' + 'Local Time' + ' ' + '=' * 10 + '\n\n')
        device_log_file.write(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + '\n\n')

        # 执行常规巡检命令
        for cmd in cmds_dict[login_info['device_type']]:
            if isinstance(cmd, str):
                device_log_file.write('=' * 10 + ' ' + cmd + ' ' + '=' * 10 + '\n\n')
                try:
                    show = ssh.send_command(cmd, read_timeout=120)
                except exceptions.ReadTimeout:
                    print(f'设备 {login_info["host"]} 命令 {cmd} 执行超时！')
                    show = f'命令 {cmd} 执行超时！'
                finally:
                    device_log_file.write(show + '\n\n')

    # === 功能2：根据设备类型执行额外命令，输出 {host}.log.log ===
    device_type = login_info['device_type']
    extra_cmd = None
    if device_type in ['cisco_ios', 'cisco_ios_telnet']:
        extra_cmd = 'show logging alarm'
    elif device_type == 'huawei':
        extra_cmd = 'display logbuffer'

    if extra_cmd:
        try:
            output = ssh.send_command(extra_cmd, read_timeout=60)
            extra_log_path = os.path.join(host_subdir, f"{login_info['host']}.log.log")
            with open(extra_log_path, 'w', encoding='utf-8') as extra_f:
                extra_f.write(output)
        except Exception:
            # 命令不支持或超时，静默跳过，不影响巡检结果
            pass

    t12 = time.time()
    with LOCK:
        print(f'设备 {login_info["host"]} 巡检完成，用时 {round(t12 - t11, 1)} 秒。')

    ssh.disconnect()
    POOL.release()


if __name__ == '__main__':
    t1 = time.time()
    threading_list = []
    devices_info, cmds_info = read_info()

    print(f'\n巡检开始...')
    print(f'\n' + '>' * 40 + '\n')

    # 清空当天目录（如有则删除重建）
    if os.path.exists(LOCAL_TIME):
        shutil.rmtree(LOCAL_TIME)
    os.makedirs(LOCAL_TIME)

    for device_info in devices_info:
        updated_device_info = device_info.copy()
        updated_device_info["conn_timeout"] = 40
        pre_device = threading.Thread(target=inspection, args=(updated_device_info, cmds_info), name=device_info['host'] + '_Thread')
        threading_list.append(pre_device)
        POOL.acquire()
        pre_device.start()

    for _ in threading_list:
        _.join()

    try:
        with open(os.path.join(os.getcwd(), LOCAL_TIME, '01log.log'), 'r', encoding='utf-8') as log_file:
            file_lines = len(log_file.readlines())
    except FileNotFoundError:
        file_lines = 0

    t2 = time.time()
    print(f'\n' + '<' * 40 + '\n')
    print(f'巡检完成，共巡检 {len(threading_list)} 台设备，{file_lines} 台异常，共用时 {round(t2 - t1, 1)} 秒。\n')
    input('输入Enter退出！')
