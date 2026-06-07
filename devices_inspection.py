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
        * {host}.log          : 常规巡检命令输出（自动过滤掉 show logging alarm / display logbuffer）
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

FILENAME = input(f"\n请输入info文件名（默认为 info.xlsx）：") or "info.xlsx"
INFO_PATH = os.path.join(os.getcwd(), FILENAME)
LOCAL_TIME = time.strftime('%Y.%m.%d', time.localtime())
LOCK = threading.Lock()
POOL = threading.BoundedSemaphore(200)


class PasswordRequiredError(Exception):
    """文件受密码保护，必须提供密码"""
    pass


@contextmanager
def suppress_stderr():
    with open(os.devnull, 'w') as devnull:
        old_stderr = sys.stderr
        sys.stderr = devnull
        try:
            yield
        finally:
            sys.stderr = old_stderr


def read_info():
    if is_encrypted(INFO_PATH):
        return read_encrypted_file(INFO_PATH)
    else:
        return read_unencrypted_file(INFO_PATH)


def is_encrypted(info_file: str) -> bool:
    try:
        with open(info_file, "rb") as f:
            return msoffcrypto.OfficeFile(f).is_encrypted()
    except Exception:
        return False


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


def connect_with_retry(login_info, max_retries=3, retry_delay=5):
    """尝试连接，认证异常时重试"""
    for attempt in range(1, max_retries + 1):
        try:
            with suppress_stderr():
                conn = ConnectHandler(**login_info)
                return conn, False, None, None
        except Exception as e:
            if isinstance(e, exceptions.NetmikoAuthenticationException):
                if attempt < max_retries:
                    with LOCK:
                        print(f"设备 {login_info['host']} 认证失败，{retry_delay}秒后进行第{attempt+1}次重试...")
                    time.sleep(retry_delay)
                    continue
                else:
                    return None, True, 'NetmikoAuthenticationException', str(e)
            else:
                return None, True, type(e).__name__, str(e)
    return None, True, 'UnknownError', '连接失败'


def inspection(login_info, cmds_dict):
    t11 = time.time()
    ssh = None

    ssh, has_error, error_type, error_msg = connect_with_retry(login_info)

    if has_error:
        with LOCK:
            log_path = os.path.join(os.getcwd(), LOCAL_TIME, '01log.log')
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            with open(log_path, 'a', encoding='utf-8') as log:
                if error_type == 'AttributeError':
                    print(f'设备 {login_info["host"]} 缺少设备管理地址！')
                    log.write(f'设备 {login_info["host"]} 缺少设备管理地址！\n')
                elif error_type == 'NetmikoTimeoutException':
                    print(f'设备 {login_info["host"]} 管理地址或端口不可达！')
                    log.write(f'设备 {login_info["host"]} 管理地址或端口不可达！\n')
                elif error_type == 'NetmikoAuthenticationException':
                    print(f'设备 {login_info["host"]} 用户名或密码认证失败！')
                    log.write(f'设备 {login_info["host"]} 用户名或密码认证失败！\n')
                elif error_type == 'ValueError':
                    print(f'设备 {login_info["host"]} Enable密码认证失败！')
                    log.write(f'设备 {login_info["host"]} Enable密码认证失败！\n')
                elif error_type == 'TimeoutError':
                    print(f'设备 {login_info["host"]} Telnet连接超时！')
                    log.write(f'设备 {login_info["host"]} Telnet连接超时！\n')
                elif error_type == 'ReadTimeout':
                    print(f'设备 {login_info["host"]} Enable密码认证失败！')
                    log.write(f'设备 {login_info["host"]} Enable密码认证失败！\n')
                elif error_type == 'ConnectionRefusedError':
                    print(f'设备 {login_info["host"]} 远程登录协议错误！')
                    log.write(f'设备 {login_info["host"]} 远程登录协议错误！\n')
                else:
                    print(f'设备 {login_info["host"]} 未知错误！{error_type}: {error_msg}')
                    log.write(f'设备 {login_info["host"]} 未知错误！{error_type}: {error_msg}\n')
        POOL.release()
        return

    # 功能1：每台设备独立子目录
    host_subdir = os.path.join(os.getcwd(), LOCAL_TIME, login_info['host'])
    os.makedirs(host_subdir, exist_ok=True)
    main_log = os.path.join(host_subdir, f"{login_info['host']}.log")

    # 确定额外命令（功能2）
    device_type = login_info['device_type']
    extra_cmd = None
    if device_type in ['cisco_ios', 'cisco_ios_telnet']:
        extra_cmd = 'show logging alarm'
    elif device_type == 'huawei':
        extra_cmd = 'display logbuffer'

    with open(main_log, 'w', encoding='utf-8') as f:
        with LOCK:
            print(f'设备 {login_info["host"]} 正在巡检...')
        f.write('=' * 10 + ' Local Time ' + '=' * 10 + '\n\n')
        f.write(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + '\n\n')

        # 常规命令列表：过滤掉与额外命令相同的命令（避免重复）
        for cmd in cmds_dict[login_info['device_type']]:
            if not isinstance(cmd, str):
                continue
            # 如果当前命令就是额外命令，则跳过（不写入主日志）
            if extra_cmd and cmd.strip() == extra_cmd.strip():
                continue
            f.write('=' * 10 + ' ' + cmd + ' ' + '=' * 10 + '\n\n')
            try:
                out = ssh.send_command(cmd, read_timeout=120)
            except exceptions.ReadTimeout:
                print(f'设备 {login_info["host"]} 命令 {cmd} 执行超时！')
                out = f'命令 {cmd} 执行超时！'
            f.write(out + '\n\n')

    # 功能2：执行额外命令并单独输出到 {host}.log.log
    if extra_cmd:
        try:
            out = ssh.send_command(extra_cmd, read_timeout=60)
            extra_log = os.path.join(host_subdir, f"{login_info['host']}.log.log")
            with open(extra_log, 'w', encoding='utf-8') as ef:
                ef.write(out)
        except Exception:
            pass  # 静默失败

    t12 = time.time()
    with LOCK:
        print(f'设备 {login_info["host"]} 巡检完成，用时 {round(t12 - t11, 1)} 秒。')

    ssh.disconnect()
    POOL.release()


if __name__ == '__main__':
    t1 = time.time()
    threads = []
    devices_info, cmds_info = read_info()

    print(f'\n巡检开始...')
    print(f'\n' + '>' * 40 + '\n')

    if os.path.exists(LOCAL_TIME):
        shutil.rmtree(LOCAL_TIME)
    os.makedirs(LOCAL_TIME)

    for dev in devices_info:
        dev_copy = dev.copy()
        dev_copy["conn_timeout"] = 40
        t = threading.Thread(target=inspection, args=(dev_copy, cmds_info), name=dev['host'] + '_Thread')
        threads.append(t)
        POOL.acquire()
        t.start()

    for t in threads:
        t.join()

    error_log = os.path.join(os.getcwd(), LOCAL_TIME, '01log.log')
    if os.path.exists(error_log):
        with open(error_log, 'r', encoding='utf-8') as f:
            error_count = len(f.readlines())
    else:
        error_count = 0

    t2 = time.time()
    print(f'\n' + '<' * 40 + '\n')
    print(f'巡检完成，共巡检 {len(threads)} 台设备，{error_count} 台异常，共用时 {round(t2 - t1, 1)} 秒。\n')
    input('输入Enter退出！')
