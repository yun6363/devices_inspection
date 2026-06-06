#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

"""
devices_inspection.py —— 网络设备自动化巡检脚本 (增强版)
支持按主机子目录、额外命令日志、认证重试
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
    last_exception = None
    for attempt in range(1, max_retries + 1):
        try:
            with suppress_stderr():
                conn = ConnectHandler(**login_info)
                return conn, None, None, None
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
                return None, True, type(e).__name__, str(e)
    return None, True, 'UnknownError', str(last_exception)


def inspection(login_info, cmds_dict):
    t11 = time.time()
    ssh = None

    ssh, has_error, error_type, error_msg = connect_with_retry(login_info, max_retries=3, retry_delay=5)

    if has_error:
        with LOCK:
            # 根据错误类型输出和记录
            log_path = os.path.join(os.getcwd(), LOCAL_TIME, '01log.log')
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            match error_type:
                case 'AttributeError':
                    print(f'设备 {login_info["host"]} 缺少设备管理地址！')
                    with open(log_path, 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} 缺少设备管理地址！\n')
                case 'NetmikoTimeoutException':
                    print(f'设备 {login_info["host"]} 管理地址或端口不可达！')
                    with open(log_path, 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} 管理地址或端口不可达！\n')
                case 'NetmikoAuthenticationException':
                    print(f'设备 {login_info["host"]} 用户名或密码认证失败！')
                    with open(log_path, 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} 用户名或密码认证失败！\n')
                case 'ValueError':
                    print(f'设备 {login_info["host"]} Enable密码认证失败！')
                    with open(log_path, 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} Enable密码认证失败！\n')
                case 'TimeoutError':
                    print(f'设备 {login_info["host"]} Telnet连接超时！')
                    with open(log_path, 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} Telnet连接超时！\n')
                case 'ReadTimeout':
                    print(f'设备 {login_info["host"]} Enable密码认证失败！')
                    with open(log_path, 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} Enable密码认证失败！\n')
                case 'ConnectionRefusedError':
                    print(f'设备 {login_info["host"]} 远程登录协议错误！')
                    with open(log_path, 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} 远程登录协议错误！\n')
                case _:
                    print(f'设备 {login_info["host"]} 未知错误！{error_type}: {error_msg}')
                    with open(log_path, 'a', encoding='utf-8') as log:
                        log.write(f'设备 {login_info["host"]} 未知错误！{error_type}: {error_msg}\n')
        POOL.release()
        return

    # 创建主机子目录
    host_subdir = os.path.join(os.getcwd(), LOCAL_TIME, login_info['host'])
    os.makedirs(host_subdir, exist_ok=True)
    main_log_path = os.path.join(host_subdir, f"{login_info['host']}.log.log")

    with open(main_log_path, 'w', encoding='utf-8') as device_log_file:
        with LOCK:
            print(f'设备 {login_info["host"]} 正在巡检...')
        device_log_file.write('=' * 10 + ' ' + 'Local Time' + ' ' + '=' * 10 + '\n\n')
        device_log_file.write(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()) + '\n\n')

        # 执行常规巡检命令
        for cmd in cmds_dict.get(login_info['device_type'], []):
            if isinstance(cmd, str):
                device_log_file.write('=' * 10 + ' ' + cmd + ' ' + '=' * 10 + '\n\n')
                try:
                    show = ssh.send_command(cmd, read_timeout=120)
                except exceptions.ReadTimeout:
                    print(f'设备 {login_info["host"]} 命令 {cmd} 执行超时！')
                    show = f'命令 {cmd} 执行超时！'
                finally:
                    device_log_file.write(show + '\n\n')

        # 额外命令单独保存
        extra_commands = {
            "show logging alarm": f"{login_info['host']}_show_logging_alarm.log",
            "display logbuffer": f"{login_info['host']}_display_logbuffer.log"
        }
        for cmd, filename in extra_commands.items():
            try:
                output = ssh.send_command(cmd, read_timeout=60)
                extra_log_path = os.path.join(host_subdir, filename)
                with open(extra_log_path, 'w', encoding='utf-8') as extra_f:
                    extra_f.write(output)
            except Exception:
                pass  # 命令不支持则跳过

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

    # 清空并重建当天目录
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
