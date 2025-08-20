#!/usr/bin/env python3
"""
沙盒系统核心实现
支持Windows和Linux程序自动检测与隔离执行
"""

import os
import sys
import json
import logging
import magic
import tempfile
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger("sandbox_system")


class SandboxSystem:
    def __init__(self, cuckoo_path: str = "/opt/cuckoo"):
        """
        初始化沙盒系统

        Args:
            cuckoo_path: Cuckoo Sandbox安装路径
        """
        self.cuckoo_path = cuckoo_path
        self.temp_dir = tempfile.mkdtemp(prefix="sandbox_")
        logger.info(f"初始化沙盒系统，临时目录: {self.temp_dir}")

    def detect_file_os(self, file_path: str) -> str:
        """
        检测文件适用的操作系统

        Args:
            file_path: 要检测的文件路径

        Returns:
            'windows', 'linux' 或抛出异常
        """
        try:
            # 使用python-magic检测文件类型
            file_type = magic.from_file(file_path, mime=False)
            logger.info(f"文件类型检测: {file_type}")

            if 'PE32' in file_type or 'PE64' in file_type or 'MS-DOS' in file_type:
                return 'windows'
            elif 'ELF' in file_type:
                return 'linux'
            elif 'Mach-O' in file_type:
                return 'macos'  # 可选支持
            else:
                # 尝试通过文件扩展名辅助判断
                ext = Path(file_path).suffix.lower()
                if ext in ['.exe', '.dll', '.msi', '.bat', '.ps1', '.vbs']:
                    return 'windows'
                elif ext in ['.sh', '.bin', '.out', '.run'] or not ext:
                    return 'linux'
                else:
                    raise ValueError(f"无法确定文件类型: {file_type}")

        except Exception as e:
            logger.error(f"文件检测失败: {e}")
            raise

    def prepare_analysis_environment(self, file_path: str, target_os: str) -> Dict[str, Any]:
        """
        准备分析环境

        Args:
            file_path: 要分析的文件路径
            target_os: 目标操作系统

        Returns:
            包含分析环境信息的字典
        """
        # 创建分析目录
        analysis_id = f"analysis_{os.getpid()}_{int(time.time())}"
        analysis_dir = os.path.join(self.temp_dir, analysis_id)
        os.makedirs(analysis_dir, exist_ok=True)

        # 复制文件到分析目录
        target_file = os.path.join(analysis_dir, os.path.basename(file_path))
        shutil.copy2(file_path, target_file)

        # 根据目标OS选择分析机标签
        if target_os == 'windows':
            machine_tag = 'win10_sandbox'  # 需要在Cuckoo中配置的Windows分析机标签
        elif target_os == 'linux':
            machine_tag = 'ubuntu_sandbox'  # 需要在Cuckoo中配置的Linux分析机标签
        else:
            machine_tag = 'auto'  # 让Cuckoo自动选择

        return {
            'analysis_id': analysis_id,
            'analysis_dir': analysis_dir,
            'file_path': target_file,
            'machine_tag': machine_tag
        }

    def submit_to_cuckoo(self, file_path: str, machine_tag: str = "auto") -> Optional[int]:
        """
        提交文件到Cuckoo Sandbox进行分析

        Args:
            file_path: 要分析的文件路径
            machine_tag: 分析机标签

        Returns:
            任务ID或None（失败时）
        """
        try:
            # 切换到Cuckoo目录
            original_cwd = os.getcwd()
            os.chdir(self.cuckoo_path)

            # 构建Cuckoo提交命令
            cmd = [
                "python3", "utils/submit.py",
                "--machine", machine_tag,
                "--timeout", "300",  # 5分钟超时
                "--enforce-timeout",
                "--options", "{\"free\": \"yes\"}",  # 允许分析完成后释放VM
                file_path
            ]

            logger.info(f"执行命令: {' '.join(cmd)}")

            # 执行提交命令
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30  # 提交超时30秒
            )

            os.chdir(original_cwd)

            if result.returncode == 0:
                # 解析输出获取任务ID
                for line in result.stdout.split('\n'):
                    if "Task ID" in line:
                        task_id = int(line.split(":")[1].strip())
                        logger.info(f"任务提交成功，任务ID: {task_id}")
                        return task_id

                logger.warning("无法解析任务ID，但命令执行成功")
                return None
            else:
                logger.error(f"任务提交失败: {result.stderr}")
                return None

        except subprocess.TimeoutExpired:
            logger.error("提交任务超时")
            return None
        except Exception as e:
            logger.error(f"提交任务时发生异常: {e}")
            return None

    def wait_for_analysis_completion(self, task_id: int, timeout: int = 600) -> bool:
        """
        等待分析完成

        Args:
            task_id: 任务ID
            timeout: 超时时间（秒）

        Returns:
            是否成功完成
        """
        try:
            # 切换到Cuckoo目录
            original_cwd = os.getcwd()
            os.chdir(self.cuckoo_path)

            # 构建检查命令
            cmd = ["python3", "utils/task.py", "--status", str(task_id)]

            start_time = time.time()
            while time.time() - start_time < timeout:
                # 检查任务状态
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=30
                )

                if result.returncode == 0:
                    if "completed" in result.stdout.lower():
                        logger.info(f"任务 {task_id} 分析完成")
                        return True
                    elif "failed" in result.stdout.lower() or "error" in result.stdout.lower():
                        logger.error(f"任务 {task_id} 分析失败")
                        return False

                # 等待一段时间再检查
                time.sleep(10)

            logger.error(f"等待任务 {task_id} 完成超时")
            return False

        except Exception as e:
            logger.error(f"检查任务状态时发生异常: {e}")
            return False
        finally:
            os.chdir(original_cwd)

    def get_analysis_report(self, task_id: int) -> Optional[Dict[str, Any]]:
        """
        获取分析报告

        Args:
            task_id: 任务ID

        Returns:
            分析报告字典或None（失败时）
        """
        try:
            # 报告路径（Cuckoo默认存储位置）
            report_path = os.path.join(
                self.cuckoo_path,
                "storage",
                "analyses",
                str(task_id),
                "reports",
                "report.json"
            )

            if os.path.exists(report_path):
                with open(report_path, 'r') as f:
                    report = json.load(f)
                logger.info(f"成功获取任务 {task_id} 的报告")
                return report
            else:
                logger.error(f"报告文件不存在: {report_path}")
                return None

        except Exception as e:
            logger.error(f"获取报告时发生异常: {e}")
            return None

    def analyze_file(self, file_path: str) -> Optional[Dict[str, Any]]:
        """
        分析文件的主方法

        Args:
            file_path: 要分析的文件路径

        Returns:
            分析结果字典或None（失败时）
        """
        if not os.path.exists(file_path):
            logger.error(f"文件不存在: {file_path}")
            return None

        try:
            # 1. 检测文件适用的OS
            target_os = self.detect_file_os(file_path)
            logger.info(f"检测到文件适用于: {target_os}")

            # 2. 准备分析环境
            env_info = self.prepare_analysis_environment(file_path, target_os)

            # 3. 提交到Cuckoo
            task_id = self.submit_to_cuckoo(env_info['file_path'], env_info['machine_tag'])

            if task_id is None:
                logger.error("提交分析任务失败")
                return None

            # 4. 等待分析完成
            if not self.wait_for_analysis_completion(task_id):
                logger.error("分析任务未成功完成")
                return None

            # 5. 获取分析报告
            report = self.get_analysis_report(task_id)

            if report:
                # 添加一些自定义信息
                report['sandbox_info'] = {
                    'original_file': file_path,
                    'detected_os': target_os,
                    'analysis_id': env_info['analysis_id'],
                    'machine_used': env_info['machine_tag']
                }

                # 简化的恶意评分
                score = self.calculate_malware_score(report)
                report['malware_score'] = score

                logger.info(f"分析完成，恶意评分: {score}/10")

            return report

        except Exception as e:
            logger.error(f"分析过程中发生异常: {e}")
            return None
        finally:
            # 清理临时文件
            self.cleanup()

    def calculate_malware_score(self, report: Dict[str, Any]) -> int:
        """
        根据分析报告计算恶意评分

        Args:
            report: Cuckoo分析报告

        Returns:
            恶意评分 (0-10)
        """
        score = 0

        # 简化的评分逻辑
        if 'signatures' in report:
            for sig in report['signatures']:
                severity = sig.get('severity', 0)
                score += severity * 0.5  # 根据严重程度加权

        # 基于网络活动评分
        if 'network' in report and report['network']:
            score += 2

        # 基于文件活动评分
        if 'behavior' in report and report['behavior']:
            process_list = report['behavior'].get('processes', [])
            if process_list:
                score += 1

            # 检查可疑文件操作
            for process in process_list:
                for call in process.get('calls', []):
                    if call.get('api', '').startswith('CreateFile') and \
                            ('System32' in str(call.get('arguments', {})) or \
                             'Windows' in str(call.get('arguments', {}))):
                        score += 2
                        break

        # 限制分数在0-10之间
        return min(10, int(score))

    def cleanup(self):
        """清理临时文件"""
        try:
            if os.path.exists(self.temp_dir):
                shutil.rmtree(self.temp_dir)
                logger.info(f"已清理临时目录: {self.temp_dir}")
        except Exception as e:
            logger.warning(f"清理临时文件时发生异常: {e}")


# Web API接口（可选）
from flask import Flask, request, jsonify

app = Flask(__name__)
sandbox = SandboxSystem()


@app.route('/api/analyze', methods=['POST'])
def analyze_file_api():
    """分析文件的API端点"""
    if 'file' not in request.files:
        return jsonify({'error': '没有提供文件'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': '没有选择文件'}), 400

    # 保存上传的文件
    upload_dir = tempfile.mkdtemp()
    file_path = os.path.join(upload_dir, file.filename)
    file.save(file_path)

    try:
        # 分析文件
        result = sandbox.analyze_file(file_path)

        if result:
            return jsonify(result), 200
        else:
            return jsonify({'error': '分析失败'}), 500

    except Exception as e:
        return jsonify({'error': f'分析过程中发生异常: {str(e)}'}), 500
    finally:
        # 清理上传的文件
        try:
            shutil.rmtree(upload_dir)
        except:
            pass


# 命令行接口
if __name__ == "__main__":
    import argparse
    import time

    parser = argparse.ArgumentParser(description="沙盒系统")
    parser.add_argument("file", help="要分析的文件路径")
    parser.add_argument("--web", action="store_true", help="启动Web服务")
    parser.add_argument("--port", type=int, default=5000, help="Web服务端口")

    args = parser.parse_args()

    if args.web:
        print(f"启动Web服务，端口: {args.port}")
        app.run(host='0.0.0.0', port=args.port, debug=False)
    else:
        # 命令行模式
        if not os.path.exists(args.file):
            print(f"错误: 文件 '{args.file}' 不存在")
            sys.exit(1)

        sandbox = SandboxSystem()
        result = sandbox.analyze_file(args.file)

        if result:
            print("分析完成!")
            print(f"恶意评分: {result.get('malware_score', 'N/A')}/10")
            print(f"详细信息已保存到报告")

            # 保存报告到文件
            report_file = f"report_{int(time.time())}.json"
            with open(report_file, 'w') as f:
                json.dump(result, f, indent=2)
            print(f"完整报告已保存到: {report_file}")
        else:
            print("分析失败!")
            sys.exit(1)
