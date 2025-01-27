import os
import subprocess
import json
import requests
import time
from datetime import datetime
import socket


class KernelAnalyzer:
    def __init__(self, api_key):
        self.api_key = api_key
        self.hostname = self.get_hostname()
        self.kernel_version = self.get_kernel_version()
        self.latest_kernel_version = self.get_latest_kernel_version()
        self.security_modes = {
            "MAC": self.check_mac_enabled(),
            "DAC": self.check_dac_enabled(),
            "PaX": self.check_pax_enabled(),
            "GrSecurity": self.check_grsecurity_enabled(),
            "Secure Boot": self.check_secure_boot()
        }
        self.patch_status = self.check_patches()
        self.vulnerabilities = self.check_kernel_vulnerabilities()
        self.instructions = self.generate_security_instructions()

    def run_command(self, command):
        try:
            result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, shell=True)
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception as e:
            print(f"Erro ao executar o comando {command}: {e}")
            return None

    def get_hostname(self):
        return socket.gethostname()

    def get_kernel_version(self):
        return self.run_command("uname -r")

    def get_latest_kernel_version(self):
        try:
            response = requests.get("https://www.kernel.org/releases.json")
            response.raise_for_status()
            data = response.json()
            stable_release = next((release for release in data["releases"] if release["moniker"] == "stable"), None)
            return stable_release["version"] if stable_release else "Unknown"
        except Exception as e:
            print(f"Erro ao comparar a ultima versao do Kernel Linux: {e}")
            return "Unknown"

    def check_patches(self):
        if self.latest_kernel_version == "Unknown":
            return "Nao foi possivel determinar a ultima versao do Kernel Linux"
        if self.kernel_version.startswith(self.latest_kernel_version):
            return "Kernel esta atualizado"
        else:
            return f"Kernel esta desatualizado. Ultima versao disponivel: {self.latest_kernel_version}"

    def check_mac_enabled(self):
        selinux_status = self.run_command("sestatus")
        if selinux_status:
            return "SELinux Habilitado"
        apparmor_status = self.run_command("aa-status")
        if apparmor_status:
            return "AppArmor Habilitado"
        return "MAC esta desabilitado"

    def check_dac_enabled(self):
        dac_enabled = self.run_command("ls -ld /home")
        return "DAC Habilitado" if dac_enabled else "DAC Nao esta configurado (Desabilitado)"

    def check_pax_enabled(self):
        pax_status = self.run_command("cat /proc/self/status | grep PaX")
        return "PaX Habilitado" if pax_status else "PaX nao foi detectado (Desabilitado)"

    def check_grsecurity_enabled(self):
        grsecurity_status = self.run_command("dmesg | grep grsecurity")
        return "GrSecurity Habilitado" if grsecurity_status else "GrSecurity nao foi detectado (Desabilitado)"

    def check_secure_boot(self):
        secure_boot_status = self.run_command("mokutil --sb-state")
        if secure_boot_status:
            return "Secure Boot Habilitado" if "enabled" in secure_boot_status.lower() else "Secure Boot Desabilitado"
        return "Nao foi possivel determinar o status do Secure Boot"

    def check_kernel_vulnerabilities(self, retries=3, delay=5):
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        headers = {"apiKey": self.api_key}
        params = {
            "keywordSearch": "Linux Kernel",
            "resultsPerPage": 5,
            "pubStartDate": "2024-10-01T00:00:00.000",
            "pubEndDate": "2024-12-31T23:59:59.999",
        }

        for attempt in range(retries):
            try:
                response = requests.get(base_url, headers=headers, params=params)
                response.raise_for_status()
                data = response.json()

                relevant_cves = [
                    {
                        "ID": cve["id"],
                        "Severity": cve.get("metrics", [{}])[0].get("cvssMetricV31", {}).get("baseSeverity", "Unknown"),
                        "Description": cve.get("descriptions", [{}])[0].get("value", "Sem descricao disponivel"),
                        "Published Date": cve["published"]
                    }
                    for cve in data.get("vulnerabilities", [])
                ]

                return relevant_cves if relevant_cves else "Nenhuma vulnerabilidade encontrada para o kernel atual"
            except requests.exceptions.RequestException as e:
                if attempt < retries - 1:
                    print(f"Erro ao conectar à API NIST. Tentativa {attempt + 1}/{retries}. Re-tentando em {delay} segundos...")
                    time.sleep(delay)
                else:
                    print(f"Erro ao checar vulnerabilidades: {e}")
                    break

        return "Nao foi possivel checar as vulnerabilidades"

    def generate_security_instructions(self):
        instructions = {}
        if "SELinux Habilitado" not in self.security_modes["MAC"]:
            instructions["SELinux"] = "Para habilitar o SELinux, edite o arquivo /etc/selinux/config e defina SELINUX=enforcing. Reinicie o sistema para aplicar as alteracoes."
        if "AppArmor Habilitado" not in self.security_modes["MAC"]:
            instructions["AppArmor"] = "Para habilitar o AppArmor, instale o pacote apparmor com sudo apt install apparmor e reinicie o sistema."
        if "GrSecurity Habilitado" not in self.security_modes["GrSecurity"]:
            instructions["GrSecurity"] = "GrSecurity requer um kernel customizado. Consulte https://grsecurity.net/ para obter mais informacoes."
        if "PaX Habilitado" not in self.security_modes["PaX"]:
            instructions["PaX"] = "PaX tambem requer um kernel customizado. Consulte https://pax.grsecurity.net/ para detalhes."
        if "Secure Boot Habilitado" not in self.security_modes["Secure Boot"]:
            instructions["Secure Boot"] = "Para habilitar o Secure Boot, ative-o no firmware UEFI (BIOS) do sistema."
        return instructions

    def analyze(self):
        report = {
            "Hostname": self.hostname,
            "Data de Geracao": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Versao do Kernel Linux": self.kernel_version,
            "Ultima versao estavel do Kernel Linux": self.latest_kernel_version,
            "Patches Disponiveis": self.patch_status,
            "Modos de seguranca": self.security_modes,
            "Vulnerabilidades para o Kernel Linux": self.vulnerabilities,
        }
        return report

    def save_reports(self):
        analysis_report = self.analyze()
        instructions_report = self.instructions

        filename_base = f"{self.hostname}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        with open(f"{filename_base}_analysis.json", "w") as analysis_file:
            json.dump(analysis_report, analysis_file, indent=4)
        with open(f"{filename_base}_instructions.json", "w") as instructions_file:
            json.dump(instructions_report, instructions_file, indent=4)
        print(f"Relatorios salvos como {filename_base}_analysis.json e {filename_base}_instructions.json")


# Exemplo de uso
if __name__ == "__main__":
    api_key = "SUA_CHAVE_DE_API"
    analyzer = KernelAnalyzer(api_key)
    analyzer.save_reports()
