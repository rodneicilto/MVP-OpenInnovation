Arquitetura Geral: O código segue uma arquitetura modular e orientada a objetos, centrada em uma classe principal chamada KernelAnalyzer. A classe encapsula a lógica do programa e organiza suas funcionalidades em métodos específicos para realizar tarefas isoladas. Além disso, há uso de integração com APIs externas (NVD/NIST) e manipulação de arquivos JSON para salvar os relatórios.

    Componentes Principais: Classe KernelAnalyzer, a classe principal gerencia toda a lógica de análise do sistema. Suas responsabilidades incluem:

    - Coletar informações sobre o Kernel Linux (versão do Kernel Linux, status de segurança).

    - Realizar verificações de segurança (MAC, DAC, PaX, GrSecurity, Secure Boot).

    - Consultar vulnerabilidades do Kernel Linux via API NIST.

    - Gerar relatórios JSON para análise e instruções de segurança.

    Atributos Principais:

    - api_key: Chave da API para autenticação no NIST.

    - hostname: Nome do host do equipamento, recuperado dinamicamente.
    
    - kernel_version: Versão atual do Kernel Linux.

    - latest_kernel_version: Última versão estável do Kernel Linux.

    - security_modes: Status dos modos de segurança.

    - patch_status: Verificação se o Kernel Linux está atualizado.

    - vulnerabilities: Lista de vulnerabilidades do Kernel Linux, consultadas na API do NIST.

    - instructions: Instruções para habilitar recursos de segurança desabilitados.

    Métodos Principais: Os métodos são organizados com responsabilidades específicas e focados na reutilização de código.

    Grupo 1: Métodos de Coleta de Informações

    - get_hostname(): Recupera o nome do host do equipamento.
 
    - get_kernel_version(): Obtém a versão do Kernel Linux em execução.

    - get_latest_kernel_version(): Consulta a última versão estável do Kernel Linux no site oficial kernel.org.

    Grupo 2: Métodos de Verificação de Segurança

    - check_mac_enabled(): Verifica se o SELinux ou AppArmor está habilitado.

    - check_dac_enabled(): Confirma se o controle DAC está ativo.

    - check_pax_enabled(): Analisa se o PaX está habilitado.

    - check_grsecurity_enabled(): Verifica se o GrSecurity está ativo.

    - check_secure_boot(): Verifica se o Secure Boot está ativado.

    - check_patches(): Compara a versão do Kernel Linux em uso com a versão mais recente disponível.

    Grupo 3: Métodos de Integração com APIs

    check_kernel_vulnerabilities():
        Faz uma consulta à API do NIST (usando uma chave de API) para buscar vulnerabilidades do Kernel Linux.
        Realiza até três tentativas em caso de falhas, com um atraso entre as tentativas.
        Filtra vulnerabilidades relevantes "Medium" e "High".

    Grupo 4: Geração de Relatórios

    generate_security_instructions():
        Gera instruções para habilitar recursos de segurança desativados.
    analyze():
        Consolida todas as informações coletadas em um dicionário estruturado.
    save_reports():
        Salva dois arquivos JSON no disco:
            Análise completa do sistema (estado atual e vulnerabilidades).
            Instruções de segurança para habilitar recursos desativados.

Grupo 5: Utilitários

    run_command():
        Método reutilizável para executar comandos de shell e capturar a saída.
