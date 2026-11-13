# Varredura ClamAV em lotes

## Qual problema resolve

Verificar discos com muitos arquivos pode levar horas, e uma interrupção ou um
erro em alguns arquivos dificulta saber o que já foi analisado e o que ainda
precisa de atenção. Além disso, tratar detecções manualmente e acompanhar os
resultados de novas varreduras exige trabalho repetitivo.

Esta ferramenta organiza a varredura de discos selecionados em lotes, registra
o progresso para permitir a retomada e reúne as detecções e pendências em
relatórios. Ela coloca as detecções em quarentena e inicia uma nova rodada após
o isolamento. Arquivos não analisados continuam registrados como pendências;
uma execução com pendências não garante que todo o conteúdo foi verificado.

**É obrigatório informar cada disco inteiro com `--disco`.** Não existe disco
padrão. O programa detecta as partições e registra identidade, UUIDs e formatos;
ele compara esses dados novamente durante a execução. Os nomes `/dev/sdX` podem
mudar após reconexões ou reinicialização: confira sempre o modelo e o número de
série com `lsblk` antes de iniciar. Use um caminho estável de `/dev/disk/by-id/`
quando disponível; o programa resolve o caminho para o dispositivo atual.
Quando não houver número de série ou WWN, a identificação depende dos demais
dados disponíveis, incluindo modelo, tamanho e UUIDs; clones podem compartilhar
esses dados. Confira fisicamente qual disco está conectado antes de selecioná-lo.

Formatos aceitos: NTFS, ext2/3/4, FAT (`vfat`), exFAT, XFS e Btrfs, desde que
o sistema tenha os respectivos drivers e ferramentas de montagem. O programa
recusa partições sem UUID ou com outros formatos, discos com LVM/criptografia
ou dispositivos aninhados e discos com qualquer volume já montado ou em swap.
Não escolhe uma partição individual. Um sistema de arquivos diretamente no
disco, sem partições, é aceito quando tiver UUID e formato suportado. Essas
restrições tornam a cobertura explícita; nem toda topologia de disco é aceita.

**A quarentena remove os originais depois de copiar e verificar o SHA-256.**
Ela inclui PUA e pode remover componentes do Windows ou programas legítimos,
inclusive por falso positivo. Um contêiner detectado, como ZIP, CAB ou MSI, é
isolado inteiro. Tenha um backup independente antes de usar em dados necessários.

## Requisitos e instalação no Linux

As instruções abaixo são para Linux Mint, Ubuntu e Debian com `apt` e systemd.
Esta máquina usa Linux Mint 21, Python 3.10, ClamAV 1.5.4 e NTFS-3G. Outros
Linux usam nomes de pacotes, serviços e ferramentas de montagem diferentes e
podem exigir adaptação; o programa foi preparado para `clamav-freshclam.service`
e os caminhos locais indicados abaixo.

Abra um terminal e instale:

```bash
sudo apt update
sudo apt install python3 clamav clamav-freshclam ntfs-3g util-linux systemd
```

Não há dependências Python externas nem necessidade de `pip`. São necessários
Python 3.9 ou posterior, acesso administrativo, os discos conectados e espaço
livre no disco do sistema para relatórios, base de assinaturas e quarentena.
Uma versão de ClamAV precisa aceitar as opções mostradas por `clamscan --help`;
versões diferentes podem ter comportamento e limites distintos.

Confira as versões e os discos:

```bash
python3 --version
clamscan --version
lsblk -o NAME,PATH,SIZE,FSTYPE,UUID,LABEL,MODEL,SERIAL,MOUNTPOINTS
```

O atualizador `clamav-freshclam` obtém as assinaturas via rede. Na execução
normal, o script interrompe temporariamente o serviço `clamav-freshclam` se ele
estiver ativo, executa `freshclam` e o reinicia. Se a atualização falhar, a
execução para antes de começar a varredura. A opção `--sem-atualizar` usa a base
instalada e deve ser reservada para quando essa limitação for aceitável.

## Antes de executar

1. Mantenha `clamav_loop.py` e `batch_state.py` juntos nesta pasta.
2. Confira os discos pelo número de série e UUID. Feche programas e janelas que
   os estejam usando e desmonte suas partições antes de iniciar. O script recusa
   discos montados e monta os volumes em `/mnt`, com escrita para a quarentena.
   Não selecione o disco do Linux em uso: ele está montado e será recusado.
3. Mantenha o computador ligado e sem suspensão; uma rodada pode levar muitas
   horas. Evite alterar os discos durante a tarefa.
4. Rode apenas uma instância. O script usa bloqueio para impedir outra instância
   dele mesmo, mas não impede outros programas de acessarem os discos.

## Iniciar e acompanhar

Para executar em primeiro plano:

```bash
sudo python3 "$HOME/clamav-loop/clamav_loop.py" --disco /dev/sdb
```

Para executar em segundo plano com systemd:

```bash
sudo systemd-run --unit=clamav-loop-lotes --property=Type=exec /usr/bin/python3 -u "$HOME/clamav-loop/clamav_loop.py" --disco /dev/sdb
```

Use apenas um dos comandos. Se a unidade já estiver ativa, acompanhe a execução
existente em vez de iniciar outra:

```bash
systemctl status clamav-loop-lotes.service --no-pager
sudo journalctl -fu clamav-loop-lotes.service
```

`Ctrl+C` fecha a visualização do `journalctl`; não para o serviço. Para solicitar
a interrupção do programa e a desmontagem das partições:

```bash
sudo systemctl kill --kill-who=main --signal=SIGINT clamav-loop-lotes.service
```

Espere o serviço encerrar antes de reiniciar. Após falha/interrupção, se a
unidade antiga continuar registrada, limpe seu estado de falha e inicie-a de
novo com o comando `systemd-run` acima:

```bash
sudo systemctl reset-failed clamav-loop-lotes.service
```

Os caminhos `/dev/sdb` acima são apenas exemplos. Para selecionar dois discos,
informe o parâmetro duas vezes, depois de confirmar a identidade de cada um:

```bash
sudo python3 "$HOME/clamav-loop/clamav_loop.py" --disco /dev/sda --disco /dev/sdb
```

Para retomar, use os mesmos discos e opções da tarefa interrompida. Os checkpoints
de tarefas diferentes são mantidos separadamente; a seleção de outros discos não
apaga o estado anterior. Alterações nas assinaturas, scanner, código, caminhos ou
opções de análise podem exigir uma nova tarefa e nova varredura.

O serviço transitório não reinicia automaticamente após reinicialização do
computador. Uma alternativa é retomar em primeiro plano com o comando Python.

## Lotes, retomada e pendências

Por padrão cada lote tem até 128 arquivos e uma meta de 512 MiB; um arquivo
maior que a meta fica sozinho. Depois de um lote confirmado, seus resultados
são gravados em SQLite. Na retomada, o lote interrompido é refeito e resultados
confirmados com metadados iguais são reutilizados na mesma rodada. A comparação
de metadados não é prova criptográfica de que um arquivo não foi alterado.

Após a quarentena, começa uma **nova rodada completa**. Por execução há limite
de cinco rodadas; se for atingido, consulte o resultado e execute novamente para
continuar. A base de assinaturas usada na tarefa é copiada e verificada. Mudanças
incompatíveis nas assinaturas, nas opções, no scanner ou no código podem exigir
nova varredura para manter os resultados consistentes.

Um lote com erro é dividido para localizar os arquivos problemáticos. Falhas
individuais ficam pendentes; três falhas consecutivas interrompem a execução para
evitar repetir um problema geral. Erros de montagem ou armazenamento também podem
interromper a execução. Os resultados já confirmados ficam no checkpoint.

Arquivos individuais acima de **2.000 MiB** são registrados como não analisados.
Arquivos criptografados e contêineres que excedem limites internos também ficam
pendentes. Lotes não eliminam o limite de tamanho por arquivo do ClamAV. O
programa não extrai contêineres nem descriptografa arquivos automaticamente.
Um resultado com pendências não significa que todos os arquivos foram analisados.

Exemplo para aumentar os limites de arquivos internos e profundidade, com maior
consumo de recursos:

```bash
sudo python3 "$HOME/clamav-loop/clamav_loop.py" --disco /dev/sdb --max-arquivos-internos 200000 --profundidade-arquivos 100
```

Consulte todas as opções com:

```bash
python3 "$HOME/clamav-loop/clamav_loop.py" --help
```

## Relatórios e quarentena

- Relatórios: `/var/log/clamav-loop/DATA-HORA/`. O caminho é mostrado ao iniciar.
- Quarentena e base congelada: `/var/lib/clamav-loop/`, acessível ao root.
- Checkpoint: `/var/lib/clamav-loop/checkpoint.sqlite3` e arquivos auxiliares
  SQLite. Não os exclua durante uma tarefa.
- `eventos.jsonl` registra eventos e erros; logs por lote contêm a saída do
  ClamAV. `RELATORIO.md`, `resumo.json` e `quarentena.csv` são gerados ao fim
  da execução. Os históricos JSON incluem lotes e quarentenas da tarefa ao
  longo de retomadas.

Para localizar relatórios:

```bash
sudo ls -lt /var/log/clamav-loop/
```

O arquivo `RESULTADO.txt` distingue conclusão sem detecções, pendências e
execução incompleta. Para inspecionar arquivos restritos, use `sudo` com o
caminho da execução. A cópia de quarentena preserva os bytes do arquivo, mas não
necessariamente ACLs, fluxos alternativos ou todos os metadados NTFS. Não há
restauração automática; revise os eventos antes de recuperar um arquivo.

A varredura examina os arquivos acessíveis nas partições montadas. Ela não
certifica firmware, espaço não alocado ou todos os recursos específicos do NTFS,
e não garante ausência absoluta de malware.
