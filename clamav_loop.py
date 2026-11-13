#!/usr/bin/env python3
"""Loop local ClamAV: varrer, copiar/verificar/quarentenar, repetir.
Executar com sudo. Não executa arquivos dos discos examinados.
"""
import argparse
import csv
import datetime as dt
import fcntl
import hashlib
import json
import os
import re
import platform
import signal
from pathlib import Path
import shutil
import stat
import subprocess as sp
import sys
import tempfile
import threading
import time
import traceback
from batch_state import Store, fingerprint, frozen_database

AUDIT = None
AUDIT_DIR = None
COMMAND_NUMBER = 0

SUPPORTED_FILESYSTEMS = {'ntfs': 'ntfs-3g', 'ext2': 'ext2', 'ext3': 'ext3',
                         'ext4': 'ext4', 'vfat': 'vfat', 'exfat': 'exfat',
                         'xfs': 'xfs', 'btrfs': 'btrfs'}
SCAN_OPTIONS = [
    '--recursive=yes', '--cross-fs=no', '--follow-dir-symlinks=0',
    '--follow-file-symlinks=0', '--detect-pua=yes', '--alert-exceeds-max=yes',
    '--alert-encrypted=yes', '--max-filesize=2000M', '--max-scansize=2000M',
    '--max-files=100000', '--max-recursion=50', '--max-dir-recursion=1000',
    '--max-scantime=0',
]


def command(args, **kw):
    global COMMAND_NUMBER
    COMMAND_NUMBER += 1
    number = COMMAND_NUMBER
    start = time.monotonic()
    if AUDIT:
        AUDIT('comando_inicio', numero=number, comando=args,
              stdout_arquivo=getattr(kw.get('stdout'), 'name', None))
    kw.setdefault('text', True)
    kw.setdefault('check', True)
    if not any(k in kw for k in ('stdout', 'stderr', 'capture_output')):
        kw['capture_output'] = True
    try:
        result = sp.run(args, **kw)
    except BaseException as exc:
        if AUDIT:
            save_command_output(number, getattr(exc, 'stdout', None),
                                getattr(exc, 'stderr', None))
            AUDIT('comando_erro', numero=number, comando=args,
                  duracao_s=round(time.monotonic() - start, 3),
                  codigo=getattr(exc, 'returncode', None), erro=repr(exc))
        raise
    if AUDIT:
        save_command_output(number, result.stdout, result.stderr)
        AUDIT('comando_fim', numero=number, comando=args, codigo=result.returncode,
              duracao_s=round(time.monotonic() - start, 3))
    return result


def save_command_output(number, stdout, stderr):
    for name, content in (('stdout', stdout), ('stderr', stderr)):
        if content is not None:
            file = AUDIT_DIR / f'comando-{number:05d}-{name}.txt'
            file.write_text(content if isinstance(content, str)
                            else content.decode('utf-8', errors='replace'))
            file.chmod(0o644)


def scan_command(args, log, event):
    """Saída original, uma cópia com horário por linha, pulso a cada 60 s."""
    started = time.monotonic()
    state = {'linhas': 0, 'ultima_linha': None, 'erro': None}
    timed = log.with_suffix('.linhas.jsonl')
    process = sp.Popen(args, stdout=sp.PIPE, stderr=sp.STDOUT)
    try:
        event('scanner_processo', comando=args, pid=process.pid, log=str(log),
              log_com_horarios=str(timed))
    except BaseException:
        process.terminate()
        process.wait()
        process.stdout.close()
        raise
    def consume():
        try:
            with log.open('wb') as raw, timed.open('w') as timestamps:
                for line in iter(process.stdout.readline, b''):
                    raw.write(line)
                    raw.flush()
                    state['linhas'] += 1
                    state['ultima_linha'] = line.decode('utf-8', errors='replace').rstrip('\n')
                    timestamps.write(json.dumps(dict(
                        hora=dt.datetime.now().astimezone().isoformat(),
                        linha=state['linhas'], texto=state['ultima_linha']),
                        ensure_ascii=True) + '\n')
                    timestamps.flush()
                raw.flush()
                os.fsync(raw.fileno())
                timestamps.flush()
                os.fsync(timestamps.fileno())
        except BaseException as exc:
            state['erro'] = repr(exc)
    thread = threading.Thread(target=consume, daemon=True)
    thread.start()
    try:
        while True:
            try:
                code = process.wait(timeout=60)
                break
            except sp.TimeoutExpired:
                event('scanner_ativo', pid=process.pid,
                      duracao_s=round(time.monotonic() - started, 3),
                      linhas=state['linhas'], ultima_linha=state['ultima_linha'],
                      espaco_livre_logs=shutil.disk_usage(log.parent).free)
                if state['erro']:
                    raise RuntimeError(f'Falha de gravação dos logs: {state["erro"]}')
        thread.join(timeout=10)
        if thread.is_alive() or state['erro']:
            raise RuntimeError(f'Log incompleto: {state["erro"]}')
        event('scanner_encerrado', pid=process.pid, codigo=code,
              duracao_s=round(time.monotonic() - started, 3), linhas=state['linhas'])
        return code
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=15)
            except sp.TimeoutExpired:
                process.kill()
                process.wait()
            event('scanner_interrompido', pid=process.pid, codigo=process.returncode)
        thread.join(timeout=10)
        process.stdout.close()
        for file in (log, timed):
            if file.exists():
                file.chmod(0o644)


def scan_batches(store, part, root, files, run, options, args, event):
    """Só confirma um lote após sucesso e conferência dos metadados de entrada."""
    results, todo = {}, []
    for rel, fp, size in files:
        if size > 2000 * 1024**2:
            results[rel] = dict(deteccoes=[], pendencias=['Arquivo acima de 2000 MiB; não analisado'], log=None)
            continue
        cached = store.cached(part, rel, fp)
        if cached is not None:
            results[rel] = cached
        else:
            todo.append((rel, fp, size))
    event('lotes_planejados', tarefa=store.job, rodada=store.round, particao=part,
          arquivos_reaproveitados=len(results), arquivos_pendentes=len(todo))
    groups, batch, total = [], [], 0
    for item in todo:
        if batch and (len(batch) >= args.lote_arquivos or
                      total + item[2] > args.lote_mib * 1024**2):
            groups.append(batch)
            batch, total = [], 0
        batch.append(item)
        total += item[2]
    if batch:
        groups.append(batch)
    index = 0
    failures = 0
    while groups:
        batch = groups.pop(0)
        index += 1
        prefix = f'rodada-{store.round}-{Path(part).name}-lote-{index:05d}'
        listing = run / f'{prefix}.lista.txt'
        listing.write_text(''.join(str(root / rel) + '\n' for rel, _, _ in batch))
        log = run / f'{prefix}.log'
        token = store.batch_start(part, batch, log)
        event('lote_inicio', tarefa=store.job, rodada=store.round, particao=part,
              lote=token, arquivos=len(batch), bytes=sum(x[2] for x in batch),
              lista=str(listing), log=str(log))
        code = scan_command(['clamscan', *options, '--file-list=' + str(listing)], log, event)
        text = log.read_text(errors='replace')
        # ClamAV 1.5 pode devolver 2 para um único arquivo maior que o limite,
        # com aviso MaxFileSize e erro "Virus(es) detected". É pendência,
        # não resultado limpo; outros erros continuam interrompendo a tarefa.
        one_path = str(root / batch[0][0]) if len(batch) == 1 else ''
        lines = text.splitlines()
        limited = (code == 2 and len(batch) == 1 and
                   f'{one_path}: Heuristics.Limits.Exceeded.MaxFileSize FOUND' in lines and
                   f'{one_path}: Virus(es) detected ERROR' in lines and
                   all('ERROR' not in line or line == f'{one_path}: Virus(es) detected ERROR'
                       for line in lines) and
                   re.search(r'^Total errors:\s*1\s*$', text, re.M))
        if (code not in (0, 1) and not limited) or 'SCAN SUMMARY' not in text:
            store.batch_failed(token)
            event('lote_falhou', lote=token, particao=part, codigo=code, log=str(log), arquivos=len(batch))
            if len(batch) > 1:
                middle = len(batch) // 2
                groups[0:0] = [batch[:middle], batch[middle:]]
                continue
            rel, fp, _ = batch[0]
            result = dict(deteccoes=[], pendencias=[f'Erro do scanner, código {code}; análise incompleta'],
                          log=str(log), retryable=True)
            token2 = store.batch_start(part, batch, log)
            store.batch_done(token2, part, [(rel, fp, result)])
            results[rel] = result
            failures += 1
            if failures >= 3:
                raise RuntimeError('Três arquivos consecutivos falharam; interrompido para evitar falha geral repetitiva')
            continue
        failures = 0
        known = {str(root / rel): rel for rel, _, _ in batch}
        records = {rel: dict(deteccoes=[], pendencias=[], log=str(log)) for rel, _, _ in batch}
        seen, warnings = set(), []
        for line in text.splitlines():
            if not line.endswith(': OK') and re.search(r'\b(error|errors|warning|warnings)\b', line, re.I):
                warnings.append(line)
            if ': ' in line:
                name, status = line.rsplit(': ', 1)
                rel = known.get(name)
                if rel is not None:
                    seen.add(rel)
                    if status.endswith(' FOUND'):
                        signature = status[:-6]
                        key = ('pendencias' if signature.startswith(
                            ('Heuristics.Limits.', 'Heuristics.Encrypted.')) else 'deteccoes')
                        records[rel][key].append(signature)
                    elif status not in ('OK', 'Empty file', 'Empty file.'):
                        records[rel]['pendencias'].append(status)
                elif line.endswith(' FOUND'):
                    raise RuntimeError(f'Detecção com caminho fora do lote: {line}')
        records[batch[0][0]]['pendencias'].extend(warnings)
        for rel, fp, _ in batch:
            try:
                changed = fingerprint(root / rel) != fp
            except OSError:
                changed = True
            if changed:
                records[rel] = dict(deteccoes=[], pendencias=['Arquivo mudou ou ficou inacessível durante a varredura'], log=str(log), retryable=True)
            if rel not in seen:
                records[rel]['pendencias'].append('Scanner não confirmou resultado individual')
                records[rel]['retryable'] = True
        store.batch_done(token, part, [(rel, fp, records[rel]) for rel, fp, _ in batch])
        results.update(records)
        event('lote_fim', tarefa=store.job, rodada=store.round, particao=part, lote=token)
    detections, pending = {}, []
    for rel, result in results.items():
        for signature in result['deteccoes']:
            detections[root / rel] = (part, root, signature)
            event('deteccao', rodada=store.round, particao=part, original=rel,
                  deteccao=signature, log_origem=result['log'])
        for reason in result['pendencias']:
            item = dict(particao=part, caminho=rel, motivo=reason, log_origem=result['log'])
            pending.append(item)
            event('pendencia_arquivo', rodada=store.round, **item)
    return detections, pending


def export_reports(run, outcome):
    items = [json.loads(line) for line in (run / 'eventos.jsonl').read_text().splitlines()]
    fields = ['hora', 'evento', 'rodada', 'particao', 'original', 'deteccao',
              'destino', 'sha256', 'tamanho', 'duracao_s', 'detalhe']
    with (run / 'quarentena.csv').open('w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        for item in items:
            if item.get('original') is not None:
                # Evitar interpretação de nomes de arquivo como fórmulas em planilhas.
                writer.writerow({k: ("'" + v if isinstance(v, str) and
                    v.startswith(('=', '+', '-', '@', '\t', '\r')) else v)
                    for k, v in item.items()})
    errors = [i for i in items if i['evento'] in
              ('erro', 'comando_erro', 'falha_desmontagem', 'interrompido')]
    summary = dict(resultado=outcome, inicio=items[0]['hora'], fim=items[-1]['hora'],
                   arquivos_quarentenados=sum(i['evento'] == 'quarentenado' for i in items),
                   erros=errors, rodadas=[i for i in items if i['evento'] == 'resultado_rodada'],
                   lotes=[i for i in items if i['evento'] == 'lotes_planejados'])
    (run / 'resumo.json').write_text(json.dumps(summary, ensure_ascii=True, indent=2))
    (run / 'RELATORIO.md').write_text(
        '# Relatório ClamAV\n\n' + f'Resultado: **{outcome}**\n\n' +
        f'Início: {summary["inicio"]}  \nFim: {summary["fim"]}\n\n' +
        f'Arquivos com retirada confirmada: {summary["arquivos_quarentenados"]}\n\n' +
        'Eventos completos: eventos.jsonl. Operações por arquivo: quarentena.csv.\n'
        'Inventários registram metadados, não comprovação de inspeção interna.\n'
        'O horário por linha registra o recebimento da saída do scanner; pode haver buffering.\n\n' +
        '## Rodadas\n\n' + ''.join(f'- Rodada {i["rodada"]}: '
            f'{i["deteccoes"]} arquivos detectados; {i["pendencias"]} pendências.\n'
            for i in summary['rodadas']) + '\n## Erros e interrupções\n\n' +
        ('```json\n' + json.dumps(errors, ensure_ascii=True, indent=2) + '\n```\n'
         if errors else 'Nenhum erro de execução registrado. Consulte também as pendências.\n'))
    for name in ('quarentena.csv', 'resumo.json', 'RELATORIO.md'):
        (run / name).chmod(0o644)


def secure_dir(path, mode):
    path.mkdir(mode=mode, parents=True, exist_ok=True)
    st = path.lstat()
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or st.st_mode & 0o022:
        raise RuntimeError(f'Diretório administrativo inseguro: {path}')


def inspect_disks(disks):
    data = json.loads(command(['lsblk', '-J', '-p', '-o',
        'PATH,TYPE,FSTYPE,UUID,SERIAL,WWN,PKNAME,SIZE,MODEL'], capture_output=True).stdout)
    flat = {}
    def visit(items):
        for item in items:
            flat[item['path']] = item
            visit(item.get('children', []))
    visit(data['blockdevices'])
    result = {}
    uuids = set()
    for disk in disks:
        device = flat.get(disk, {})
        if device.get('type') != 'disk':
            raise RuntimeError(f'Informe um disco físico inteiro, não uma partição: {disk}')
        children = {p: v for p, v in flat.items() if v.get('pkname') == disk}
        if any(v.get('type') != 'part' for v in children.values()):
            raise RuntimeError(f'Topologia não suportada no disco {disk}')
        for child in children:
            if any(v.get('pkname') == child for v in flat.values()):
                raise RuntimeError(f'Disco contém dispositivos aninhados (LVM/criptografia): {disk}')
        if children and device.get('fstype'):
            raise RuntimeError(f'Sistema de arquivos e partições coexistem em {disk}')
        volumes = children or {disk: device}
        parts = {}
        for part, item in sorted(volumes.items()):
            uuid, fstype = item.get('uuid'), item.get('fstype')
            if not uuid or fstype not in SUPPORTED_FILESYSTEMS:
                raise RuntimeError(f'Volume sem UUID ou formato não suportado: {part} ({fstype})')
            if uuid in uuids:
                raise RuntimeError(f'UUID duplicado entre volumes selecionados: {uuid}')
            uuids.add(uuid)
            parts[part] = {'uuid': uuid, 'fstype': fstype, 'size': item.get('size')}
        result[disk] = {'serial': device.get('serial'), 'wwn': device.get('wwn'),
                        'model': device.get('model'), 'size': device.get('size'), 'volumes': parts}
    return result


def identity(expected):
    actual = inspect_disks(sorted(expected))
    if actual != expected:
        raise RuntimeError('Identidade, topologia, UUID ou formato dos discos mudou; execução interrompida')


def ensure_unmounted(expected):
    volumes = {part for disk, info in expected.items()
               for part in (disk, *info['volumes'])}
    # findmnt resolve sistemas FUSE como ntfs-3g pelo nome da fonte.
    out = command(['findmnt', '-rn', '-o', 'SOURCE,TARGET'], capture_output=True).stdout
    for line in out.splitlines():
        source, _, target = line.partition(' ')
        source = source.split('[', 1)[0]
        if source.startswith('/dev/') and os.path.realpath(source) in volumes:
            raise RuntimeError(f'Disco selecionado está montado em {target.strip()}; desmonte-o primeiro')
    for line in Path('/proc/swaps').read_text().splitlines()[1:]:
        source = line.split()[0]
        if source.startswith('/dev/') and os.path.realpath(source) in volumes:
            raise RuntimeError(f'Disco selecionado está em uso como swap: {source}')


def sha(path):
    h = hashlib.sha256()
    with path.open('rb') as f:
        for block in iter(lambda: f.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def main():
    global AUDIT, AUDIT_DIR
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--disco', action='append', required=True, metavar='DISPOSITIVO',
                        help='disco inteiro, por exemplo /dev/sdb; repita para selecionar mais de um')
    parser.add_argument('--max-rodadas', type=int, default=5,
                        help='limite de segurança; padrão: 5')
    parser.add_argument('--sem-atualizar', action='store_true',
                        help='usar assinaturas instaladas; registrar essa limitação')
    parser.add_argument('--max-arquivos-internos', type=int, default=100000,
                        help='limite por contêiner; aumentar consome mais recursos')
    parser.add_argument('--profundidade-arquivos', type=int, default=50,
                        help='profundidade de arquivos compactados, 1 a 100')
    parser.add_argument('--lote-arquivos', type=int, default=128,
                        help='máximo de arquivos por lote (padrão: 128)')
    parser.add_argument('--lote-mib', type=int, default=512,
                        help='meta de tamanho por lote; arquivo maior fica sozinho')
    args = parser.parse_args()
    if args.max_rodadas < 1:
        parser.error('--max-rodadas precisa ser positivo')
    if args.lote_arquivos < 1 or args.lote_mib < 1:
        parser.error('tamanho e quantidade de arquivos por lote precisam ser positivos')
    if args.max_arquivos_internos < 1 or not 1 <= args.profundidade_arquivos <= 100:
        parser.error('limites inválidos: arquivos internos >= 1, profundidade de 1 a 100')
    scan_options = [s for s in SCAN_OPTIONS if not s.startswith(
        ('--max-files=', '--max-recursion='))] + [
        f'--max-files={args.max_arquivos_internos}',
        f'--max-recursion={args.profundidade_arquivos}']
    if os.geteuid() != 0:
        parser.error('execute com sudo python3 clamav_loop.py')
    os.environ['PATH'] = '/usr/sbin:/usr/bin:/sbin:/bin'
    os.environ['LC_ALL'] = 'C'
    os.umask(0o077)
    stamp = dt.datetime.now().strftime('%Y%m%d-%H%M%S-%f')
    reports = Path('/var/log/clamav-loop')
    quarantine = Path('/var/lib/clamav-loop')
    secure_dir(reports, 0o755)
    reports.chmod(0o755)
    secure_dir(quarantine, 0o700)
    run = reports / stamp
    run.mkdir(mode=0o755)
    run.chmod(0o755)
    qrun = quarantine / stamp
    qrun.mkdir(mode=0o700)
    shutil.copyfile(Path(__file__), run / 'script-executado.py')
    (run / 'script-executado.py').chmod(0o644)
    helper = Path(__file__).with_name('batch_state.py')
    shutil.copyfile(helper, run / 'batch_state-executado.py')
    journal = run / 'eventos.jsonl'
    def event(kind, **fields):
        item = dict(hora=dt.datetime.now().astimezone().isoformat(),
                    monotonic_s=time.monotonic(), pid_executor=os.getpid(), evento=kind, **fields)
        with journal.open('a') as f:
            f.write(json.dumps(item, ensure_ascii=True) + '\n')
            f.flush()
            os.fsync(f.fileno())
        journal.chmod(0o644)
        print(json.dumps(item, ensure_ascii=False), flush=True)
    print(f'Relatórios: {run}\nQuarentena: {qrun}', flush=True)
    AUDIT, AUDIT_DIR = event, run
    mounts = []
    outcome = 'INCOMPLETO'
    def interrupted(*_):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    lock = None
    store = None
    event('execucao_inicio', argumentos=vars(args),
          python=sys.version, sistema=platform.platform(), opcoes_clamav=scan_options,
          script_sha256=sha(Path(__file__)), quarentena=str(qrun))
    try:
        for tool in ('clamscan', 'freshclam', 'lsblk', 'findmnt', 'mount',
                     'umount', 'systemctl'):
            if not shutil.which(tool):
                raise RuntimeError(f'Programa ausente: {tool}')
        lock = open('/run/lock/clamav-loop.lock', 'a')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        disks = sorted(os.path.realpath(p) for p in args.disco)
        if len(disks) != len(set(disks)) or any(not p.startswith('/dev/') for p in disks):
            raise RuntimeError('Discos duplicados ou fora de /dev')
        for disk in disks:
            if not stat.S_ISBLK(os.stat(disk).st_mode):
                raise RuntimeError(f'Não é dispositivo de bloco: {disk}')
        expected = inspect_disks(disks)
        if any(v['fstype'] == 'ntfs' for d in expected.values() for v in d['volumes'].values()):
            if not shutil.which('ntfs-3g'):
                raise RuntimeError('NTFS selecionado, mas ntfs-3g não está instalado')
        ensure_unmounted(expected)
        event('discos_selecionados', discos=expected)
        command(['findmnt', '-J'])
        command(['df', '-h'])
        if not args.sem_atualizar:
            active = command(['systemctl', 'is-active', '--quiet',
                             'clamav-freshclam.service'], check=False).returncode == 0
            try:
                if active:
                    command(['systemctl', 'stop', 'clamav-freshclam.service'])
                with (run / 'atualizacao.log').open('w') as f:
                    event('atualizacao_inicio', log=str(run / 'atualizacao.log'))
                    command(['freshclam'], stdout=f, stderr=sp.STDOUT)
            finally:
                if active:
                    command(['systemctl', 'start', 'clamav-freshclam.service'])
        event('assinaturas', versao=command(['clamscan', '--version'],
              capture_output=True).stdout.strip(), atualizacao=not args.sem_atualizar)
        database, hashes = frozen_database(Path('/var/lib/clamav'), quarantine)
        identity(expected)
        ensure_unmounted(expected)
        config = dict(alvos=expected, opcoes=scan_options, assinaturas=hashes,
                      scanner_sha256=sha(Path(shutil.which('clamscan'))),
                      script_sha256=sha(Path(__file__)), helper_sha256=sha(helper))
        store = Store(quarantine / 'checkpoint.sqlite3', config, event)
        scan_options = [*scan_options, '--database=' + str(database)]
        event('base_congelada', caminho=str(database), sha256=hashes,
              checkpoint=str(quarantine / 'checkpoint.sqlite3'), tarefa=store.job)
        for info in expected.values():
            for part, volume in info['volumes'].items():
                identity(expected)
                root = Path(tempfile.mkdtemp(prefix='clamav-loop-', dir='/mnt'))
                command(['mount', '-t', SUPPORTED_FILESYSTEMS[volume['fstype']], '-o', 'rw,nosuid,nodev,noexec',
                         part, str(root)])
                mounts.append((part, root))
                mounted_source = command(['findmnt', '-n', '-M', str(root), '-o', 'SOURCE'],
                                         capture_output=True).stdout.strip().split('[', 1)[0]
                if os.path.realpath(mounted_source) != part:
                    raise RuntimeError(f'Fonte montada divergente: {mounted_source}, esperado {part}')
                opts = command(['findmnt', '-n', '-M', str(root), '-o', 'OPTIONS'],
                               capture_output=True).stdout.strip().split(',')
                if 'rw' not in opts:
                    raise RuntimeError(f'{part} não permite quarentena (somente leitura)')
                event('particao_montada', particao=part, caminho=str(root), opcoes=opts)
        roots = dict(mounts)
        for part, rel, dest, expected_hash, state in store.copies():
            if part not in roots or not Path(rel).is_relative_to('.') or '..' in Path(rel).parts:
                raise RuntimeError('Caminho inválido no checkpoint de quarentena')
            source = roots[part] / rel
            if not source.exists():
                if not Path(dest).is_file() or sha(Path(dest)) != expected_hash:
                    raise RuntimeError(f'Quarentena ausente ou divergente na retomada: {dest}')
                store.copy_state(part, rel, dest, expected_hash, 'removed')
                event('quarentena_confirmada_na_retomada', particao=part,
                      original=rel, destino=dest, sha256=expected_hash, estado_anterior=state)
        for rodada in range(store.round, store.round + args.max_rodadas):
            identity(expected)
            detections = {}
            pending = []
            for part, root in mounts:
                event('varredura_inicio', rodada=rodada, particao=part)
                # Saída ClamAV é baseada em linhas: recusar nomes ambíguos.
                def walk_error(exc):
                    raise exc
                inventory = run / f'rodada-{rodada}-{Path(part).name}-inventario.jsonl'
                files = []
                with inventory.open('w') as inv:
                    for parent, dirs, names in os.walk(root, onerror=walk_error):
                        dirs.sort()
                        for name in sorted(dirs + names):
                            if '\n' in name or '\r' in name:
                                raise RuntimeError(f'Nome incompatível com log: {name!r}')
                            path = Path(parent) / name
                            st = path.lstat()
                            inv.write(json.dumps(dict(hora=dt.datetime.now().astimezone().isoformat(),
                                particao=part, caminho=str(path.relative_to(root)),
                                tamanho=st.st_size, inode=st.st_ino, modo=st.st_mode,
                                uid=st.st_uid, gid=st.st_gid, mtime_ns=st.st_mtime_ns,
                                ctime_ns=st.st_ctime_ns, link=path.is_symlink()),
                                ensure_ascii=True) + '\n')
                            if stat.S_ISREG(st.st_mode):
                                files.append((str(path.relative_to(root)), fingerprint(path), st.st_size))
                inventory.chmod(0o644)
                found, unresolved = scan_batches(store, part, root, files, run,
                                                  scan_options, args, event)
                detections.update(found)
                pending.extend(unresolved)
                event('varredura_fim', rodada=rodada, particao=part,
                      arquivos=len(files), deteccoes=len(found), pendencias=len(unresolved))
            pending_file = run / f'rodada-{rodada}-pendencias.json'
            pending_file.write_text(json.dumps(pending, ensure_ascii=True, indent=2))
            pending_file.chmod(0o644)
            with (run / f'rodada-{rodada}-deteccoes.json').open('w') as f:
                json.dump([dict(particao=p, original=str(src.relative_to(root)), deteccao=sig)
                    for src, (p, root, sig) in detections.items()], f, ensure_ascii=True, indent=2)
            event('resultado_rodada', rodada=rodada,
                  deteccoes=len(detections), pendencias=len(pending))
            if not detections:
                if store.phase == 'quarantine':
                    # Retomada após retirada dos últimos infectados: ainda falta
                    # uma rodada realmente nova, sem usar os resultados antigos.
                    store.next_round()
                    continue
                outcome = ('SEM_DETECCOES_COM_PENDENCIAS' if pending
                           else 'CONCLUIDO_SEM_DETECCOES')
                store.finish('done' if not pending else 'pending')
                break
            store.quarantining()
            needed = sum(p.stat().st_size for p in detections)
            if shutil.disk_usage(qrun).free < needed + 1024**3:
                raise RuntimeError('Espaço insuficiente para quarentena e margem de 1 GiB')
            for source, (part, root, signature) in detections.items():
                identity(expected)
                started_file = time.monotonic()
                context = dict(rodada=rodada, particao=part,
                               original=str(source.relative_to(root)), deteccao=signature)
                event('quarentena_inicio', **context)
                if source.is_symlink() or source.resolve() != source:
                    raise RuntimeError(f'Link encontrado na quarentena: {source}')
                original = source.stat()
                if not stat.S_ISREG(original.st_mode):
                    raise RuntimeError(f'Não é arquivo regular: {source}')
                dest = qrun / f'rodada-{rodada}' / Path(part).name / source.relative_to(root)
                dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                before = sha(source)
                previous = store.get_copy(part, str(source.relative_to(root)))
                if previous and Path(previous[0]).is_file():
                    old_dest, old_hash, _ = previous
                    if old_hash == before and sha(Path(old_dest)) == before:
                        dest = Path(old_dest)
                        event('copia_reutilizada', **context, destino=str(dest), sha256=before)
                    else:
                        raise RuntimeError(f'Cópia anterior divergente; original preservado: {source}')
                event('copia_inicio', **context, destino=str(dest), tamanho=original.st_size,
                      sha256=before, inode=original.st_ino, mtime_ns=original.st_mtime_ns,
                      modo=original.st_mode)
                if not previous or dest != Path(previous[0]):
                    with source.open('rb') as src, dest.open('xb') as dst:
                        shutil.copyfileobj(src, dst, 1024 * 1024)
                        dst.flush()
                        os.fsync(dst.fileno())
                after = source.stat()
                if (original.st_ino, original.st_size, original.st_mtime_ns) != (
                        after.st_ino, after.st_size, after.st_mtime_ns):
                    raise RuntimeError(f'Arquivo mudou durante a cópia: {source}')
                if before != sha(dest) or before != sha(source):
                    raise RuntimeError(f'Hash divergente; original preservado: {source}')
                dest.chmod(0)
                event('copia_verificada', **context,
                      destino=str(dest), sha256=before, tamanho=original.st_size)
                store.copy_state(part, str(source.relative_to(root)), dest, before, 'verified')
                event('remocao_inicio', **context, destino=str(dest), sha256=before)
                source.unlink()
                if source.exists():
                    raise RuntimeError(f'Não foi possível remover: {source}')
                event('quarentenado', **context, destino=str(dest), tamanho=original.st_size,
                      sha256=before, duracao_s=round(time.monotonic() - started_file, 3))
                store.copy_state(part, str(source.relative_to(root)), dest, before, 'removed')
            os.sync()
            store.next_round()
        else:
            outcome = 'LIMITE_DE_RODADAS_REQUER_NOVA_VARREDURA'
    except KeyboardInterrupt:
        event('interrompido')
    except Exception as exc:
        event('erro', detalhe=str(exc), tipo=type(exc).__name__, traceback=traceback.format_exc())
    finally:
        for part, root in reversed(mounts):
            try:
                command(['umount', '--', str(root)])
                root.rmdir()
            except Exception as exc:
                outcome = 'INCOMPLETO'
                event('falha_desmontagem', particao=part, detalhe=str(exc))
        event('fim', resultado=outcome)
        result = run / 'RESULTADO.txt'
        result.write_text(outcome + '\nConsulte eventos.jsonl, logs e pendências.\n')
        result.chmod(0o644)
        if store is not None:
            store.export(run)
        export_reports(run, outcome)
        # Permite conferir alterações acidentais nos relatórios posteriormente.
        # Não é assinatura digital nem proteção contra alteração por root.
        manifest = {p.name: sha(p) for p in run.iterdir() if p.is_file()}
        manifest_path = run / 'SHA256-relatorios.json'
        manifest_path.write_text(json.dumps(manifest, ensure_ascii=True, indent=2))
        manifest_path.chmod(0o644)
        AUDIT = None
        if lock is not None:
            lock.close()
        if store is not None:
            store.close()
    return 0 if outcome == 'CONCLUIDO_SEM_DETECCOES' else 2


if __name__ == '__main__':
    sys.exit(main())
