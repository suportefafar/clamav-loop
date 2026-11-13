"""Checkpoints duráveis por lote; conteúdo identificado por metadados e base congelada."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import sqlite3
import time


def digest(path):
    h = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            h.update(block)
    return h.hexdigest()


def fingerprint(path):
    s = path.lstat()
    return json.dumps([s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns,
                       s.st_mode, s.st_nlink])


def atomic_json(path, value):
    tmp = path.with_suffix('.tmp')
    with tmp.open('w') as f:
        json.dump(value, f, ensure_ascii=True, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def frozen_database(base, parent):
    extensions = {'.cvd', '.cld', '.cud', '.sign', '.hdb', '.hsb', '.mdb',
                  '.msb', '.ndb', '.ldb', '.sfp', '.fp', '.ign', '.ign2',
                  '.yar', '.yara', '.cbc', '.crb', '.cat', '.pdb', '.wdb', '.idb'}
    files = sorted(p for p in base.iterdir() if p.is_file() and p.suffix in extensions)
    if not files:
        raise RuntimeError(f'Nenhuma base de assinaturas em {base}')
    hashes = {p.name: digest(p) for p in files}
    key = hashlib.sha256(json.dumps(hashes, sort_keys=True).encode()).hexdigest()
    target = parent / 'bases' / key
    target.mkdir(parents=True, exist_ok=True, mode=0o700)
    for source in files:
        dest = target / source.name
        if not dest.exists() or digest(dest) != hashes[source.name]:
            tmp = dest.with_suffix(dest.suffix + '.tmp')
            shutil.copyfile(source, tmp)
            with tmp.open('rb') as f:
                os.fsync(f.fileno())
            if digest(tmp) != hashes[source.name]:
                raise RuntimeError('Assinaturas mudaram durante a cópia; repetir execução')
            os.replace(tmp, dest)
    atomic_json(target / 'manifesto.json', hashes)
    return target, hashes


class Store:
    def __init__(self, path, config, event):
        self.event = event
        self.db = sqlite3.connect(path)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.executescript('''
          CREATE TABLE IF NOT EXISTS jobs (
            id INTEGER PRIMARY KEY, config TEXT, round INTEGER, status TEXT, phase TEXT);
          CREATE TABLE IF NOT EXISTS files (
            job INTEGER, round INTEGER, part TEXT, path TEXT, fp TEXT, result TEXT,
            PRIMARY KEY(job,round,part,path));
          CREATE TABLE IF NOT EXISTS copies (
            job INTEGER, round INTEGER, part TEXT, path TEXT, dest TEXT,
            hash TEXT, state TEXT, PRIMARY KEY(job,round,part,path));
          CREATE TABLE IF NOT EXISTS batches (
            id INTEGER PRIMARY KEY, job INTEGER, round INTEGER, part TEXT,
            started REAL, finished REAL, status TEXT, manifest TEXT, log TEXT);
        ''')
        canonical = json.dumps(config, sort_keys=True)
        latest = self.db.execute(
            'SELECT id,config,round,status,phase FROM jobs WHERE config=? ORDER BY id DESC LIMIT 1',
            (canonical,)).fetchone()
        if latest and latest[3] in ('active', 'pending'):
            self.job, _, self.round, _, self.phase = latest
            with self.db:
                self.db.execute('UPDATE jobs SET status=? WHERE id=?', ('active', self.job))
            event('checkpoint_retomado', tarefa=self.job, rodada=self.round)
        else:
            cur = self.db.execute('INSERT INTO jobs(config,round,status,phase) VALUES (?,1,?,?)',
                                  (canonical, 'active', 'scan'))
            self.job, self.round, self.phase = cur.lastrowid, 1, 'scan'
            self.db.commit()
            event('checkpoint_novo', tarefa=self.job, rodada=1)

    def cached(self, part, rel, fp):
        row = self.db.execute('SELECT fp,result FROM files WHERE job=? AND round=? AND part=? AND path=?',
                              (self.job, self.round, part, rel)).fetchone()
        if not row or row[0] != fp:
            return None
        result = json.loads(row[1])
        return None if result.get('retryable') else result

    def batch_start(self, part, manifest, log):
        cur = self.db.execute('INSERT INTO batches(job,round,part,started,status,manifest,log) VALUES (?,?,?,?,?,?,?)',
            (self.job, self.round, part, time.time(), 'running', json.dumps(manifest), str(log)))
        self.db.commit()
        return cur.lastrowid

    def batch_done(self, batch, part, results):
        with self.db:
            for rel, fp, result in results:
                self.db.execute('INSERT OR REPLACE INTO files VALUES (?,?,?,?,?,?)',
                                (self.job, self.round, part, rel, fp, json.dumps(result)))
            self.db.execute('UPDATE batches SET status=?,finished=? WHERE id=?', ('done', time.time(), batch))
        self.event('checkpoint_lote_gravado', tarefa=self.job, rodada=self.round,
                   lote=batch, arquivos=len(results))

    def batch_failed(self, batch):
        with self.db:
            self.db.execute('UPDATE batches SET status=?,finished=? WHERE id=?', ('failed', time.time(), batch))

    def get_copy(self, part, rel):
        return self.db.execute('SELECT dest,hash,state FROM copies WHERE job=? AND round=? AND part=? AND path=?',
                               (self.job, self.round, part, rel)).fetchone()

    def copies(self):
        return self.db.execute('SELECT part,path,dest,hash,state FROM copies WHERE job=? AND round=?',
                               (self.job, self.round)).fetchall()

    def copy_state(self, part, rel, dest, sha, state):
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO copies VALUES (?,?,?,?,?,?,?)',
                            (self.job, self.round, part, rel, str(dest), sha, state))

    def next_round(self):
        self.round += 1
        self.phase = 'scan'
        with self.db:
            self.db.execute('UPDATE jobs SET round=?,phase=? WHERE id=?', (self.round, self.phase, self.job))

    def quarantining(self):
        self.phase = 'quarantine'
        with self.db:
            self.db.execute('UPDATE jobs SET phase=? WHERE id=?', (self.phase, self.job))

    def finish(self, status):
        with self.db:
            self.db.execute('UPDATE jobs SET status=? WHERE id=?', (status, self.job))

    def close(self):
        self.db.close()

    def export(self, run):
        rows = self.db.execute('SELECT id,round,part,started,finished,status,log FROM batches WHERE job=? ORDER BY id',
                               (self.job,)).fetchall()
        names = ['lote', 'rodada', 'particao', 'inicio_unix', 'fim_unix', 'estado', 'log']
        atomic_json(run / 'historico-lotes.json', [dict(zip(names, row)) for row in rows])
        rows = self.db.execute('SELECT round,part,path,dest,hash,state FROM copies WHERE job=?', (self.job,)).fetchall()
        names = ['rodada', 'particao', 'original', 'destino', 'sha256', 'estado']
        atomic_json(run / 'historico-quarentena.json', [dict(zip(names, row)) for row in rows])
