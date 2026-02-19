const CODEBERG_API = 'https://codeberg.org/api/v1';
const INTEL_REPO_OWNER = 'careybalboa';
const INTEL_REPO_NAME = 'dns-tool-intel';
const INTEL_BRANCH = 'main';

function getToken() {
  const token = process.env.CODEBERG_FORGEJO_API;
  if (!token) {
    throw new Error('CODEBERG_FORGEJO_API secret not set');
  }
  return token;
}

async function apiFetch(path, options = {}) {
  const token = getToken();
  const url = `${CODEBERG_API}${path}`;
  const headers = {
    'Authorization': `token ${token}`,
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    ...options.headers,
  };
  const resp = await fetch(url, { ...options, headers });
  if (!resp.ok) {
    const body = await resp.text().catch(() => '');
    throw Object.assign(new Error(`Forgejo API ${resp.status}: ${resp.statusText} — ${body}`), { status: resp.status });
  }
  return resp.json();
}

async function listIntelFiles() {
  const result = [];

  async function listDir(path) {
    try {
      const data = await apiFetch(`/repos/${INTEL_REPO_OWNER}/${INTEL_REPO_NAME}/contents/${path}?ref=${INTEL_BRANCH}`);
      if (Array.isArray(data)) {
        for (const item of data) {
          if (item.type === 'dir') {
            await listDir(item.path);
          } else {
            result.push({ path: item.path, sha: item.sha, size: item.size });
          }
        }
      }
    } catch (e) {
      if (e.status !== 404) throw e;
    }
  }

  await listDir('');
  return result;
}

async function getFile(path) {
  const data = await apiFetch(`/repos/${INTEL_REPO_OWNER}/${INTEL_REPO_NAME}/contents/${encodeURIComponent(path)}?ref=${INTEL_BRANCH}`);
  if (data.encoding === 'base64') {
    return { content: Buffer.from(data.content, 'base64').toString('utf8'), sha: data.sha };
  }
  return { content: data.content, sha: data.sha };
}

async function putFile(path, content, message, existingSha) {
  const body = {
    content: Buffer.from(content).toString('base64'),
    message: message,
    branch: INTEL_BRANCH,
  };
  if (existingSha) {
    body.sha = existingSha;
    const data = await apiFetch(`/repos/${INTEL_REPO_OWNER}/${INTEL_REPO_NAME}/contents/${encodeURIComponent(path)}`, {
      method: 'PUT',
      body: JSON.stringify(body),
    });
    return { sha: data.content.sha, commit: data.commit?.sha || 'unknown' };
  } else {
    const data = await apiFetch(`/repos/${INTEL_REPO_OWNER}/${INTEL_REPO_NAME}/contents/${encodeURIComponent(path)}`, {
      method: 'POST',
      body: JSON.stringify(body),
    });
    return { sha: data.content.sha, commit: data.commit?.sha || 'unknown' };
  }
}

async function deleteFile(path, message, sha) {
  await apiFetch(`/repos/${INTEL_REPO_OWNER}/${INTEL_REPO_NAME}/contents/${encodeURIComponent(path)}`, {
    method: 'DELETE',
    body: JSON.stringify({
      message: message,
      sha: sha,
      branch: INTEL_BRANCH,
    }),
  });
}

async function getCommits(perPage = 10) {
  const data = await apiFetch(`/repos/${INTEL_REPO_OWNER}/${INTEL_REPO_NAME}/commits?sha=${INTEL_BRANCH}&limit=${perPage}`);
  return data.map(c => ({
    sha: c.sha.substring(0, 7),
    message: c.commit.message,
    date: c.commit.committer.date,
    author: c.commit.author.name,
  }));
}

const cmd = process.argv[2];

switch (cmd) {
  case 'list': {
    const files = await listIntelFiles();
    console.log(`\n=== dns-tool-intel file listing (${files.length} files) ===`);
    for (const f of files) {
      console.log(`  ${f.path} (${f.size} bytes)`);
    }
    break;
  }
  case 'read': {
    const filePath = process.argv[3];
    if (!filePath) { console.error('Usage: node codeberg-intel-sync.mjs read <path>'); process.exit(1); }
    const { content } = await getFile(filePath);
    console.log(content);
    break;
  }
  case 'push': {
    const localPath = process.argv[3];
    const remotePath = process.argv[4];
    const message = process.argv[5] || `Update ${remotePath}`;
    if (!localPath || !remotePath) { console.error('Usage: node codeberg-intel-sync.mjs push <local-path> <remote-path> [message]'); process.exit(1); }
    const fs = await import('fs');
    const content = fs.readFileSync(localPath, 'utf8');
    let existingSha = null;
    try {
      const existing = await getFile(remotePath);
      existingSha = existing.sha;
    } catch (e) {
      if (e.status !== 404) throw e;
    }
    const result = await putFile(remotePath, content, message, existingSha);
    console.log(`Pushed ${localPath} → ${INTEL_REPO_OWNER}/${INTEL_REPO_NAME}/${remotePath}`);
    console.log(`  Commit: ${result.commit}`);
    break;
  }
  case 'delete': {
    const delPath = process.argv[3];
    const delMsg = process.argv[4] || `Delete ${delPath}`;
    if (!delPath) { console.error('Usage: node codeberg-intel-sync.mjs delete <remote-path> [message]'); process.exit(1); }
    const { sha } = await getFile(delPath);
    await deleteFile(delPath, delMsg, sha);
    console.log(`Deleted ${INTEL_REPO_OWNER}/${INTEL_REPO_NAME}/${delPath}`);
    break;
  }
  case 'commits': {
    const count = parseInt(process.argv[3] || '10');
    const commits = await getCommits(count);
    console.log(`\n=== dns-tool-intel recent commits ===`);
    for (const c of commits) {
      console.log(`  ${c.sha} ${c.date} ${c.message}`);
    }
    break;
  }
  default:
    console.log('Usage: node scripts/codeberg-intel-sync.mjs <command>');
    console.log('Commands:');
    console.log('  list                              List all files in Intel repo');
    console.log('  read <path>                       Read a file from Intel repo');
    console.log('  push <local> <remote> [message]   Push local file to Intel repo');
    console.log('  delete <path> [message]           Delete file from Intel repo');
    console.log('  commits [count]                   Show recent commits');
}
